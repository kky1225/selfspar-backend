"""worker가 실행하는 작업. web은 run_scan.delay(점검 번호)로 요청만 넣고 바로 응답한다."""
import logging
import re
from datetime import timedelta

from celery import shared_task
from django.conf import settings
from django.db import close_old_connections, connection, transaction
from django.utils import timezone

from findings.models import Finding, FindingEvent

from .models import ModuleRun, Scan
from .modules import MODULES_BY_KEY
from .modules.base import Cancelled, ScanError

logger = logging.getLogger(__name__)

UNEXPECTED_ERROR = '예상하지 못한 오류로 점검하지 못했습니다. worker 로그를 확인하세요.'
RUNNER_ERROR = '점검 실행기 오류로 이 칸을 끝내지 못했습니다. worker 로그를 확인하세요.'
WORKER_LOST = 'worker가 응답하지 않아 이 칸을 끝내지 못했습니다. worker가 다시 시작되었거나 멈췄습니다.'

# 실행 중인 점검이 이만큼 아무 신호도 남기지 않으면 worker가 멈춘 것으로 본다.
# 신호(Scan.heartbeat_at)는 점검과 칸을 시작할 때, 그리고 도구가 도는 동안 2초마다 남긴다.
# Airflow도 작업의 신호가 5분 동안 끊기면 멈춘 작업(좀비)으로 보고 실패 처리한다.
STALE_AFTER = timedelta(minutes=5)
# 대기인 점검이 이만큼 지나도 시작되지 않으면 실행 요청이 사라진 것으로 보고 취소한다(예: redis를 다시 만듦).
# 정상 대기는 길어야 몇십 분이다. 프로젝트마다 대기 점검은 하나이고 worker가 2개씩 돌리므로, 가장 늦은 점검의 대기는
# (프로젝트 수 / 2 - 1) × 점검 하나의 시간이다. 예: 프로젝트 20개를 한꺼번에 넣어도 점검 하나가 13분 안에 끝나면 넘지 않는다.
# 하루보다 짧아야 매일 도는 점검이 갇혀도 다음 날 점검을 막지 않는다.
QUEUED_EXPIRES = timedelta(hours=2)
# 어느 칸도 가리키지 않는 원본 결과 파일이라도 이만큼 지나야 지운다. 칸은 파일을 먼저 쓰고 결과를 저장하면서 경로를 적어서,
# 그 사이에는 방금 쓴 파일도 가리키는 칸이 없어 보이기 때문이다.
ORPHAN_FILE_MIN_AGE = timedelta(days=1)
# save_raw_output이 만드는 폴더와 파일 이름. task-는 칸(ModuleRun)의 예전 이름(ScanTask) 때 만든 파일이다.
RAW_OUTPUT_FOLDER = re.compile(r'scan-\d+')
RAW_OUTPUT_FILE = re.compile(r'(run|task)-\d+-[\w-]+\.json')

# 점검은 web의 취소 요청(ScanCancelApi)과 동시에 바뀔 수 있다. 그래서 상태는 읽고 나서 저장하지 않고,
# "아직 그 상태일 때만 바꾼다"는 조건을 붙인 UPDATE 한 번으로 바꾼다. 바뀐 줄이 0이면 그 사이 취소된 것이다.


@shared_task
def run_scan(scan_id):
    # 대기 중일 때만 시작한다. 시작하기 전에 취소된 점검이면 아무것도 하지 않는다.
    if not Scan.objects.filter(pk=scan_id, status=Scan.Status.QUEUED).update(
        status=Scan.Status.RUNNING, heartbeat_at=timezone.now(),
    ):
        logger.info('점검 #%s는 대기 중이 아니라서 실행하지 않음', scan_id)
        return
    try:
        for run in ModuleRun.objects.filter(scan_id=scan_id).select_related('target'):
            try:
                run_module(run)
            except Exception:
                # run_module은 칸 안의 오류를 '실패'로 기록하지만, 기록하는 중에도 오류가 날 수 있다(예: DB 연결이 잠깐 끊김).
                # 그래도 이 칸만 실패로 두고 다음 칸으로 넘어간다.
                logger.exception('모듈 실행 %s를 끝내지 못함', run.pk)
                reset_broken_connection()
                fail_unfinished(ModuleRun.objects.filter(pk=run.pk))
    finally:
        # 점검 전체가 도중에 멈춰도(예: 칸 목록을 읽거나 위의 실패 기록에서 다시 오류) 점검은 완료로,
        # 끝나지 않은 칸은 실패로 바꾼다. 그래야 '실행 중'으로 남아 다음 점검을 막지 않고, 화면에도 실패로 보인다.
        # 취소된 점검은 취소할 때 이미 끝냈으므로 그대로 둔다.
        # DB가 계속 내려가 있으면 이것도 실패한다. 그때는 DB가 돌아온 뒤 정리 작업(cleanup_stale_scans)이 5분쯤 뒤에 정리한다.
        reset_broken_connection()
        with transaction.atomic():
            if Scan.objects.filter(pk=scan_id, status=Scan.Status.RUNNING).update(
                status=Scan.Status.DONE, finished_at=timezone.now(),
            ):
                fail_unfinished(ModuleRun.objects.filter(scan_id=scan_id))


def reset_broken_connection():
    """오류로 끊긴 DB 연결을 닫는다. 다음 쿼리에서 새로 연결한다.
    Django는 작업 도중에 연결이 끊겨도 저절로 다시 연결하지 않고, 끊긴 연결을 계속 써서 다음 쿼리도 실패한다.
    트랜잭션 안에서는 연결을 닫을 수 없어서 건너뛴다(테스트는 테스트 전체가 트랜잭션 안에서 돈다)."""
    if not connection.in_atomic_block:
        close_old_connections()


def fail_unfinished(runs, error_message=RUNNER_ERROR):
    """끝나지 않은 칸(대기, 실행 중)을 실패 처리한다. 이미 끝났거나 취소된 칸은 그대로 둔다."""
    runs.filter(status__in=ModuleRun.ACTIVE).update(
        status=ModuleRun.Status.FAILED, error_message=error_message, finished_at=timezone.now(),
    )


@shared_task
def cleanup_stale_scans():
    """worker가 멈춰 끝나지 않은 점검을 정리한다. Celery beat가 1분마다 부른다(settings.CELERY_BEAT_SCHEDULE).
    worker가 도중에 강제로 꺼지면 run_scan의 finally도 실행되지 않아서, 점검이 '실행 중'으로 남아 다음 점검을 막는다."""
    now = timezone.now()
    cutoff = now - STALE_AFTER

    for scan_id in Scan.objects.filter(
        status=Scan.Status.RUNNING, heartbeat_at__lt=cutoff,
    ).values_list('pk', flat=True):
        # run_scan의 마무리와 같다: 점검은 완료로, 끝나지 않은 칸은 실패로.
        # 찾은 뒤에 취소되었거나 신호가 새로 들어왔으면 조건에 맞지 않아 바꾸지 않는다.
        # 정리한 뒤에 worker가 사실은 살아 있었다면, 다음 취소 확인에서 점검이 '실행 중'이 아닌 것을 보고 도구를 멈추고,
        # 결과도 칸이 '실행 중'일 때만 저장하므로 이 실패를 덮어쓰지 않는다.
        with transaction.atomic():
            if Scan.objects.filter(pk=scan_id, status=Scan.Status.RUNNING, heartbeat_at__lt=cutoff).update(
                status=Scan.Status.DONE, finished_at=now,
            ):
                fail_unfinished(ModuleRun.objects.filter(scan_id=scan_id), WORKER_LOST)
                logger.warning('점검 #%s는 worker 신호가 %s 넘게 없어서 정리함', scan_id, STALE_AFTER)

    for scan_id in Scan.objects.filter(
        status=Scan.Status.QUEUED, created_at__lt=now - QUEUED_EXPIRES,
    ).values_list('pk', flat=True):
        # 취소 API와 같은 방법으로 취소한다. 줄을 잠그므로 그 사이 worker가 시작하려 하면 취소가 끝난 뒤 '대기'가 아닌 것을 보고 건너뛴다.
        with transaction.atomic():
            scan = Scan.objects.select_for_update().filter(pk=scan_id, status=Scan.Status.QUEUED).first()
            if scan:
                scan.cancel()
                logger.warning('점검 #%s는 %s 넘게 시작되지 않아서 취소함', scan_id, QUEUED_EXPIRES)


@shared_task
def cleanup_orphans():
    """지운 점검이 남긴 것을 정리한다. Celery beat가 하루에 한 번 부른다(settings.CELERY_BEAT_SCHEDULE).
    - 원본 결과 파일: 어느 칸도 가리키지 않는 파일. 점검을 지우거나, 파일을 쓴 뒤 취소된 칸에서 생긴다.
    - 발견: 이어진 칸이 하나도 없는 발견. 그 발견을 본 점검을 모두 지우면 생긴다.
    DB 줄을 지울 때 파일을 함께 지우지 않는 것은 Django와 같은 방식이다. 지우는 트랜잭션이 롤백되면 줄은 살아나는데 파일만 사라지기 때문이다.
    발견을 먼저 정리한다. 파일 쪽에 문제가 있어도 발견 정리는 끝내기 위해서다."""
    remove_orphan_findings()
    remove_orphan_files()


def remove_orphan_findings():
    # 지우기 전에 잠그고 다시 확인한다. 그 사이 새 점검이 같은 발견을 찾아 다시 이었으면 지우지 않는다(save_findings도 같은 줄을 잠근다).
    # of=('self',): 발견 줄만 잠근다. 칸과 잇는 표는 없는 쪽(LEFT JOIN의 빈 쪽)이라 잠글 수 없다.
    with transaction.atomic():
        ids = list(Finding.objects.select_for_update(of=('self',)).filter(runs=None).values_list('pk', flat=True))
        if ids:
            count, _ = Finding.objects.filter(pk__in=ids, runs=None).delete()
            logger.info('이어진 칸이 없는 발견 %s개를 지움', count)


def remove_orphan_files():
    """결과 폴더에서 어느 칸도 가리키지 않는 원본 결과 파일과 빈 점검 폴더를 지운다.
    save_raw_output이 만드는 모양(scan-N/run-M-모듈.json)만 본다. 결과 폴더를 실수로 넓은 곳으로 잡아도 다른 파일은 지우지 않는다.
    심볼릭 링크는 따라가지 않는다. 폴더 하나를 정리하지 못해도 로그만 남기고 다음 폴더로 넘어간다."""
    root = settings.SELFSPAR_SCAN_RESULTS_DIR
    if not root.is_dir():
        # worker에 결과 볼륨이 붙지 않은 설정 실수일 수 있어서 알려 둔다.
        logger.warning('원본 결과 폴더 %s가 없어서 파일 정리를 건너뜀', root)
        return

    cutoff = (timezone.now() - ORPHAN_FILE_MIN_AGE).timestamp()
    kept = set(ModuleRun.objects.exclude(raw_output_path='').values_list('raw_output_path', flat=True))
    removed = 0
    for folder in root.iterdir():
        if folder.is_symlink() or not folder.is_dir() or not RAW_OUTPUT_FOLDER.fullmatch(folder.name):
            continue
        try:
            for path in folder.iterdir():
                if (
                    not path.is_symlink() and path.is_file() and RAW_OUTPUT_FILE.fullmatch(path.name)
                    and f'{folder.name}/{path.name}' not in kept and path.stat().st_mtime < cutoff
                ):
                    path.unlink()
                    removed += 1
            # 빈 폴더도 지운다. 칸이 폴더를 막 만들고 파일을 쓰기 전일 수 있어서 오래된 폴더만 지운다.
            # 안의 파일을 지우면 폴더의 수정 시각이 지금으로 바뀌므로, 그런 폴더는 다음 정리 때 지워진다.
            if not any(folder.iterdir()) and folder.stat().st_mtime < cutoff:
                folder.rmdir()
        except OSError:
            logger.exception('원본 결과 폴더 %s를 정리하지 못함', folder)
    if removed:
        logger.info('어느 칸도 가리키지 않는 원본 결과 파일 %s개를 지움', removed)


def run_module(run):
    """모듈 실행 하나를 돌리고 결과를 저장한다. 하나가 실패해도 다른 실행은 계속한다."""
    # 대기 중인 칸만 시작한다. 그 사이 취소된 칸은 건너뛴다.
    started_at = timezone.now()
    if not ModuleRun.objects.filter(pk=run.pk, status=ModuleRun.Status.QUEUED).update(
        status=ModuleRun.Status.RUNNING, started_at=started_at,
    ):
        return
    run.status, run.started_at = ModuleRun.Status.RUNNING, started_at
    # 칸을 넘어갈 때마다 신호를 남긴다. 금방 끝나는 칸만 이어져서 아래 취소 확인이 한 번도 불리지 않아도 신호가 끊기지 않는다.
    Scan.objects.filter(pk=run.scan_id, status=Scan.Status.RUNNING).update(heartbeat_at=started_at)

    def cancelled():
        # 확인하면서 살아 있다는 신호(Scan.heartbeat_at)도 남긴다. 도구가 도는 동안 2초마다 불린다.
        # 점검이 더 이상 '실행 중'이 아니면 바뀐 줄이 0이고, 도구를 멈춰야 한다.
        # 그런 경우는 사용자가 점검을 취소했거나(칸도 함께 취소됨), 정리 작업이 멈춘 점검으로 처리했을 때(칸은 실패)다.
        return not Scan.objects.filter(pk=run.scan_id, status=Scan.Status.RUNNING).update(
            heartbeat_at=timezone.now(),
        )

    module = MODULES_BY_KEY[run.module]
    try:
        result = module.run(run.target, cancelled)
        raw_output_path = save_raw_output(run, result.raw_output)
    except Cancelled:
        return
    except ScanError as e:
        finish(run, status=ModuleRun.Status.FAILED, error_message=str(e))
        return
    except Exception:
        # 코드 버그 같은 예상하지 못한 오류. 자세한 내용은 worker 로그에 남기고 화면에는 짧게 보여 준다.
        logger.exception('모듈 실행 %s 중 오류', run.pk)
        finish(run, status=ModuleRun.Status.FAILED, error_message=UNEXPECTED_ERROR)
        return

    try:
        # 발견 저장이 중간에 실패하면 일부만 남지 않게 한 번에 저장한다.
        with transaction.atomic():
            # 이 칸을 잠가 둔다. 저장하는 동안 들어온 취소 요청은 잠금이 풀릴 때까지 기다렸다가, 이미 끝난 칸이라 건너뛴다.
            # 반대로 취소가 먼저 끝났으면 여기서 '실행 중'인 칸을 찾지 못해 저장하지 않는다.
            if not ModuleRun.objects.select_for_update().filter(pk=run.pk, status=ModuleRun.Status.RUNNING).exists():
                return
            findings = save_findings(run, result.findings)
            update_statuses(run, findings)
            finish(
                run,
                status=ModuleRun.Status.FOUND if findings else ModuleRun.Status.PASSED,
                raw_output_path=raw_output_path,
                tool_version=result.tool_version,
                finding_count=len(findings),
            )
    except Exception:
        logger.exception('모듈 실행 %s의 결과 저장 중 오류', run.pk)
        finish(run, status=ModuleRun.Status.FAILED, error_message=UNEXPECTED_ERROR)


def finish(run, **fields):
    """칸을 끝낸 상태로 바꾼다. 그 사이 취소된 칸이면 취소를 덮어쓰지 않는다."""
    ModuleRun.objects.filter(pk=run.pk, status=ModuleRun.Status.RUNNING).update(finished_at=timezone.now(), **fields)


# 다시 나온 발견에서 이번 결과로 바꿔 쓰는 칸. 같은 취약점이라도 DB가 갱신되면 심각도·고친 버전·제목이 바뀐다.
REFRESHED_FIELDS = ['rule_id', 'title', 'severity', 'location', 'evidence', 'extra']


def save_findings(run, items):
    """발견을 저장하고 이 모듈 실행에 잇는다. 이미 있는 발견(같은 대상·모듈·fingerprint)은 새로 만들지 않고,
    내용을 이번 결과로 바꾼 뒤 다시 잇는다."""
    # 한 번의 결과 안에 같은 발견이 두 번 나와도 하나로 센다. 먼저 나온 것을 쓴다.
    unique = {}
    for item in items:
        unique.setdefault(item.fingerprint, item)

    # 이 대상·모듈의 발견을 모두 잠가 둔다.
    # - 정리 작업(cleanup_orphans)이 이어진 칸이 없는 발견을 지우는 중이면 끝날 때까지 기다린다.
    #   그동안 지워진 발견은 여기서 읽히지 않아 아래에서 새로 만든다.
    # - 이어서 update_statuses가 이번에 안 나온 발견의 상태도 바꾸므로, 이번에 나온 것만이 아니라 전부 잠근다.
    # 정리 작업과 같은 id 순서로 잠가서, 서로 상대가 쥔 줄을 기다리며 멈추는 일(교착)이 생기지 않는다.
    locked = {
        finding.fingerprint: finding
        for finding in Finding.objects.select_for_update().filter(target=run.target, module=run.module).order_by('pk')
    }
    existing = {fingerprint: locked[fingerprint] for fingerprint in unique if fingerprint in locked}
    for fingerprint, finding in existing.items():
        for field in REFRESHED_FIELDS:
            setattr(finding, field, getattr(unique[fingerprint], field))
    # 한 건씩 save()하지 않고 UPDATE 한 번으로 바꾼다.
    Finding.objects.bulk_update(existing.values(), REFRESHED_FIELDS)

    new = [
        Finding(
            target=run.target, module=run.module, fingerprint=item.fingerprint, rule_id=item.rule_id,
            title=item.title, severity=item.severity, location=item.location, evidence=item.evidence, extra=item.extra,
        )
        for fingerprint, item in unique.items() if fingerprint not in existing
    ]
    Finding.objects.bulk_create(new)

    findings = [*existing.values(), *new]
    run.findings.add(*findings)
    return findings


def update_statuses(run, findings):
    """이번 결과로 같은 대상·모듈 발견의 상태를 바꾼다. DefectDojo가 같은 점검 결과를 다시 가져올 때와 같은 규칙이다.
    - 미해결인데 이번에 안 나온 발견: 해결됨
    - 해결됨인데 이번에 다시 나온 발견: 미해결(재발)
    - 위험 수용인데 다시 나오면서 심각도가 높음 이상으로 오른 발견: 미해결(높음 이상은 위험 수용할 수 없다)
    - 그 밖의 오탐·위험 수용은 사람이 정한 상태라 나오든 안 나오든 그대로 둔다.
    칸이 이상 없음이나 발견으로 끝날 때만 부른다. 실패·취소된 칸은 '안 나왔다'는 증거가 아니라서 부르지 않는다.
    save_findings와 같은 트랜잭션 안에서 부른다. 심각도는 save_findings가 이번 결과로 갱신한 뒤의 값을 본다."""
    found = {finding.pk for finding in findings}
    # (발견, 바뀔 상태, 사유)
    changes = []
    # save_findings가 이미 잠근 줄이지만, 이 함수만 따로 불러도 안전하도록 여기서도 같은 순서로 잠근다.
    for finding in Finding.objects.select_for_update().filter(
        target=run.target, module=run.module,
        status__in=[Finding.Status.OPEN, Finding.Status.FIXED, Finding.Status.RISK_ACCEPTED],
    ).order_by('pk'):
        if finding.status == Finding.Status.OPEN and finding.pk not in found:
            changes.append((finding, Finding.Status.FIXED, ''))
        elif finding.status == Finding.Status.FIXED and finding.pk in found:
            changes.append((finding, Finding.Status.OPEN, ''))
        elif finding.status == Finding.Status.RISK_ACCEPTED and finding.pk in found and not finding.can_accept_risk():
            reason = f'심각도가 {finding.get_severity_display()}(으)로 올라 위험 수용을 풀었습니다.'
            changes.append((finding, Finding.Status.OPEN, reason))

    for to_status in (Finding.Status.FIXED, Finding.Status.OPEN):
        ids = [finding.pk for finding, status, _ in changes if status == to_status]
        if ids:
            # 미해결·해결됨에는 만료일이 없다. 위험 수용을 푼 발견의 만료일도 함께 비운다.
            Finding.objects.filter(pk__in=ids).update(status=to_status, accepted_until=None)
    FindingEvent.objects.bulk_create([
        FindingEvent(finding=finding, from_status=finding.status, to_status=to_status, reason=reason, run=run)
        for finding, to_status, reason in changes
    ])


def save_raw_output(run, raw_output):
    """원본 결과를 파일로 보관하고, 결과 폴더 기준 경로를 돌려준다. 예: scan-3/run-7-secrets.json"""
    relative = f'scan-{run.scan_id}/run-{run.pk}-{run.module}.json'
    path = settings.SELFSPAR_SCAN_RESULTS_DIR / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw_output)
    return relative
