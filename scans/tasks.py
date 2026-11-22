"""worker가 실행하는 작업. web은 run_scan.delay(점검 번호)로 요청만 넣고 바로 응답한다."""
import logging

from celery import shared_task
from django.conf import settings
from django.db import close_old_connections, connection, transaction
from django.utils import timezone

from findings.models import Finding

from .models import ModuleRun, Scan
from .modules import MODULES_BY_KEY
from .modules.base import Cancelled, ScanError

logger = logging.getLogger(__name__)

UNEXPECTED_ERROR = '예상하지 못한 오류로 점검하지 못했습니다. worker 로그를 확인하세요.'
RUNNER_ERROR = '점검 실행기 오류로 이 칸을 끝내지 못했습니다. worker 로그를 확인하세요.'

# 점검은 web의 취소 요청(ScanCancelApi)과 동시에 바뀔 수 있다. 그래서 상태는 읽고 나서 저장하지 않고,
# "아직 그 상태일 때만 바꾼다"는 조건을 붙인 UPDATE 한 번으로 바꾼다. 바뀐 줄이 0이면 그 사이 취소된 것이다.


@shared_task
def run_scan(scan_id):
    # 대기 중일 때만 시작한다. 시작하기 전에 취소된 점검이면 아무것도 하지 않는다.
    if not Scan.objects.filter(pk=scan_id, status=Scan.Status.QUEUED).update(status=Scan.Status.RUNNING):
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
        # DB가 계속 내려가 있으면 이것도 실패한다. 그때는 DB가 돌아온 뒤 화면에서 점검을 취소해 푼다.
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


def fail_unfinished(runs):
    """끝나지 않은 칸(대기, 실행 중)을 실행기 오류로 실패 처리한다. 이미 끝났거나 취소된 칸은 그대로 둔다."""
    runs.filter(status__in=ModuleRun.ACTIVE).update(
        status=ModuleRun.Status.FAILED, error_message=RUNNER_ERROR, finished_at=timezone.now(),
    )


def run_module(run):
    """모듈 실행 하나를 돌리고 결과를 저장한다. 하나가 실패해도 다른 실행은 계속한다."""
    # 대기 중인 칸만 시작한다. 그 사이 취소된 칸은 건너뛴다.
    started_at = timezone.now()
    if not ModuleRun.objects.filter(pk=run.pk, status=ModuleRun.Status.QUEUED).update(
        status=ModuleRun.Status.RUNNING, started_at=started_at,
    ):
        return
    run.status, run.started_at = ModuleRun.Status.RUNNING, started_at

    def cancelled():
        # 취소하면 web이 칸을 '취소'로 바꾸므로, 더 이상 '실행 중'이 아니면 취소된 것이다.
        return not ModuleRun.objects.filter(pk=run.pk, status=ModuleRun.Status.RUNNING).exists()

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

    existing = {
        finding.fingerprint: finding
        for finding in Finding.objects.filter(target=run.target, module=run.module, fingerprint__in=list(unique))
    }
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


def save_raw_output(run, raw_output):
    """원본 결과를 파일로 보관하고, 결과 폴더 기준 경로를 돌려준다. 예: scan-3/run-7-secrets.json"""
    relative = f'scan-{run.scan_id}/run-{run.pk}-{run.module}.json'
    path = settings.SELFSPAR_SCAN_RESULTS_DIR / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw_output)
    return relative
