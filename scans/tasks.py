"""worker가 실행하는 작업. web은 run_scan.delay(점검 번호)로 요청만 넣고 바로 응답한다."""
import logging

from celery import shared_task
from django.conf import settings
from django.db import transaction
from django.utils import timezone

from findings.models import Finding

from .models import ModuleRun, Scan
from .modules import MODULES_BY_KEY
from .modules.base import ScanError

logger = logging.getLogger(__name__)


@shared_task
def run_scan(scan_id):
    scan = Scan.objects.get(pk=scan_id)
    scan.status = Scan.Status.RUNNING
    scan.save(update_fields=['status'])
    try:
        for run in scan.runs.select_related('target'):
            run_module(run)
    finally:
        # 도중에 예상하지 못한 오류가 나도 점검이 '실행 중'으로 남아 다음 점검을 막지 않게 한다.
        scan.status = Scan.Status.DONE
        scan.finished_at = timezone.now()
        scan.save(update_fields=['status', 'finished_at'])


def run_module(run):
    """모듈 실행 하나를 돌리고 결과를 저장한다. 하나가 실패해도 다른 실행은 계속한다."""
    run.status = ModuleRun.Status.RUNNING
    run.started_at = timezone.now()
    run.save(update_fields=['status', 'started_at'])

    module = MODULES_BY_KEY[run.module]
    try:
        result = module.run(run.target)
        raw_output_path = save_raw_output(run, result.raw_output)
        # 발견 저장이 중간에 실패하면 일부만 남지 않게 한 번에 저장한다.
        with transaction.atomic():
            findings = save_findings(run, result.findings)
    except ScanError as e:
        run.status = ModuleRun.Status.FAILED
        run.error_message = str(e)
    except Exception:
        # 코드 버그 같은 예상하지 못한 오류. 자세한 내용은 worker 로그에 남기고 화면에는 짧게 보여 준다.
        logger.exception('모듈 실행 %s 중 오류', run.pk)
        run.status = ModuleRun.Status.FAILED
        run.error_message = '예상하지 못한 오류로 점검하지 못했습니다. worker 로그를 확인하세요.'
    else:
        run.raw_output_path = raw_output_path
        run.tool_version = result.tool_version
        run.finding_count = len(findings)
        run.status = ModuleRun.Status.FOUND if findings else ModuleRun.Status.PASSED

    run.finished_at = timezone.now()
    run.save()


def save_findings(run, items):
    """발견을 저장하고 이 모듈 실행에 잇는다. 이미 있는 발견(같은 대상·모듈·fingerprint)은 새로 만들지 않고 다시 잇기만 한다."""
    # 한 번의 결과 안에 같은 발견이 두 번 나와도 하나로 센다. 먼저 나온 것을 쓴다.
    unique = {}
    for item in items:
        unique.setdefault(item.fingerprint, item)

    existing = {
        finding.fingerprint: finding
        for finding in Finding.objects.filter(target=run.target, module=run.module, fingerprint__in=list(unique))
    }
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
