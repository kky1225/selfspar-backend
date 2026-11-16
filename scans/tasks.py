"""worker가 실행하는 작업. web은 run_scan.delay(점검 번호)로 요청만 넣고 바로 응답한다."""
import logging

from celery import shared_task
from django.conf import settings
from django.utils import timezone

from .models import Scan, ScanTask
from .modules import MODULES_BY_KEY
from .modules.base import ScanError

logger = logging.getLogger(__name__)


@shared_task
def run_scan(scan_id):
    scan = Scan.objects.get(pk=scan_id)
    scan.status = Scan.Status.RUNNING
    scan.save(update_fields=['status'])
    try:
        for task in scan.tasks.select_related('target'):
            run_task(task)
    finally:
        # 도중에 예상하지 못한 오류가 나도 점검이 '실행 중'으로 남아 다음 점검을 막지 않게 한다.
        scan.status = Scan.Status.DONE
        scan.finished_at = timezone.now()
        scan.save(update_fields=['status', 'finished_at'])


def run_task(task):
    """칸 하나를 실행하고 결과를 저장한다. 한 칸이 실패해도 다른 칸은 계속 실행한다."""
    task.status = ScanTask.Status.RUNNING
    task.started_at = timezone.now()
    task.save(update_fields=['status', 'started_at'])

    module = MODULES_BY_KEY[task.module]
    try:
        result = module.run(task.target)
    except ScanError as e:
        task.status = ScanTask.Status.FAILED
        task.error_message = str(e)
    except Exception:
        # 코드 버그 같은 예상하지 못한 오류. 자세한 내용은 worker 로그에 남기고 화면에는 짧게 보여 준다.
        logger.exception('점검 칸 %s 실행 중 오류', task.pk)
        task.status = ScanTask.Status.FAILED
        task.error_message = '예상하지 못한 오류로 점검하지 못했습니다. worker 로그를 확인하세요.'
    else:
        task.raw_output_path = save_raw_output(task, result.raw_output)
        task.tool_version = result.tool_version
        task.finding_count = result.finding_count
        task.status = ScanTask.Status.FOUND if result.finding_count else ScanTask.Status.PASSED

    task.finished_at = timezone.now()
    task.save()


def save_raw_output(task, raw_output):
    """원본 결과를 파일로 보관하고, 결과 폴더 기준 경로를 돌려준다. 예: scan-3/task-7-secrets.json"""
    relative = f'scan-{task.scan_id}/task-{task.pk}-{task.module}.json'
    path = settings.SELFSPAR_SCAN_RESULTS_DIR / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw_output)
    return relative
