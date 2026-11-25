"""발견에 관한 정해진 작업. Celery beat가 때가 되면 요청을 넣고 worker가 실행한다."""
import logging

from celery import shared_task
from django.db import transaction
from django.utils import timezone

from .models import Finding, FindingEvent

logger = logging.getLogger(__name__)

EXPIRED_REASON = '위험 수용 기한이 지났습니다.'


@shared_task
def expire_risk_acceptances():
    """기한이 지난 위험 수용을 미해결로 되돌린다. Celery beat가 1시간마다 부른다(settings.CELERY_BEAT_SCHEDULE).
    만료일 당일까지는 인정하고, 다음 날(한국 시각) 첫 확인에서 되돌린다. DefectDojo도 기본값으로 만료된 위험 수용을 다시 활성으로 돌린다."""
    today = timezone.localdate()
    with transaction.atomic():
        # 점검 저장·정리 작업과 같은 id 순서로 잠가서 서로 기다리며 멈추는 일(교착)이 없게 한다.
        # 잠근 뒤에 조건을 다시 보므로, 그 사이 사람이 기한을 늘렸으면 고르지 않는다.
        expired = list(
            Finding.objects.select_for_update()
            .filter(status=Finding.Status.RISK_ACCEPTED, accepted_until__lt=today)
            .order_by('pk')
        )
        if not expired:
            return
        Finding.objects.filter(pk__in=[finding.pk for finding in expired]).update(
            status=Finding.Status.OPEN, accepted_until=None,
        )
        FindingEvent.objects.bulk_create([
            FindingEvent(
                finding=finding, from_status=Finding.Status.RISK_ACCEPTED, to_status=Finding.Status.OPEN, reason=EXPIRED_REASON,
            )
            for finding in expired
        ])
    logger.info('기한이 지난 위험 수용 %s개를 미해결로 되돌림', len(expired))
