import math
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.db import transaction
from django.utils import timezone

from .models import LoginFailure

# (연속 실패 횟수, 잠금 시간). 큰 횟수부터 확인한다. investfeed-backend와 같은 기준이다.
LOCK_STAGES = [
    (20, timedelta(minutes=60)),
    (10, timedelta(minutes=30)),
    (5, timedelta(minutes=10)),
]


def lock_duration(failed_count):
    for min_count, duration in LOCK_STAGES:
        if failed_count >= min_count:
            return duration
    return None


def remaining_lock_seconds(username):
    """잠겨 있으면 남은 시간(초), 잠겨 있지 않으면 0을 돌려준다."""
    failure = LoginFailure.objects.filter(user__username=username).first()
    if failure is None or failure.locked_until is None:
        return 0
    remaining = (failure.locked_until - timezone.now()).total_seconds()
    return max(0, math.ceil(remaining))


def record_failure(username):
    user = get_user_model().objects.filter(username=username).first()
    if user is None:
        # 없는 아이디는 셀 대상이 없다. 이런 시도는 IP 횟수 제한이 막는다.
        return

    with transaction.atomic():
        # 동시에 여러 번 틀려도 횟수가 빠지지 않게, 이 줄을 잠그고 읽는다.
        failure, _ = LoginFailure.objects.select_for_update().get_or_create(user=user)
        failure.failed_count += 1
        duration = lock_duration(failure.failed_count)
        if duration is not None:
            failure.locked_until = timezone.now() + duration
        failure.save()


def reset(username):
    LoginFailure.objects.filter(user__username=username).delete()
