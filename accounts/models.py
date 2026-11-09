from django.conf import settings
from django.db import models


class LoginFailure(models.Model):
    # Django의 사용자 테이블에는 칸을 바로 더할 수 없어서 1:1 테이블을 따로 둔다.
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='login_failure',
    )
    failed_count = models.PositiveIntegerField('연속 실패 횟수', default=0)
    locked_until = models.DateTimeField('잠금 해제 시각', null=True, blank=True)

    class Meta:
        verbose_name = '로그인 실패 기록'

    def __str__(self):
        return f'{self.user} / {self.failed_count}회'
