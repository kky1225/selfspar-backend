from django.conf import settings
from django.db import models


class Finding(models.Model):
    """점검에서 찾은 문제 하나. 같은 대상·모듈에서 같은 fingerprint가 다시 나오면 새로 만들지 않고 이 줄을 다시 쓴다."""

    class Status(models.TextChoices):
        OPEN = 'open', '미해결'
        # 점검만 이 상태로 바꾼다. 같은 대상·모듈을 다시 점검했는데 나오지 않았을 때다(GitHub 코드 스캐닝의 fixed와 같다).
        FIXED = 'fixed', '해결됨'
        # 사람이 사유를 적고 바꾼다. 다시 나와도 그대로 둔다(DefectDojo와 같다).
        FALSE_POSITIVE = 'false_positive', '오탐'
        RISK_ACCEPTED = 'risk_accepted', '위험 수용'

    class Severity(models.TextChoices):
        CRITICAL = 'critical', '치명'
        HIGH = 'high', '높음'
        MEDIUM = 'medium', '보통'
        LOW = 'low', '낮음'
        INFO = 'info', '정보'

    # 다른 앱의 모델은 '앱이름.모델이름' 글자로 가리킨다. 앱끼리 서로 import하다 꼬이지 않게 한다.
    target = models.ForeignKey('projects.Target', on_delete=models.CASCADE, related_name='findings')
    # 어느 점검 모듈이 찾았는지. ModuleRun.module과 같은 값이다. 예: 'secrets'
    module = models.CharField('모듈', max_length=30)
    # 점검 도구가 주는, 발견 하나를 구분하는 값. 다음 점검에서 같은 발견인지 이 값으로 판단한다.
    fingerprint = models.CharField('고유 값', max_length=500)
    rule_id = models.CharField('규칙', max_length=100)
    title = models.CharField('제목', max_length=300)
    severity = models.CharField('심각도', max_length=10, choices=Severity.choices)
    # 파일:줄, 주소 같은 위치
    location = models.CharField('위치', max_length=500)
    # 문제가 된 부분. 비밀 값은 가린 상태로만 저장한다.
    evidence = models.TextField('근거', blank=True)
    # 모듈마다 다른 정보. 예: 시크릿 점검은 커밋과 날짜, 의존성 점검은 패키지와 CVE
    extra = models.JSONField('추가 정보', default=dict, blank=True)
    # 이 발견을 본 모듈 실행들. 한 발견이 여러 점검에서 계속 보일 수 있어서 다대다로 잇는다.
    runs = models.ManyToManyField('scans.ModuleRun', related_name='findings', verbose_name='본 모듈 실행')
    created_at = models.DateTimeField('처음 발견', auto_now_add=True)
    # 지금 상태. 바뀐 내역은 FindingEvent에 한 줄씩 쌓는다.
    status = models.CharField('상태', max_length=20, choices=Status.choices, default=Status.OPEN)
    # 위험 수용을 이날까지 인정한다. 위험 수용일 때만 채운다.
    accepted_until = models.DateField('위험 수용 만료일', null=True, blank=True)

    class Meta:
        verbose_name = '발견'
        ordering = ['id']
        constraints = [
            # 같은 대상·모듈 안에서 같은 발견은 한 줄만 둔다(중복 제거).
            models.UniqueConstraint(fields=['target', 'module', 'fingerprint'], name='unique_finding_per_target_module'),
        ]

    def __str__(self):
        return f'{self.target.name} / {self.rule_id} / {self.location}'


class FindingEvent(models.Model):
    """발견의 상태가 바뀐 기록 한 줄(이력). 바꾼 사람이나 바뀌게 만든 칸, 사유를 남긴다. 지우거나 고치지 않고 쌓기만 한다."""

    finding = models.ForeignKey(Finding, on_delete=models.CASCADE, related_name='events')
    from_status = models.CharField('이전 상태', max_length=20, choices=Finding.Status.choices)
    to_status = models.CharField('바뀐 상태', max_length=20, choices=Finding.Status.choices)
    # 사람이 바꿀 때 적는 사유. GitHub도 닫는 사유를 280자까지 받는다.
    reason = models.CharField('사유', max_length=280, blank=True)
    # 위험 수용으로 바꿀 때 정한 만료일
    accepted_until = models.DateField('위험 수용 만료일', null=True, blank=True)
    # 바꾼 사람. 점검이 자동으로 바꿨으면 비어 있다. 계정을 지워도 기록은 남긴다.
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, verbose_name='바꾼 사람')
    # 자동으로 바뀌게 만든 칸(모듈 실행). 사람이 바꿨으면 비어 있다. 그 점검을 지워도 기록은 남긴다.
    run = models.ForeignKey(
        'scans.ModuleRun', on_delete=models.SET_NULL, null=True, blank=True, related_name='finding_events', verbose_name='바뀐 칸',
    )
    created_at = models.DateTimeField('바뀐 시각', auto_now_add=True)

    class Meta:
        verbose_name = '발견 상태 이력'
        ordering = ['-created_at', '-id']

    def __str__(self):
        return f'{self.finding} / {self.from_status} → {self.to_status}'
