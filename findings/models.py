from django.db import models


class Finding(models.Model):
    """점검에서 찾은 문제 하나. 같은 대상·모듈에서 같은 fingerprint가 다시 나오면 새로 만들지 않고 이 줄을 다시 쓴다."""

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

    class Meta:
        verbose_name = '발견'
        ordering = ['id']
        constraints = [
            # 같은 대상·모듈 안에서 같은 발견은 한 줄만 둔다(중복 제거).
            models.UniqueConstraint(fields=['target', 'module', 'fingerprint'], name='unique_finding_per_target_module'),
        ]

    def __str__(self):
        return f'{self.target.name} / {self.rule_id} / {self.location}'
