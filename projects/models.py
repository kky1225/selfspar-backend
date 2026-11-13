from django.db import models


class Project(models.Model):
    """점검할 내 서비스 하나. 예: investfeed"""

    # 이름으로 서비스를 구분하므로 중복을 막는다.
    name = models.CharField('이름', max_length=100, unique=True)
    description = models.TextField('설명', blank=True)
    # 기술 이름 목록. 예: ["Spring Boot", "Kotlin"]
    stack = models.JSONField('기술 스택', default=list, blank=True)
    created_at = models.DateTimeField('등록일', auto_now_add=True)

    class Meta:
        verbose_name = '프로젝트'
        ordering = ['-created_at']

    def __str__(self):
        return self.name


class Target(models.Model):
    """프로젝트에 속한 점검 대상 하나. 예: investfeed 운영 API"""

    class Kind(models.TextChoices):
        REPO = 'repo', '저장소'
        DOMAIN = 'domain', '도메인'
        API = 'api', 'API'
        APK = 'apk', 'APK'
        CLOUD = 'cloud', '클라우드 계정'

    class Environment(models.TextChoices):
        LOCAL = 'local', '로컬'
        STAGING = 'staging', '스테이징'
        PROD = 'prod', '운영'

    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name='targets')
    name = models.CharField('이름', max_length=100)
    kind = models.CharField('종류', max_length=10, choices=Kind.choices)
    environment = models.CharField('환경', max_length=10, choices=Environment.choices)
    # 종류마다 필요한 정보가 달라서 JSON 칸 하나에 담는다. 값 검사는 forms.py에서 한다.
    config = models.JSONField('종류별 정보', default=dict)
    created_at = models.DateTimeField('등록일', auto_now_add=True)

    class Meta:
        verbose_name = '점검 대상'
        ordering = ['created_at']
        constraints = [
            models.UniqueConstraint(fields=['project', 'name'], name='unique_target_name_per_project'),
        ]

    def __str__(self):
        return f'{self.project} / {self.name}'
