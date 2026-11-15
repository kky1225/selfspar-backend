from django.db import models

from .crypto import decrypt, encrypt


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

    # 로그인 기능이 있어서 테스트 계정을 등록할 수 있는 종류
    LOGIN_KINDS = (Kind.API, Kind.DOMAIN)

    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name='targets')
    name = models.CharField('이름', max_length=100)
    kind = models.CharField('종류', max_length=10, choices=Kind.choices)
    environment = models.CharField('환경', max_length=10, choices=Environment.choices)
    # 종류마다 필요한 정보가 달라서 JSON 칸 하나에 담는다. 값 검사는 serializers.py에서 종류별로 한다.
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


class TestAccount(models.Model):
    """점검할 때 로그인에 쓰는 대상의 테스트 계정. 예: 관리자 API의 사용자 A"""

    target = models.ForeignKey(Target, on_delete=models.CASCADE, related_name='accounts')
    label = models.CharField('이름', max_length=50)
    username = models.CharField('아이디', max_length=200)
    # 원래 비밀번호는 저장하지 않는다. set_password / get_password로만 다룬다.
    password_encrypted = models.TextField('암호화된 비밀번호')
    created_at = models.DateTimeField('등록일', auto_now_add=True)

    class Meta:
        verbose_name = '테스트 계정'
        ordering = ['created_at']
        constraints = [
            models.UniqueConstraint(fields=['target', 'label'], name='unique_account_label_per_target'),
        ]

    def __str__(self):
        return f'{self.target} / {self.label}'

    def set_password(self, raw_password):
        self.password_encrypted = encrypt(raw_password)

    def get_password(self):
        return decrypt(self.password_encrypted)
