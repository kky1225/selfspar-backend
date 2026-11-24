from django.db import models
from django.utils import timezone

from projects.models import Project, Target


class Scan(models.Model):
    """점검 1회. 프로젝트의 대상마다 해당하는 모듈을 실행한다."""

    class Status(models.TextChoices):
        QUEUED = 'queued', '대기'
        RUNNING = 'running', '실행 중'
        DONE = 'done', '완료'
        CANCELLED = 'cancelled', '취소'

    # 아직 끝나지 않은 상태. 프로젝트마다 이 상태의 점검은 하나만 둘 수 있다.
    ACTIVE = (Status.QUEUED, Status.RUNNING)

    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name='scans')
    # 지난 점검의 일부 칸만 다시 돌린 재점검이면 그 지난 점검. 비어 있으면 전체 점검이다.
    # 재점검은 지난 점검에 딸린 후속 기록이라 지난 점검을 지우면 함께 지운다(GitHub Actions의 재실행과 같다).
    source_scan = models.ForeignKey(
        'self', on_delete=models.CASCADE, null=True, blank=True, related_name='rescans', verbose_name='다시 점검한 점검',
    )
    status = models.CharField('상태', max_length=10, choices=Status.choices, default=Status.QUEUED)
    created_at = models.DateTimeField('시작일', auto_now_add=True)
    # 실행 중인 점검을 돌리는 worker가 잠시마다 남기는 시각(살아 있다는 신호). 오래 끊기면 worker가 멈춘 것으로 본다.
    heartbeat_at = models.DateTimeField('마지막 신호', null=True, blank=True)
    finished_at = models.DateTimeField('종료일', null=True, blank=True)

    class Meta:
        verbose_name = '점검'
        ordering = ['-created_at']
        constraints = [
            # 같은 프로젝트에 끝나지 않은 점검이 둘 생기지 않게 DB에서도 막는다.
            # 조건(condition)에 맞는 줄끼리만 중복을 검사한다(부분 유니크 제약).
            models.UniqueConstraint(
                fields=['project'],
                condition=models.Q(status__in=['queued', 'running']),
                name='one_active_scan_per_project',
            ),
        ]

    def __str__(self):
        return f'{self.project} / 점검 #{self.pk}'

    def cancel(self):
        """끝나지 않은 점검을 취소한다. 끝난 칸의 결과는 그대로 두고, 끝나지 않은 칸만 취소로 바꾼다.
        부르는 쪽에서 트랜잭션을 열고 이 점검 줄을 잠근 뒤에 부른다."""
        now = timezone.now()
        self.status = self.Status.CANCELLED
        self.finished_at = now
        self.save(update_fields=['status', 'finished_at'])
        self.runs.filter(status__in=ModuleRun.ACTIVE).update(status=ModuleRun.Status.CANCELLED, finished_at=now)


class ModuleRun(models.Model):
    """모듈 실행 기록 1건(이력). 점검 1회 안에서 대상 하나에 모듈 하나를 실행한 결과다.
    점검할 때마다 새로 쌓이고, 결과 화면 격자의 칸 하나가 이것 하나다."""

    class Status(models.TextChoices):
        QUEUED = 'queued', '대기'
        RUNNING = 'running', '실행 중'
        PASSED = 'passed', '이상 없음'
        FOUND = 'found', '발견'
        FAILED = 'failed', '실패'
        # 점검을 취소해서 실행하지 않았거나 도중에 멈춘 칸
        CANCELLED = 'cancelled', '취소'

    # 아직 끝나지 않은 상태. 점검을 취소하면 이 상태의 칸을 모두 취소로 바꾼다.
    ACTIVE = (Status.QUEUED, Status.RUNNING)

    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='runs')
    target = models.ForeignKey(Target, on_delete=models.CASCADE, related_name='module_runs')
    # 모듈 목록은 DB가 아니라 코드(scans/modules)에 있다. 여기에는 모듈의 key를 적는다. 예: 'secrets'
    module = models.CharField('모듈', max_length=30)
    status = models.CharField('상태', max_length=10, choices=Status.choices, default=Status.QUEUED)
    finding_count = models.PositiveIntegerField('발견 수', default=0)
    # 도구를 업데이트하면 같은 코드에서도 결과가 달라질 수 있어서 버전을 남긴다.
    tool_version = models.CharField('도구 버전', max_length=50, blank=True)
    # 도구가 낸 원본 결과 파일. SELFSPAR_SCAN_RESULTS_DIR 아래의 경로다.
    raw_output_path = models.CharField('원본 결과 파일', max_length=500, blank=True)
    error_message = models.TextField('오류 내용', blank=True)
    started_at = models.DateTimeField('시작일', null=True, blank=True)
    finished_at = models.DateTimeField('종료일', null=True, blank=True)

    class Meta:
        verbose_name = '모듈 실행'
        ordering = ['id']
        constraints = [
            models.UniqueConstraint(fields=['scan', 'target', 'module'], name='unique_run_per_scan'),
        ]

    def __str__(self):
        return f'{self.scan} / {self.target.name} / {self.module}'
