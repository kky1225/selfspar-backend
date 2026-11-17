from rest_framework import serializers

from projects.models import Target

from .models import ModuleRun, Scan
from .modules import MODULES


class ScanSummarySerializer(serializers.ModelSerializer):
    """프로젝트 상세의 최근 점검 목록 한 줄. 개수는 view에서 세어 붙인다."""

    status_label = serializers.CharField(source='get_status_display', read_only=True)
    run_count = serializers.IntegerField(read_only=True, default=0)
    finished_run_count = serializers.IntegerField(read_only=True, default=0)
    # 발견 건수 합계. 칸 수가 아니다.
    finding_count = serializers.IntegerField(read_only=True, default=0)
    failed_count = serializers.IntegerField(read_only=True, default=0)

    class Meta:
        model = Scan
        fields = [
            'id', 'status', 'status_label', 'created_at', 'finished_at',
            'run_count', 'finished_run_count', 'finding_count', 'failed_count',
        ]


class ScanTargetSerializer(serializers.ModelSerializer):
    """결과 격자의 행. 점검에 필요한 정보만 보낸다."""

    kind_label = serializers.CharField(source='get_kind_display', read_only=True)
    environment_label = serializers.CharField(source='get_environment_display', read_only=True)

    class Meta:
        model = Target
        fields = ['id', 'name', 'kind', 'kind_label', 'environment', 'environment_label']


class ModuleRunSerializer(serializers.ModelSerializer):
    status_label = serializers.CharField(source='get_status_display', read_only=True)

    class Meta:
        model = ModuleRun
        # 원본 결과 파일 경로는 서버 안의 경로라서 보내지 않는다.
        fields = [
            'id', 'target', 'module', 'status', 'status_label', 'finding_count',
            'tool_version', 'error_message', 'started_at', 'finished_at',
        ]


class ScanDetailSerializer(serializers.ModelSerializer):
    """점검 결과 화면. 격자를 그리는 데 필요한 열(모듈), 행(대상), 칸(모듈 실행)을 함께 보낸다."""

    status_label = serializers.CharField(source='get_status_display', read_only=True)
    project = serializers.SerializerMethodField()
    modules = serializers.SerializerMethodField()
    targets = serializers.SerializerMethodField()
    runs = ModuleRunSerializer(many=True, read_only=True)

    class Meta:
        model = Scan
        fields = ['id', 'project', 'status', 'status_label', 'created_at', 'finished_at', 'modules', 'targets', 'runs']

    def get_project(self, scan):
        return {'id': scan.project.id, 'name': scan.project.name}

    def get_modules(self, scan):
        return [{'key': module.key, 'label': module.label} for module in MODULES]

    def get_targets(self, scan):
        # 점검을 시작한 뒤에 등록한 대상은 이 점검과 상관없어서 빼고 보낸다.
        targets = scan.project.targets.filter(created_at__lte=scan.created_at)
        return ScanTargetSerializer(targets, many=True).data
