from rest_framework import serializers

from projects.models import Target

from .models import ModuleRun, Scan
from .modules import MODULES, MODULES_BY_KEY

# 한 번에 다시 점검할 수 있는 칸 수. 대상 × 모듈 수보다 넉넉하게 둔 상한이다.
MAX_RESCAN_RUNS = 500


class RescanSerializer(serializers.Serializer):
    """재점검 요청. 지난 점검 하나와 그 점검에서 다시 돌릴 칸(모듈 실행) 번호들.
    검사를 통과하면 validated_data에 지난 점검(source_scan)과 다시 만들 (대상, 모듈 key) 목록(pairs)이 담긴다."""

    source_scan = serializers.IntegerField()
    run_ids = serializers.ListField(child=serializers.IntegerField(), min_length=1, max_length=MAX_RESCAN_RUNS)

    def validate_source_scan(self, value):
        # 다른 프로젝트의 점검 칸을 섞어 이 프로젝트에서 돌리지 못하게, 이 프로젝트의 점검 안에서만 찾는다.
        # 끝나지 않은 점검이면 view가 이미 409로 막았다(프로젝트마다 끝나지 않은 점검은 하나뿐이다).
        scan = self.context['project'].scans.filter(pk=value).first()
        if scan is None:
            raise serializers.ValidationError('이 프로젝트의 점검이 아닙니다.')
        return scan

    def validate(self, data):
        source = data['source_scan']
        run_ids = set(data['run_ids'])
        runs = list(source.runs.select_related('target').filter(pk__in=run_ids))
        if len(runs) != len(run_ids):
            raise serializers.ValidationError({'run_ids': '이 점검의 칸이 아닌 번호가 있습니다.'})
        for run in runs:
            # 지난 점검 뒤에 모듈을 없앴거나 대상 종류가 바뀌었으면 지금은 돌릴 수 없다.
            module = MODULES_BY_KEY.get(run.module)
            if module is None or not module.applies_to(run.target):
                raise serializers.ValidationError({'run_ids': f'지금은 점검할 수 없는 칸입니다: {run.target.name} · {run.module}'})
        # 지난 점검의 칸 순서(id 순)를 그대로 따른다.
        data['pairs'] = [(run.target, run.module) for run in runs]
        return data


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
            'id', 'source_scan', 'status', 'status_label', 'created_at', 'finished_at',
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
        fields = [
            'id', 'project', 'source_scan', 'status', 'status_label', 'created_at', 'finished_at',
            'modules', 'targets', 'runs',
        ]

    def get_project(self, scan):
        return {'id': scan.project.id, 'name': scan.project.name}

    def get_modules(self, scan):
        # kinds: 이 모듈을 실행하는 대상 종류. 재점검에서 고르지 않은 칸('점검 안 함')과 해당 없는 칸(–)을 화면이 구분한다.
        return [{'key': module.key, 'label': module.label, 'kinds': list(module.kinds)} for module in MODULES]

    def get_targets(self, scan):
        # 점검을 시작한 뒤에 등록한 대상은 이 점검과 상관없어서 빼고 보낸다.
        targets = scan.project.targets.filter(created_at__lte=scan.created_at)
        return ScanTargetSerializer(targets, many=True).data
