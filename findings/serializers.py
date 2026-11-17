from rest_framework import serializers

from .models import Finding


class FindingSerializer(serializers.ModelSerializer):
    severity_label = serializers.CharField(source='get_severity_display', read_only=True)
    # 이 발견을 처음 본 점검 번호. view에서 계산해 붙인다.
    first_scan_id = serializers.IntegerField(read_only=True)

    class Meta:
        model = Finding
        fields = [
            'id', 'rule_id', 'title', 'severity', 'severity_label', 'location', 'evidence', 'extra',
            'first_scan_id', 'created_at',
        ]
