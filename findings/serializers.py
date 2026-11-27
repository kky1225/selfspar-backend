from datetime import timedelta

from django.utils import timezone
from rest_framework import serializers

from .models import Finding, FindingEvent


class FindingSerializer(serializers.ModelSerializer):
    severity_label = serializers.CharField(source='get_severity_display', read_only=True)
    status_label = serializers.CharField(source='get_status_display', read_only=True)
    # 이 발견을 처음 본 점검 번호. view에서 계산해 붙인다.
    first_scan_id = serializers.IntegerField(read_only=True)
    # 이 발견을 위험 수용할 수 있는 최대 일수. 위험 수용할 수 없는 심각도면 null이다.
    # 화면이 같은 규칙을 따로 들고 있지 않도록 서버가 알려 준다.
    max_accept_days = serializers.SerializerMethodField()

    class Meta:
        model = Finding
        fields = [
            'id', 'rule_id', 'title', 'severity', 'severity_label', 'location', 'evidence', 'extra',
            'status', 'status_label', 'accepted_until', 'max_accept_days', 'first_scan_id', 'created_at',
        ]

    def get_max_accept_days(self, finding):
        return Finding.RISK_ACCEPT_MAX_DAYS.get(finding.severity)


class FindingStatusSerializer(serializers.Serializer):
    """사람이 발견의 상태를 바꾸는 요청. 바꿀 발견은 context['finding']으로 받는다(잠근 뒤 다시 읽은 것)."""

    status = serializers.ChoiceField(choices=Finding.MANUAL_STATUSES, error_messages={
        'invalid_choice': '미해결·오탐·위험 수용만 고를 수 있습니다. 해결됨은 다시 점검해서 안 나오면 바뀝니다.',
    })
    # 사람이 바꾸면 사유를 반드시 남긴다. 앞뒤 공백만 있는 사유도 받지 않는다(trim_whitespace 기본값).
    reason = serializers.CharField(max_length=280)
    accepted_until = serializers.DateField(required=False, allow_null=True)

    def validate(self, data):
        finding = self.context['finding']
        if data['status'] != Finding.Status.RISK_ACCEPTED:
            if data.get('accepted_until'):
                raise serializers.ValidationError({'accepted_until': '만료일은 위험 수용일 때만 정합니다.'})
            if data['status'] == finding.status:
                raise serializers.ValidationError({'status': '이미 이 상태입니다.'})
            data['accepted_until'] = None
            return data

        # 위험 수용. 같은 상태로 다시 보내면 기한 연장이다.
        if not finding.can_accept_risk():
            raise serializers.ValidationError({'status': f'{finding.get_severity_display()} 발견은 위험 수용할 수 없습니다. 고쳐야 합니다.'})
        until = data.get('accepted_until')
        if until is None:
            raise serializers.ValidationError({'accepted_until': '위험 수용은 만료일이 필요합니다.'})
        if finding.status == Finding.Status.RISK_ACCEPTED and until == finding.accepted_until:
            raise serializers.ValidationError({'accepted_until': '이미 이 만료일입니다.'})
        # 만료일 하루 동안까지 인정한다. 오늘 이전이면 받는 순간 만료라 내일부터 고를 수 있다. 날짜는 한국 시각 기준이다.
        today = timezone.localdate()
        max_days = Finding.RISK_ACCEPT_MAX_DAYS[finding.severity]
        if until <= today:
            raise serializers.ValidationError({'accepted_until': '만료일은 내일 이후여야 합니다.'})
        if until > today + timedelta(days=max_days):
            raise serializers.ValidationError({
                'accepted_until': f'{finding.get_severity_display()} 발견은 {max_days}일까지만 위험 수용할 수 있습니다.',
            })
        return data


class FindingEventSerializer(serializers.ModelSerializer):
    from_status_label = serializers.CharField(source='get_from_status_display', read_only=True)
    to_status_label = serializers.CharField(source='get_to_status_display', read_only=True)
    # 사람이 바꿨으면 그 사람 이름, 점검이 바꿨으면 그 점검 번호. 둘 다 비면 만료처럼 시스템이 바꾼 것이다.
    username = serializers.CharField(source='user.username', read_only=True, default=None)
    scan_id = serializers.IntegerField(source='run.scan_id', read_only=True, default=None)

    class Meta:
        model = FindingEvent
        fields = [
            'id', 'from_status', 'from_status_label', 'to_status', 'to_status_label', 'reason', 'accepted_until',
            'username', 'scan_id', 'created_at',
        ]
