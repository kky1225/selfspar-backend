from django.db import transaction
from django.db.models import Case, IntegerField, OuterRef, Subquery, Value, When
from django.shortcuts import get_object_or_404
from rest_framework import status
from rest_framework.pagination import PageNumberPagination
from rest_framework.response import Response
from rest_framework.views import APIView

from scans.models import ModuleRun

from .models import Finding, FindingEvent
from .serializers import FindingEventSerializer, FindingSerializer, FindingStatusSerializer

# 심각한 것부터 보여 주는 순서. Severity에 적은 순서(치명 → 정보)를 숫자로 바꿔 정렬한다.
# 글자 그대로 정렬하면 critical, high, info, low, medium처럼 알파벳 순이 된다.
SEVERITY_RANK = Case(
    *[When(severity=severity, then=Value(rank)) for rank, severity in enumerate(Finding.Severity.values)],
    output_field=IntegerField(),
)


def with_first_scan(findings):
    """발견마다 처음 본 점검 번호를 붙인다. 다른 점검에서 본 기록까지 봐야 해서 하위 쿼리로 따로 구한다.
    (칸 하나로 거른 뒤 Min('runs__scan')을 쓰면 그 칸만 보고 계산해서 항상 그 점검이 나온다.)"""
    first_scan = ModuleRun.objects.filter(findings=OuterRef('pk')).order_by('scan_id').values('scan_id')[:1]
    return findings.annotate(first_scan_id=Subquery(first_scan))


class FindingPagination(PageNumberPagination):
    """의존성 점검은 한 칸에 발견이 수백 건 나올 수 있어서 50건씩 나눠 준다. ?page=2처럼 다음 쪽을 요청한다."""

    page_size = 50


class RunFindingListApi(APIView):
    """모듈 실행 하나(결과 격자의 칸 하나)에서 찾은 발견 목록. 심각한 것부터, 같으면 먼저 저장한 것부터."""

    def get(self, request, run_pk):
        run = get_object_or_404(ModuleRun, pk=run_pk)
        # 쪽을 나눌 때 순서가 매번 같아야 건너뛰거나 겹치는 발견이 없다. 그래서 마지막에 id로 한 번 더 정렬한다.
        findings = with_first_scan(Finding.objects.filter(runs=run)).order_by(SEVERITY_RANK, 'id')
        paginator = FindingPagination()
        page = paginator.paginate_queryset(findings, request, view=self)
        return paginator.get_paginated_response(FindingSerializer(page, many=True).data)


class FindingStatusApi(APIView):
    """사람이 발견의 상태를 바꾼다(미해결·오탐·위험 수용). 바꿀 때마다 사유와 함께 이력을 남긴다."""

    def post(self, request, pk):
        with transaction.atomic():
            # 이 발견 줄을 잠근다. 점검이 결과를 저장하며 상태를 바꾸거나 만료 처리가 도는 것과 겹치지 않게,
            # 잠근 뒤 다시 읽은 상태를 '이전 상태'로 쓴다. 발견만 잠그고 칸·점검은 잠그지 않는다(점검 저장은 칸 → 발견 순서로 잠근다).
            finding = get_object_or_404(Finding.objects.select_for_update(), pk=pk)
            if finding.status == Finding.Status.FIXED:
                return Response(
                    {'detail': '해결된 발견은 바꿀 수 없습니다. 다시 나오면 점검이 미해결로 되돌립니다.'},
                    status=status.HTTP_409_CONFLICT,
                )
            serializer = FindingStatusSerializer(data=request.data, context={'finding': finding})
            serializer.is_valid(raise_exception=True)
            data = serializer.validated_data

            FindingEvent.objects.create(
                finding=finding, from_status=finding.status, to_status=data['status'], reason=data['reason'],
                accepted_until=data['accepted_until'], user=request.user,
            )
            finding.status, finding.accepted_until = data['status'], data['accepted_until']
            # 상태와 만료일만 저장한다. 예전에 읽은 객체를 통째로 저장하면 점검이 막 갱신한 제목·심각도 등을 덮어쓴다.
            finding.save(update_fields=['status', 'accepted_until'])
            # 잠금을 쥔 채로 응답할 내용을 읽는다. 커밋한 뒤에 읽으면, 그 사이 정리 작업이 이 발견을 지웠을 수 있다.
            updated = with_first_scan(Finding.objects.filter(pk=pk)).get()

        return Response(FindingSerializer(updated).data)


class FindingEventListApi(APIView):
    """발견 하나의 상태 이력. 최근 것부터."""

    def get(self, request, pk):
        finding = get_object_or_404(Finding, pk=pk)
        events = finding.events.select_related('user', 'run')
        return Response(FindingEventSerializer(events, many=True).data)
