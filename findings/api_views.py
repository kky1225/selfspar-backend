from django.db.models import Case, IntegerField, OuterRef, Subquery, Value, When
from django.shortcuts import get_object_or_404
from rest_framework.pagination import PageNumberPagination
from rest_framework.views import APIView

from scans.models import ModuleRun

from .models import Finding
from .serializers import FindingSerializer

# 심각한 것부터 보여 주는 순서. Severity에 적은 순서(치명 → 정보)를 숫자로 바꿔 정렬한다.
# 글자 그대로 정렬하면 critical, high, info, low, medium처럼 알파벳 순이 된다.
SEVERITY_RANK = Case(
    *[When(severity=severity, then=Value(rank)) for rank, severity in enumerate(Finding.Severity.values)],
    output_field=IntegerField(),
)


class FindingPagination(PageNumberPagination):
    """의존성 점검은 한 칸에 발견이 수백 건 나올 수 있어서 50건씩 나눠 준다. ?page=2처럼 다음 쪽을 요청한다."""

    page_size = 50


class RunFindingListApi(APIView):
    """모듈 실행 하나(결과 격자의 칸 하나)에서 찾은 발견 목록. 심각한 것부터, 같으면 먼저 저장한 것부터."""

    def get(self, request, run_pk):
        run = get_object_or_404(ModuleRun, pk=run_pk)
        # 발견마다 처음 본 점검 번호. 다른 점검에서 본 기록까지 봐야 해서 하위 쿼리로 따로 구한다.
        # (이 실행으로 거른 뒤 Min('runs__scan')을 쓰면 이 실행만 보고 계산해서 항상 이번 점검이 나온다.)
        first_scan = ModuleRun.objects.filter(findings=OuterRef('pk')).order_by('scan_id').values('scan_id')[:1]
        findings = (
            Finding.objects.filter(runs=run)
            .annotate(first_scan_id=Subquery(first_scan))
            # 쪽을 나눌 때 순서가 매번 같아야 건너뛰거나 겹치는 발견이 없다. 그래서 마지막에 id로 한 번 더 정렬한다.
            .order_by(SEVERITY_RANK, 'id')
        )
        paginator = FindingPagination()
        page = paginator.paginate_queryset(findings, request, view=self)
        return paginator.get_paginated_response(FindingSerializer(page, many=True).data)
