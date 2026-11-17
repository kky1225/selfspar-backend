from django.db.models import OuterRef, Subquery
from django.shortcuts import get_object_or_404
from rest_framework.response import Response
from rest_framework.views import APIView

from scans.models import ModuleRun

from .models import Finding
from .serializers import FindingSerializer


class RunFindingListApi(APIView):
    """모듈 실행 하나(결과 격자의 칸 하나)에서 찾은 발견 목록"""

    def get(self, request, run_pk):
        run = get_object_or_404(ModuleRun, pk=run_pk)
        # 발견마다 처음 본 점검 번호. 다른 점검에서 본 기록까지 봐야 해서 하위 쿼리로 따로 구한다.
        # (이 실행으로 거른 뒤 Min('runs__scan')을 쓰면 이 실행만 보고 계산해서 항상 이번 점검이 나온다.)
        first_scan = ModuleRun.objects.filter(findings=OuterRef('pk')).order_by('scan_id').values('scan_id')[:1]
        findings = Finding.objects.filter(runs=run).annotate(first_scan_id=Subquery(first_scan))
        return Response(FindingSerializer(findings, many=True).data)
