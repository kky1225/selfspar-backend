import logging

from django.db import IntegrityError, transaction
from django.db.models import Count, Q
from django.shortcuts import get_object_or_404
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from projects.models import Project

from .models import Scan, ScanTask
from .modules import MODULES
from .serializers import ScanDetailSerializer, ScanSummarySerializer
from .tasks import run_scan

logger = logging.getLogger(__name__)

ALREADY_RUNNING = {'detail': '이미 실행 중인 점검이 있습니다. 끝난 뒤에 다시 실행하세요.'}
FINISHED_TASK = (ScanTask.Status.PASSED, ScanTask.Status.FOUND, ScanTask.Status.FAILED)


class ScanListCreateApi(APIView):
    def get(self, request, project_pk):
        project = get_object_or_404(Project, pk=project_pk)
        # 칸 수를 상태별로 센다. filter=Q(...)는 SQL의 COUNT(...) FILTER (WHERE ...)가 된다.
        scans = project.scans.annotate(
            task_count=Count('tasks'),
            finished_task_count=Count('tasks', filter=Q(tasks__status__in=FINISHED_TASK)),
            found_count=Count('tasks', filter=Q(tasks__status=ScanTask.Status.FOUND)),
            failed_count=Count('tasks', filter=Q(tasks__status=ScanTask.Status.FAILED)),
        ).order_by('-created_at')
        return Response(ScanSummarySerializer(scans, many=True).data)

    def post(self, request, project_pk):
        project = get_object_or_404(Project, pk=project_pk)
        if project.scans.filter(status__in=Scan.ACTIVE).exists():
            return Response(ALREADY_RUNNING, status=status.HTTP_409_CONFLICT)

        # 전체 점검: 모든 대상 × 그 대상에 해당하는 모든 모듈
        pairs = [(target, module) for target in project.targets.all() for module in MODULES if module.applies_to(target)]
        if not pairs:
            return Response(
                {'detail': '실행할 수 있는 점검이 없습니다. 지금은 저장소 대상만 점검할 수 있습니다.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            # 점검과 칸을 한 번에 저장한다. 중간에 실패하면 둘 다 저장하지 않는다(@Transactional과 같다).
            with transaction.atomic():
                scan = Scan.objects.create(project=project)
                ScanTask.objects.bulk_create(
                    ScanTask(scan=scan, target=target, module=module.key) for target, module in pairs
                )
        except IntegrityError:
            # 위의 exists() 검사와 저장 사이에 다른 요청이 먼저 점검을 만든 경우. DB 제약이 막아 준다.
            return Response(ALREADY_RUNNING, status=status.HTTP_409_CONFLICT)

        try:
            run_scan.delay(scan.pk)
        except Exception:
            # Redis에 넣지 못하면 아무도 실행하지 않는 점검이 '대기'로 남아 다음 점검을 막는다. 만든 것을 지운다.
            logger.exception('점검 #%s를 worker에 보내지 못함', scan.pk)
            scan.delete()
            return Response(
                {'detail': '점검 실행기에 연결하지 못했습니다. redis와 worker 컨테이너가 떠 있는지 확인하세요.'},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )

        return Response(ScanDetailSerializer(scan).data, status=status.HTTP_201_CREATED)


class ScanDetailApi(APIView):
    def get(self, request, pk):
        scans = Scan.objects.select_related('project').prefetch_related('tasks')
        scan = get_object_or_404(scans, pk=pk)
        return Response(ScanDetailSerializer(scan).data)
