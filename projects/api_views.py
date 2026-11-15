from django.db.models import Count
from django.shortcuts import get_object_or_404
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import Project
from .serializers import ProjectDetailSerializer, ProjectSerializer, TargetSerializer


class ProjectListCreateApi(APIView):
    def get(self, request):
        # 집계(GROUP BY)를 쓰면 모델의 기본 정렬이 적용되지 않아서 직접 적는다.
        projects = Project.objects.annotate(target_count=Count('targets')).order_by('-created_at')
        serializer = ProjectSerializer(projects, many=True)
        return Response(serializer.data)

    def post(self, request):
        serializer = ProjectSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)


class ProjectDetailApi(APIView):
    def get(self, request, pk):
        # 없는 번호면 Http404가 나고, DRF가 404 JSON 응답으로 바꾼다.
        project = get_object_or_404(Project, pk=pk)
        serializer = ProjectDetailSerializer(project)
        return Response(serializer.data)


class TargetCreateApi(APIView):
    def post(self, request, project_pk):
        project = get_object_or_404(Project, pk=project_pk)
        serializer = TargetSerializer(data=request.data, context={'project': project})
        serializer.is_valid(raise_exception=True)
        # 프로젝트는 입력값에 넣어 보내도 쓰지 않고, 주소의 프로젝트로 저장한다.
        serializer.save(project=project)
        return Response(serializer.data, status=status.HTTP_201_CREATED)
