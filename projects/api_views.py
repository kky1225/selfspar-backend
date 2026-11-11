from django.db.models import Count
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import Project
from .serializers import ProjectSerializer


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
