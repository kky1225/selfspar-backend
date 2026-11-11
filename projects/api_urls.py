from django.contrib.auth.decorators import login_not_required
from django.urls import path

from . import api_views

urlpatterns = [
    # 로그인 검사는 DRF가 한다. LoginRequiredMiddleware를 거치면
    # 로그인 전 요청이 JSON 오류 대신 로그인 화면 이동(302)으로 응답된다.
    path('projects/', login_not_required(api_views.ProjectListCreateApi.as_view()), name='api_project_list'),
]
