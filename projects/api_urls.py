from django.urls import path

from . import api_views

# 로그인 검사는 DRF 설정(IsAuthenticated)이 한다.
urlpatterns = [
    path('projects/', api_views.ProjectListCreateApi.as_view(), name='api_project_list'),
    path('projects/<int:pk>/', api_views.ProjectDetailApi.as_view(), name='api_project_detail'),
    path('projects/<int:project_pk>/targets/', api_views.TargetCreateApi.as_view(), name='api_target_create'),
    path('targets/<int:target_pk>/accounts/', api_views.TestAccountListCreateApi.as_view(), name='api_account_list'),
    path('accounts/<int:pk>/', api_views.TestAccountDetailApi.as_view(), name='api_account_detail'),
]
