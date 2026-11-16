from django.urls import path

from . import api_views

urlpatterns = [
    path('projects/<int:project_pk>/scans/', api_views.ScanListCreateApi.as_view(), name='api_scan_list'),
    path('scans/<int:pk>/', api_views.ScanDetailApi.as_view(), name='api_scan_detail'),
]
