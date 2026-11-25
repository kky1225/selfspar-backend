from django.urls import path

from . import api_views

urlpatterns = [
    path('module-runs/<int:run_pk>/findings/', api_views.RunFindingListApi.as_view(), name='api_run_findings'),
    path('findings/<int:pk>/status/', api_views.FindingStatusApi.as_view(), name='api_finding_status'),
    path('findings/<int:pk>/events/', api_views.FindingEventListApi.as_view(), name='api_finding_events'),
]
