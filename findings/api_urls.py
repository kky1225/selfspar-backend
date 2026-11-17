from django.urls import path

from . import api_views

urlpatterns = [
    path('module-runs/<int:run_pk>/findings/', api_views.RunFindingListApi.as_view(), name='api_run_findings'),
]
