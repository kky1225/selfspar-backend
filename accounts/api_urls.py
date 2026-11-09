from django.contrib.auth.decorators import login_not_required
from django.urls import path

from . import api_views

# projects/api_urls.py와 같은 이유로 로그인 검사는 DRF에 맡긴다.
urlpatterns = [
    path('csrf/', login_not_required(api_views.CsrfApi.as_view()), name='api_csrf'),
    path('login/', login_not_required(api_views.LoginApi.as_view()), name='api_login'),
    path('logout/', login_not_required(api_views.LogoutApi.as_view()), name='api_logout'),
    path('me/', login_not_required(api_views.MeApi.as_view()), name='api_me'),
]
