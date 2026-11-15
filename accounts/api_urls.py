from django.urls import path

from . import api_views

# 로그인 검사는 DRF 설정(IsAuthenticated)이 한다. 로그인 전에 써야 하는 API는 view에서 AllowAny로 연다.
urlpatterns = [
    path('csrf/', api_views.CsrfApi.as_view(), name='api_csrf'),
    path('login/', api_views.LoginApi.as_view(), name='api_login'),
    path('logout/', api_views.LogoutApi.as_view(), name='api_logout'),
    path('me/', api_views.MeApi.as_view(), name='api_me'),
]
