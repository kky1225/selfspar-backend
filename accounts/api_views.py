import math

from django.contrib.auth import authenticate, login, logout
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_protect, ensure_csrf_cookie
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle
from rest_framework.views import APIView

from . import lockout
from .serializers import LoginSerializer, UserSerializer


# React 화면은 Django가 만들지 않아서 CSRF 토큰을 받을 곳이 따로 필요하다.
@method_decorator(ensure_csrf_cookie, name='dispatch')
class CsrfApi(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        return Response(status=status.HTTP_204_NO_CONTENT)


# DRF는 로그인한 요청에만 CSRF를 검사한다. 로그인 요청은 아직 로그인 전이라 직접 켠다.
@method_decorator(csrf_protect, name='dispatch')
class LoginApi(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = 'login'

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = authenticate(request, **serializer.validated_data)
        if user is None:
            remaining = lockout.remaining_lock_seconds(serializer.validated_data['username'])
            if remaining:
                return Response(
                    {
                        'detail': f'로그인에 여러 번 실패해 계정이 잠겼습니다. '
                                  f'{math.ceil(remaining / 60)}분 뒤에 다시 시도하세요.',
                        'lock_remaining_seconds': remaining,
                    },
                    status=status.HTTP_423_LOCKED,
                )
            # 아이디가 없는지 비밀번호가 틀렸는지 구분해서 알려 주지 않는다.
            return Response(
                {'detail': '아이디 또는 비밀번호가 올바르지 않습니다.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # 세션 ID와 CSRF 토큰을 새로 만든다.
        login(request, user)
        return Response(UserSerializer(user).data)


class LogoutApi(APIView):
    def post(self, request):
        logout(request)
        return Response(status=status.HTTP_204_NO_CONTENT)


class MeApi(APIView):
    def get(self, request):
        return Response(UserSerializer(request.user).data)
