from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.core.exceptions import PermissionDenied

from . import lockout


class LockoutModelBackend(ModelBackend):
    """Django 기본 로그인 확인에 계정 잠금을 더한다.

    authenticate()를 쓰는 모든 로그인(API, 관리자 화면)에 똑같이 적용된다.
    """

    def authenticate(self, request, username=None, password=None, **kwargs):
        if username is None:
            username = kwargs.get(get_user_model().USERNAME_FIELD)
        if username is None or password is None:
            return None

        if lockout.remaining_lock_seconds(username):
            # 잠긴 동안에는 비밀번호를 확인하지 않고, 다른 확인 방법으로도 넘어가지 않는다.
            raise PermissionDenied

        user = super().authenticate(request, username=username, password=password, **kwargs)
        if user is None:
            lockout.record_failure(username)
        else:
            lockout.reset(username)
        return user
