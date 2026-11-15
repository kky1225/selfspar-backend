"""테스트 계정 비밀번호 암호화. 점검할 때 실제로 로그인해야 해서 해시가 아니라 되돌릴 수 있는 암호화를 쓴다."""

from functools import cache

from cryptography.fernet import Fernet
from django.conf import settings


@cache
def _fernet():
    # 키 형식이 틀리면 여기서 바로 오류가 난다. 같은 키로 만든 객체를 계속 다시 쓴다.
    return Fernet(settings.SELFSPAR_ENCRYPTION_KEY)


def encrypt(text):
    return _fernet().encrypt(text.encode()).decode()


def decrypt(token):
    return _fernet().decrypt(token.encode()).decode()
