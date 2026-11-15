"""대상 정보(config) 값 검사. serializers.py의 종류별 Config serializer가 쓴다."""

from urllib.parse import urlsplit

from django.core.exceptions import ValidationError
from django.core.validators import RegexValidator, URLValidator


def validate_web_url(value):
    URLValidator(schemes=['http', 'https'])(value)
    # https://아이디:비밀번호@주소 형태는 비밀번호가 DB에 그대로 저장되므로 막는다.
    parts = urlsplit(value)
    if parts.username or parts.password:
        raise ValidationError('주소에 아이디나 비밀번호를 넣을 수 없습니다.')


def validate_absolute_path(value):
    if not value.startswith('/') or '..' in value.split('/'):
        raise ValidationError('/로 시작하는 전체 경로를 입력하세요. ..는 쓸 수 없습니다.')


def validate_apk_path(value):
    validate_absolute_path(value)
    if not value.endswith('.apk'):
        raise ValidationError('.apk 파일 경로를 입력하세요.')


validate_url_path = RegexValidator(r'^/', '/로 시작하는 경로를 입력하세요.')
validate_aws_account_id = RegexValidator(r'^\d{12}$', '12자리 숫자를 입력하세요.')
validate_aws_region = RegexValidator(r'^[a-z]{2}(-[a-z]+)+-\d+$', '예: ap-northeast-2')

TOKEN_LOCATIONS = [('header', 'Authorization 헤더'), ('cookie', '쿠키')]
