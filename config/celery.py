"""Celery 설정. worker는 `celery -A config worker`로 이 파일의 app을 찾아 실행한다."""
import os

from celery import Celery

# worker도 Django 설정(DB, 모델)을 써야 해서 web과 같은 설정 파일을 가리킨다.
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')

app = Celery('config')
# settings.py에서 CELERY_로 시작하는 값을 Celery 설정으로 읽는다. 예: CELERY_BROKER_URL → broker_url
app.config_from_object('django.conf:settings', namespace='CELERY')
# 각 앱의 tasks.py에 있는 작업을 찾아 등록한다.
app.autodiscover_tasks()
