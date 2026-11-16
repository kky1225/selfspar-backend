# Django가 시작할 때 Celery 앱도 함께 불러온다. 그래야 web에서 작업을 worker로 보낼 수 있다.
from .celery import app as celery_app

__all__ = ('celery_app',)
