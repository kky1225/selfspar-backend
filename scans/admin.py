from django.contrib import admin

from .models import Scan, ScanTask

# worker가 도중에 꺼져서 점검이 '실행 중'으로 남으면 새 점검을 시작할 수 없다.
# 점검 취소 기능을 만들기 전까지는 관리자 화면에서 상태를 '완료'로 바꿔 풀 수 있다.
admin.site.register(Scan)
admin.site.register(ScanTask)
