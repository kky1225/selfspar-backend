from django.contrib import admin

from .models import Finding, FindingEvent


@admin.register(Finding)
class FindingAdmin(admin.ModelAdmin):
    # 상태는 API(사유·기간 검사와 이력)로만 바꾼다. 관리자 화면에서 고치면 그 규칙을 모두 건너뛰게 된다.
    readonly_fields = ('status', 'accepted_until')


@admin.register(FindingEvent)
class FindingEventAdmin(admin.ModelAdmin):
    """상태 이력은 쌓기만 한다. 관리자 화면에서도 보기만 한다."""

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False
