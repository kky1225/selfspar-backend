from django.contrib import admin

from .models import LoginFailure


# 잠긴 계정을 직접 풀어야 할 때 기록을 지운다.
@admin.register(LoginFailure)
class LoginFailureAdmin(admin.ModelAdmin):
    list_display = ['user', 'failed_count', 'locked_until']
