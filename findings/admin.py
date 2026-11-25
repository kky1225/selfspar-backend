from django.contrib import admin

from .models import Finding, FindingEvent

admin.site.register(Finding)
admin.site.register(FindingEvent)
