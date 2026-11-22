from django.contrib import admin

from .models import ModuleRun, Scan

admin.site.register(Scan)
admin.site.register(ModuleRun)
