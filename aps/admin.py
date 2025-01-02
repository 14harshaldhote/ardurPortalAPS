from django.contrib import admin
from .models import UserSession, Break

# Register your models here.
admin.site.register(UserSession)

@admin.register(Break)
class BreakAdmin(admin.ModelAdmin):
    list_display = ['employee', 'break_type', 'shift', 'start_time', 'end_time', 'duration']
    list_filter = ['break_type', 'shift', 'employee']
