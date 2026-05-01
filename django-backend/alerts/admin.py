from django.contrib import admin
from django.utils.html import format_html
from django.urls import path
from django.http import HttpResponseRedirect
from django.contrib import messages
from .models import Alert, IPProfile, DetectionRule
from django_tasks_db.models import DBTaskResult

class AlertAdmin(admin.ModelAdmin):
    search_fields = ('rule_description','raw_log')

# @admin.register(DBTaskResult)
# class TaskResultAdmin(admin.ModelAdmin):
#     list_display = ["id", "task_path", "status", "enqueued_at", "finished_at"]
#     list_filter = ["status"]
#     search_fields = ["id", "task_path"]
#     readonly_fields = [
#         "id", "task_path", "status",
#         "args_kwargs", "enqueued_at",
#         "finished_at", "return_value", "exception_class"
#     ]
#     ordering = ["-enqueued_at"]

admin.site.register(Alert, AlertAdmin)
@admin.register(IPProfile)
class IPProfileAdmin(admin.ModelAdmin):
    list_display = ['ip_address', 'threat_score', 'is_blocked', 'total_events', 'unblock_button']
    list_filter = ['is_blocked']
    ordering = ['-threat_score']

    def unblock_button(self, obj):
        if obj.is_blocked:
            return format_html(
                '<a class="button" href="{}">🔓 Unblock</a>',
                f'/admin/alerts/ipprofile/{obj.pk}/unblock/'
            )
        return '✅ Not Blocked'
    unblock_button.short_description = 'Action'

    def get_urls(self):
        urls = super().get_urls()
        custom = [
            path('<int:pk>/unblock/', self.admin_site.admin_view(self.unblock_view))
        ]
        return custom + urls

    def unblock_view(self, request, pk):
        import sys
        sys.path.insert(0, '/home/hazem/automated_incident_response')
        from response_worker.actions.block_ip import unblock_ip

        ip = IPProfile.objects.get(pk=pk)
        unblock_ip(ip.ip_address)

        ip.is_blocked = False
        ip.blocked_at = None
        ip.blocked_reason = None
        ip.save()

        messages.success(request, f'✅ IP {ip.ip_address} unblocked successfully!')
        return HttpResponseRedirect('/admin/alerts/ipprofile/')


@admin.register(DetectionRule)
class DetectionRuleAdmin(admin.ModelAdmin):
    list_display = ['rule_id', 'name', 'severity_default', 'is_active']
