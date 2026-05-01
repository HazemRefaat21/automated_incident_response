from django.contrib import admin
from .models import Alert, IPProfile, DetectionRule

class AlertAdmin(admin.ModelAdmin):
    search_fields = ('rule_description','raw_log')


admin.site.register(Alert, AlertAdmin)
admin.site.register(IPProfile)
admin.site.register(DetectionRule)
