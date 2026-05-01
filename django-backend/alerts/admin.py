from django.contrib import admin
from .models import Alert, IPProfile, DetectionRule

admin.site.register(Alert)
admin.site.register(IPProfile)
admin.site.register(DetectionRule)
