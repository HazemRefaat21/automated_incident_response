from django.contrib import admin

from .models import AttackType


@admin.register(AttackType)
class AttackTypeAdmin(admin.ModelAdmin):
    list_display  = ('name', 'key', 'base_score', 'priority', 'is_active', 'updated_at')
    list_filter   = ('is_active',)
    list_editable = ('base_score', 'priority', 'is_active')
    search_fields = ('name', 'key', 'keywords')
    prepopulated_fields = {'key': ('name',)}
