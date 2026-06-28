from django import forms
from django.contrib import admin

from .models import ResponseDefinition, AttackResponseMap, ResponseAction


def _handler_choices():
    """Choices from the live handler registry; empty if worker import fails."""
    try:
        from response_worker.handlers import list_handler_keys
        return list_handler_keys()
    except Exception:
        return []


class ResponseDefinitionForm(forms.ModelForm):
    class Meta:
        model = ResponseDefinition
        fields = '__all__'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        choices = _handler_choices()
        if choices:
            self.fields['handler_key'] = forms.ChoiceField(
                choices=choices,
                help_text=self.fields['handler_key'].help_text,
            )


class AttackResponseMapInline(admin.TabularInline):
    model = AttackResponseMap
    extra = 1
    fields = ('attack_type', 'order', 'params_override', 'is_active')


@admin.register(ResponseDefinition)
class ResponseDefinitionAdmin(admin.ModelAdmin):
    form = ResponseDefinitionForm
    inlines = [AttackResponseMapInline]
    list_display  = ('name', 'handler_key', 'is_active', 'updated_at')
    list_filter   = ('is_active', 'handler_key')
    search_fields = ('name', 'handler_key', 'description')
    list_editable = ('is_active',)


@admin.register(AttackResponseMap)
class AttackResponseMapAdmin(admin.ModelAdmin):
    list_display  = ('attack_type', 'response', 'order', 'is_active')
    list_filter   = ('attack_type', 'is_active', 'response')
    list_editable = ('order', 'is_active')
    ordering      = ('attack_type', 'order')


@admin.register(ResponseAction)
class ResponseActionAdmin(admin.ModelAdmin):
    list_display  = ('action_type', 'target', 'status', 'alert', 'executed_at')
    list_filter   = ('status', 'action_type')
    search_fields = ('target', 'result_message')
    readonly_fields = ('created_at', 'executed_at')
