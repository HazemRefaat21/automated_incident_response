import json

from django import forms
from django.contrib import admin, messages
from django.template.response import TemplateResponse

from .models import ResponseDefinition, AttackResponseMap, ResponseAction


def _handler_choices():
    """Choices from the live handler registry; empty if worker import fails."""
    try:
        from response_worker.handlers import list_handler_keys
        return list_handler_keys()
    except Exception:
        return []


def _attack_type_choices():
    """Choices from the dashboard-managed AttackType rows."""
    try:
        from classification.models import AttackType
        return [(a.key, a.name) for a in AttackType.objects.all()]
    except Exception:
        return []


class AttackTypeChoiceMixin:
    """Render the `attack_type` field as a dropdown sourced from AttackType."""
    def formfield_for_dbfield(self, db_field, request, **kwargs):
        if db_field.name == 'attack_type':
            choices = _attack_type_choices()
            if choices:
                kwargs['widget'] = forms.Select(choices=choices)
        return super().formfield_for_dbfield(db_field, request, **kwargs)


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


class AttackResponseMapInline(AttackTypeChoiceMixin, admin.TabularInline):
    model = AttackResponseMap
    extra = 1
    fields = ('attack_type', 'order', 'params_override', 'is_active')


class RunNowForm(forms.Form):
    """Intermediate form shown when running a response manually from the admin."""
    target = forms.CharField(
        required=False,
        help_text="IP/host to act on (e.g. for Block IP). Leave blank for handlers "
                  "that need no target, like Kill Processes.",
    )
    params = forms.CharField(
        required=False, widget=forms.Textarea(attrs={'rows': 3}),
        help_text='Optional JSON params override, e.g. {"duration_hours": 1}',
    )


@admin.register(ResponseDefinition)
class ResponseDefinitionAdmin(admin.ModelAdmin):
    form = ResponseDefinitionForm
    inlines = [AttackResponseMapInline]
    list_display  = ('name', 'handler_key', 'is_active', 'updated_at')
    list_filter   = ('is_active', 'handler_key')
    search_fields = ('name', 'handler_key', 'description')
    list_editable = ('is_active',)
    actions = ['run_now']

    @admin.action(description='Run now (manual)')
    def run_now(self, request, queryset):
        from response_worker.executor import run_response_now

        if 'apply' in request.POST:
            form = RunNowForm(request.POST)
            if form.is_valid():
                target = form.cleaned_data['target'] or None
                raw = form.cleaned_data['params'].strip()
                try:
                    params = json.loads(raw) if raw else {}
                except json.JSONDecodeError as e:
                    self.message_user(request, f"Invalid JSON params: {e}", level=messages.ERROR)
                    return None

                for definition in queryset:
                    result = run_response_now(definition, target=target, params_override=params)
                    level = messages.SUCCESS if result.get('success') else messages.WARNING
                    self.message_user(request, f"{definition.name}: {result.get('message')}", level=level)
                return None

        form = RunNowForm()
        return TemplateResponse(request, 'admin/responses/run_now.html', {
            'title': 'Run response(s) manually',
            'definitions': queryset,
            'form': form,
            'action_checkbox_name': admin.helpers.ACTION_CHECKBOX_NAME,
            'queryset': queryset,
        })


@admin.register(AttackResponseMap)
class AttackResponseMapAdmin(AttackTypeChoiceMixin, admin.ModelAdmin):
    list_display  = ('attack_type', 'response', 'order', 'is_active')
    list_filter   = ('attack_type', 'is_active', 'response')
    list_editable = ('order', 'is_active')
    ordering      = ('attack_type', 'order')


@admin.register(ResponseAction)
class ResponseActionAdmin(admin.ModelAdmin):
    list_display  = ('action_type', 'target', 'status', 'trigger', 'alert', 'executed_at')
    list_filter   = ('status', 'trigger', 'action_type')
    search_fields = ('target', 'result_message')
    readonly_fields = ('created_at', 'executed_at')
    actions = ['revoke_actions']

    @admin.action(description='Revoke selected actions (undo)')
    def revoke_actions(self, request, queryset):
        from response_worker.executor import revoke_action
        done = 0
        for action_obj in queryset:
            result = revoke_action(action_obj)
            if result.get('success'):
                done += 1
            else:
                self.message_user(request, f"#{action_obj.id}: {result.get('message')}",
                                  level=messages.WARNING)
        if done:
            self.message_user(request, f"Revoked {done} action(s).", level=messages.SUCCESS)
