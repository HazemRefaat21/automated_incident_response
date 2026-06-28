from django.db import models
from alerts.models import Alert


class ResponseDefinition(models.Model):
    """
    A reusable, dashboard-editable response in the catalog.

    `handler_key` points at a function registered with @register_response in
    response_worker/handlers/. The actual code lives there; this row just
    selects it and supplies default params.
    """
    name        = models.CharField(max_length=100, unique=True)
    handler_key = models.CharField(
        max_length=50,
        help_text="Key of a registered response handler (e.g. block_ip, kill_process, notify)",
    )
    description = models.TextField(blank=True)
    params      = models.JSONField(default=dict, blank=True,
                                   help_text="Default params passed to the handler, e.g. {\"duration_hours\": 24}")
    is_active   = models.BooleanField(default=True)

    created_at  = models.DateTimeField(auto_now_add=True)
    updated_at  = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['name']

    def __str__(self):
        return f"{self.name} ({self.handler_key})"


class AttackResponseMap(models.Model):
    """
    Maps an attack type to a response. Create multiple rows for one attack type
    to run several responses; `order` controls execution order.
    """
    attack_type     = models.CharField(max_length=50,
                                       help_text="AttackType.key this mapping responds to")
    response        = models.ForeignKey(ResponseDefinition, on_delete=models.CASCADE,
                                        related_name='mappings')
    order           = models.PositiveIntegerField(default=0,
                                                  help_text="Lower runs first")
    params_override = models.JSONField(default=dict, blank=True,
                                       help_text="Optional params merged over the response's defaults")
    is_active       = models.BooleanField(default=True)

    created_at      = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['attack_type', 'order']
        unique_together = ('attack_type', 'response')

    def __str__(self):
        return f"{self.attack_type} → {self.response.name}"


class ResponseAction(models.Model):
    """Log of an individual response that was executed for an alert."""
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('executed', 'Executed'),
        ('failed', 'Failed'),
        ('skipped', 'Skipped'),
        ('revoked', 'Revoked'),
    ]
    TRIGGER_CHOICES = [
        ('auto', 'Automatic'),
        ('manual', 'Manual'),
    ]

    # null for manual runs that aren't tied to a specific alert
    alert          = models.ForeignKey(Alert, on_delete=models.CASCADE, related_name='actions',
                                       null=True, blank=True)
    trigger        = models.CharField(max_length=10, choices=TRIGGER_CHOICES, default='auto')
    response_definition = models.ForeignKey(ResponseDefinition, on_delete=models.SET_NULL,
                                            null=True, blank=True, related_name='executions')
    action_type    = models.CharField(max_length=50, help_text="handler_key that was run")
    target         = models.CharField(max_length=100)
    status         = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    executed_at    = models.DateTimeField(null=True, blank=True)
    result_message = models.TextField(null=True, blank=True)
    created_at     = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.action_type} → {self.target} [{self.status}]"
