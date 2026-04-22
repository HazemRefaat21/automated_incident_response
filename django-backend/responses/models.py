from django.db import models
from alerts.models import Alert


class ResponseAction(models.Model):
    ACTION_CHOICES = [
        ('block_ip', 'Block IP'),
        ('kill_process', 'Kill Process'),
        ('alert_only', 'Alert Only'),
    ]
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('executed', 'Executed'),
        ('failed', 'Failed'),
    ]

    alert          = models.ForeignKey(Alert, on_delete=models.CASCADE, related_name='actions')
    action_type    = models.CharField(max_length=20, choices=ACTION_CHOICES)
    target         = models.CharField(max_length=100)
    status         = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    executed_at    = models.DateTimeField(null=True, blank=True)
    result_message = models.TextField(null=True, blank=True)
    created_at     = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.action_type} → {self.target} [{self.status}]"
