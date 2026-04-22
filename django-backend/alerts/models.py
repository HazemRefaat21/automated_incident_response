from django.db import models

# Create your models here.
from django.db import models


class Alert(models.Model):
    SEVERITY_CHOICES = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ]
    STATUS_CHOICES = [
        ('new', 'New'),
        ('processing', 'Processing'),
        ('resolved', 'Resolved'),
    ]
    ATTACK_TYPE_CHOICES = [
        ('web_attack', 'Web Attack'),
        ('brute_force', 'Brute Force'),
        ('sql_injection', 'SQL Injection'),
        ('xss', 'XSS'),
        ('traversal', 'Directory Traversal'),
        ('dos', 'DoS'),
        ('malware', 'Malware'),
        ('unknown', 'Unknown'),
    ]

    wazuh_alert_id   = models.CharField(max_length=100, unique=True, null=True, blank=True)
    timestamp        = models.DateTimeField()
    rule_id          = models.IntegerField()
    rule_description = models.TextField()
    rule_level       = models.IntegerField()

    source_ip        = models.GenericIPAddressField(null=True, blank=True)
    destination_ip   = models.GenericIPAddressField(null=True, blank=True)

    agent_id         = models.CharField(max_length=20, null=True, blank=True)
    agent_name       = models.CharField(max_length=100, null=True, blank=True)

    attack_type      = models.CharField(max_length=50, choices=ATTACK_TYPE_CHOICES, default='unknown')
    severity         = models.CharField(max_length=10, choices=SEVERITY_CHOICES, default='low')

    raw_log          = models.JSONField(default=dict)
    status           = models.CharField(max_length=20, choices=STATUS_CHOICES, default='new')

    created_at       = models.DateTimeField(auto_now_add=True)
    updated_at       = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['severity']),
            models.Index(fields=['source_ip']),
            models.Index(fields=['attack_type']),
            models.Index(fields=['timestamp']),
            models.Index(fields=['status']),
        ]

    def __str__(self):
        return f"[{self.severity.upper()}] {self.rule_description} — {self.source_ip}"


class IPProfile(models.Model):
    ip_address       = models.GenericIPAddressField(unique=True)
    first_seen       = models.DateTimeField(auto_now_add=True)
    last_seen        = models.DateTimeField(auto_now=True)

    total_events     = models.IntegerField(default=0)
    events_last_hour = models.IntegerField(default=0)
    events_last_24h  = models.IntegerField(default=0)

    is_blocked       = models.BooleanField(default=False)
    blocked_at       = models.DateTimeField(null=True, blank=True)
    blocked_reason   = models.TextField(null=True, blank=True)

    threat_score     = models.IntegerField(default=0)

    country          = models.CharField(max_length=100, null=True, blank=True)
    asn              = models.CharField(max_length=100, null=True, blank=True)

    class Meta:
        ordering = ['-threat_score']

    def __str__(self):
        status = "BLOCKED" if self.is_blocked else "OK"
        return f"{self.ip_address} [{status}] score={self.threat_score}"


class DetectionRule(models.Model):
    SEVERITY_CHOICES = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ]

    rule_id          = models.IntegerField(unique=True)
    name             = models.CharField(max_length=200)
    description      = models.TextField()
    severity_default = models.CharField(max_length=10, choices=SEVERITY_CHOICES, default='low')
    is_custom        = models.BooleanField(default=False)
    is_active        = models.BooleanField(default=True)

    def __str__(self):
        return f"Rule {self.rule_id}: {self.name}"
