from django.db import models


class AttackType(models.Model):
    """
    Dashboard-managed attack type. Adding a new attack no longer needs a code
    change — create a row here with the keywords to match against Wazuh's
    rule.description and a base score. The classifier (alerts/hooks.py) reads
    these rows at runtime.
    """
    key        = models.SlugField(
        max_length=50, unique=True,
        help_text="Stored on alerts and used in response mappings, e.g. sql_injection",
    )
    name       = models.CharField(max_length=100)
    keywords   = models.JSONField(
        default=list, blank=True,
        help_text='Lowercase substrings matched against the Wazuh rule description, '
                  'e.g. ["sql injection", "sqli"]. First matching attack type wins.',
    )
    base_score = models.PositiveIntegerField(
        default=20,
        help_text="0-100 base score before the Wazuh rule-level bonus is added",
    )
    priority   = models.IntegerField(
        default=100,
        help_text="Lower is checked first when matching keywords (specific before generic)",
    )
    is_active  = models.BooleanField(default=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['priority', 'key']

    def __str__(self):
        return f"{self.name} ({self.key})"
