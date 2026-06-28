import sys
import logging

sys.path.insert(0, '/home/hazem/automated_incident_response')

from django_lifecycle import hook, AFTER_CREATE, AFTER_UPDATE

logger = logging.getLogger(__name__)

SEVERITY_THRESHOLDS = {
    'critical': 80,
    'high':     60,
    'medium':   30,
}

# Fallback when no AttackType row matches the description.
UNKNOWN_ATTACK = ('unknown', 20)


def classify_description(description: str):
    """Match the Wazuh rule description against dashboard-managed AttackType rows.

    Returns (attack_type_key, base_score). First active row (by priority) whose
    keyword is a substring of the description wins; falls back to 'unknown'.
    """
    from classification.models import AttackType

    desc = (description or '').lower()
    for at in AttackType.objects.filter(is_active=True).order_by('priority', 'key'):
        for keyword in (at.keywords or []):
            if keyword and keyword.lower() in desc:
                return at.key, at.base_score
    return UNKNOWN_ATTACK


def get_severity(score: float) -> str:
    if score >= SEVERITY_THRESHOLDS['critical']:
        return 'critical'
    elif score >= SEVERITY_THRESHOLDS['high']:
        return 'high'
    elif score >= SEVERITY_THRESHOLDS['medium']:
        return 'medium'
    return 'low'


class AlertHooksMixin:

    @hook(AFTER_CREATE)
    def on_create_classify(self):
        try:
            attack_type, base_score = classify_description(self.rule_description or '')

            level = self.rule_level or 0
            if level >= 12:   bonus = 15
            elif level >= 8:  bonus = 10
            elif level >= 4:  bonus = 5
            else:             bonus = 0

            score    = min(base_score + bonus, 100)
            severity = get_severity(score)

            # استخدم .save() عشان يشغّل الـ AFTER_UPDATE hook
            self.attack_type = attack_type
            self.severity    = severity
            self.status      = 'processing'
            self.save()

            logger.info(f"[CLASSIFY] Alert {self.pk}: {attack_type} → {severity} (score={score})")

        except Exception as e:
            logger.error(f"[CLASSIFY] Hook error: {e}", exc_info=True)

    @hook(AFTER_UPDATE, when='status', has_changed=True, is_now='processing')
    def on_processing_respond(self):
        try:
            from response_worker.executor import execute_response
            results = execute_response.enqueue(self.id)
        except Exception as e:
            logger.error(f"[RESPOND] Hook error: {e}", exc_info=True)
