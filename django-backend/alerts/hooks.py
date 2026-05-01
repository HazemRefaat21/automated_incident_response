import sys
import logging

sys.path.insert(0, '/home/hazem/automated_incident_response')

from django_lifecycle import hook, AFTER_CREATE, AFTER_UPDATE

logger = logging.getLogger(__name__)

DESCRIPTION_TO_ATTACK_TYPE = [
    ('sql injection',      'sql_injection'),
    ('xss',                'xss'),
    ('directory traversal','traversal'),
    ('command injection',  'command_injection'),
    ('ssh brute force',    'brute_force'),
    ('ssh root',           'brute_force'),
    ('admin panel',        'scanning'),
    ('suspicious scanner', 'scanning'),
    ('scanning',           'scanning'),
]

ATTACK_SCORES = {
    'command_injection': 90,
    'sql_injection':     85,
    'traversal':         75,
    'xss':               70,
    'dos':               70,
    'brute_force':       60,
    'scanning':          35,
    'unknown':           20,
}

SEVERITY_THRESHOLDS = {
    'critical': 80,
    'high':     60,
    'medium':   30,
}


def get_attack_type(description: str) -> str:
    desc = description.lower()
    for keyword, attack_type in DESCRIPTION_TO_ATTACK_TYPE:
        if keyword in desc:
            return attack_type
    return 'unknown'


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
            attack_type = get_attack_type(self.rule_description or '')
            base_score  = ATTACK_SCORES.get(attack_type, ATTACK_SCORES['unknown'])

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
