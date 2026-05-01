import sys
import logging

sys.path.insert(0, '/home/hazem/automated_incident_response')

from django_lifecycle import hook, AFTER_CREATE

logger = logging.getLogger(__name__)

DESCRIPTION_TO_ATTACK_TYPE = [
    ('sql injection',     'sql_injection'),
    ('xss',               'xss'),
    ('traversal',         'traversal'),
    ('command injection', 'command_injection'),
    ('brute force',       'brute_force'),
    ('flood',             'dos'),
    ('admin panel',       'scanning'),
    ('scanner',           'scanning'),
    ('scanning',          'scanning'),
    ('ssh',               'brute_force'),
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
            # 1. حدد الـ attack type من الـ description
            attack_type = get_attack_type(self.rule_description or '')

            # 2. جيب الـ base score
            base_score = ATTACK_SCORES.get(attack_type, ATTACK_SCORES['unknown'])

            # 3. bonus من الـ rule level
            level = self.rule_level or 0
            if level >= 12:   bonus = 15
            elif level >= 8:  bonus = 10
            elif level >= 4:  bonus = 5
            else:             bonus = 0

            score = min(base_score + bonus, 100)

            # 4. حدد الـ severity
            severity = get_severity(score)

            # 5. update الـ alert
            type(self).objects.filter(pk=self.pk).update(
                attack_type=attack_type,
                severity=severity,
                status='processing',
            )

            logger.info(f"Alert {self.pk}: {attack_type} → {severity} (score={score})")

        except Exception as e:
            logger.error(f"Hook error: {e}", exc_info=True)
