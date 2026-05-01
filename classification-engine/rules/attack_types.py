from classification_engine.config import ATTACK_BASE_SCORES

DESCRIPTION_TO_ATTACK_TYPE = [
    ('sql injection',      'sql_injection'),
    ('xss',                'xss'),
    ('directory traversal','traversal'),
    ('command injection',  'command_injection'),
    ('ssh brute force',    'brute_force'),
    ('ssh root',           'brute_force'),
    ('admin panel',        'scanning'),
    ('suspicious scanner', 'scanning'),
]


def get_attack_type_from_description(description: str) -> str:
    desc = description.lower()
    for keyword, attack_type in DESCRIPTION_TO_ATTACK_TYPE:
        if keyword in desc:
            return attack_type
    return 'unknown'


def get_attack_score(attack_type: str) -> float:
    return float(ATTACK_BASE_SCORES.get(attack_type, ATTACK_BASE_SCORES['unknown']))
