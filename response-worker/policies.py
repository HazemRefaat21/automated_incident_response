"""
Response Policies
بيحدد إيه الـ actions اللي هتتنفذ بناءً على الـ severity والـ attack_type
"""

# كل policy عبارة عن list من actions
POLICIES = {
    'critical': {
        'block_ip':      True,
        'block_duration': 24,    # hours
        'kill_process':  True,
        'notify':        True,
    },
    'high': {
        'block_ip':      True,
        'block_duration': 24,
        'kill_process':  False,
        'notify':        True,
    },
    'medium': {
        'block_ip':      False,  # بلوك بس لو threat_score > 70
        'block_duration': 1,
        'kill_process':  False,
        'notify':        True,
    },
    'low': {
        'block_ip':      False,
        'kill_process':  False,
        'notify':        False,  # بس logging
    },
}


def get_policy(severity: str, threat_score: int = 0) -> dict:
    """Get response policy for severity."""
    policy = POLICIES.get(severity, POLICIES['low']).copy()

    # Medium مع threat_score عالي → block
    if severity == 'medium' and threat_score > 70:
        policy['block_ip'] = True

    return policy
