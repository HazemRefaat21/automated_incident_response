# ========================
# Scoring Weights
# ========================
ATTACK_TYPE_WEIGHT = 0.40
FREQUENCY_WEIGHT   = 0.30
IP_BEHAVIOR_WEIGHT = 0.30

# ========================
# Severity Thresholds
# ========================
SEVERITY_THRESHOLDS = {
    'critical': 80,
    'high':     60,
    'medium':   30,
    'low':       0,
}

# ========================
# Attack Base Scores (0-100)
# ========================
ATTACK_BASE_SCORES = {
    'command_injection': 90,
    'sql_injection':     85,
    'traversal':         75,
    'xss':               70,
    'dos':               70,
    'brute_force':       60,
    'web_attack':        50,
    'scanning':          35,
    'unknown':           20,
}

# ========================
# Frequency Scoring
# ========================
FREQUENCY_SCORES = [
    (1,   5,  5),
    (6,  20, 15),
    (21, 50, 25),
    (51, float('inf'), 30),
]

# ========================
# IP Behavior Scoring
# ========================
IP_SEEN_BEFORE_SCORE  = 15
IP_HIGH_THREAT_SCORE  = 10
IP_PREVIOUSLY_BLOCKED = 5
