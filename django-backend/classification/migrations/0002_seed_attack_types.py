from django.db import migrations


# key: (name, keywords, base_score, priority)
# Seeded from the previously hardcoded tables in alerts/hooks.py so classification
# behaviour is unchanged. Edit these from the admin from now on.
ATTACK_TYPES = {
    'command_injection': ('Command Injection', ['command injection'],                          90, 10),
    'sql_injection':     ('SQL Injection',     ['sql injection'],                               85, 20),
    'traversal':         ('Directory Traversal', ['directory traversal'],                       75, 30),
    'xss':               ('XSS',               ['xss'],                                          70, 40),
    'dos':               ('DoS',               [],                                               70, 50),
    'brute_force':       ('Brute Force',       ['ssh brute force', 'ssh root'],                  60, 60),
    'web_attack':        ('Web Attack',        [],                                               50, 70),
    'scanning':          ('Scanning',          ['admin panel', 'suspicious scanner', 'scanning'], 35, 80),
    'malware':           ('Malware',           [],                                               80, 90),
    'unknown':           ('Unknown',           [],                                               20, 100),
}


def seed(apps, schema_editor):
    AttackType = apps.get_model('classification', 'AttackType')
    for key, (name, keywords, score, priority) in ATTACK_TYPES.items():
        AttackType.objects.get_or_create(
            key=key,
            defaults={'name': name, 'keywords': keywords,
                      'base_score': score, 'priority': priority},
        )


def unseed(apps, schema_editor):
    AttackType = apps.get_model('classification', 'AttackType')
    AttackType.objects.filter(key__in=ATTACK_TYPES.keys()).delete()


class Migration(migrations.Migration):

    dependencies = [
        ('classification', '0001_initial'),
    ]

    operations = [
        migrations.RunPython(seed, unseed),
    ]
