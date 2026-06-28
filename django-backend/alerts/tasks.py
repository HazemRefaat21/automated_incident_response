import logging
logger = logging.getLogger(__name__)


def process_incoming_alert(alert_data: dict):
    logger.info(f"Processing alert: {alert_data.get('id', 'unknown')}")
    try:
        from alerts.models import Alert
        from django.utils import timezone

        wazuh_id = alert_data.get('id')

        # تجنب duplicates
        if wazuh_id and Alert.objects.filter(wazuh_alert_id=wazuh_id).exists():
            return {'status': 'exists'}

        rule      = alert_data.get('rule', {})
        agent     = alert_data.get('agent', {})
        data      = alert_data.get('data', {})

        # Drop non-attack noise (PAM logins, sudo, etc.) — only ingest alerts
        # that match a known AttackType. Keywords are dashboard-managed.
        from alerts.hooks import classify_description, UNKNOWN_ATTACK
        attack_type, _ = classify_description(rule.get('description', ''))
        if attack_type == UNKNOWN_ATTACK[0]:
            logger.info(f"Skipping non-attack alert {wazuh_id}: {rule.get('description', '')!r}")
            return {'status': 'skipped', 'reason': 'not-attack-relevant'}

        # في الـ ingest view بدل source_ip من data
        source_ip = (
            data.get('srcip') or
            data.get('real_ip') or
            None
        )

        # استخدم .save() عشان الـ hook يشتغل
        alert = Alert(
            wazuh_alert_id   = wazuh_id,
            timestamp        = timezone.now(),
            rule_id          = rule.get('id', 0),
            rule_description = rule.get('description', ''),
            rule_level       = rule.get('level', 0),
            source_ip        = source_ip,
            agent_id         = agent.get('id', ''),
            agent_name       = agent.get('name', ''),
            raw_log          = alert_data,
            status           = 'new',
        )
        alert.save()  # ← بيشغّل الـ AFTER_CREATE hook

        return {'status': 'created', 'alert_id': alert.id}

    except Exception as e:
        logger.error(f"Error: {e}")
        raise
