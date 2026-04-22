from celery import shared_task
import logging

logger = logging.getLogger(__name__)


@shared_task
def process_incoming_alert(alert_data: dict):
    """Process incoming alert from Wazuh — Sprint 2: just save it."""
    logger.info(f"Processing alert: {alert_data.get('id', 'unknown')}")

    try:
        from alerts.models import Alert, IPProfile
        from django.utils import timezone

        rule  = alert_data.get('rule', {})
        agent = alert_data.get('agent', {})
        data  = alert_data.get('data', {})

        source_ip = data.get('srcip') or data.get('src_ip') or None

        alert, created = Alert.objects.get_or_create(
            wazuh_alert_id=alert_data.get('id'),
            defaults={
                'timestamp':        timezone.now(),
                'rule_id':          rule.get('id', 0),
                'rule_description': rule.get('description', ''),
                'rule_level':       rule.get('level', 0),
                'source_ip':        source_ip,
                'agent_id':         agent.get('id', ''),
                'agent_name':       agent.get('name', ''),
                'raw_log':          alert_data,
                'status':           'new',
            }
        )

        if created and source_ip:
            ip_profile, _ = IPProfile.objects.get_or_create(ip_address=source_ip)
            ip_profile.total_events += 1
            ip_profile.save()

        logger.info(f"Alert {'created' if created else 'exists'}: {alert.id}")
        return {'status': 'ok', 'alert_id': alert.id}

    except Exception as e:
        logger.error(f"Error: {e}")
        raise
