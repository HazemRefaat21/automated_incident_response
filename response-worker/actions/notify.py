"""
Send notifications — in-app logging + optional webhook
"""
import logging
import requests
from django.utils import timezone

logger = logging.getLogger(__name__)

# Webhook URL — اتركه None لو مش عايز تبعت
WEBHOOK_URL = None  # "https://hooks.slack.com/services/..."


def build_message(alert, action_taken: str = '') -> str:
    """Build notification message."""
    severity_emoji = {
        'critical': '🔴',
        'high':     '🟠',
        'medium':   '��',
        'low':      '🟢',
    }
    emoji = severity_emoji.get(alert.severity, '⚪')

    msg = (
        f"{emoji} [{alert.severity.upper()}] {alert.rule_description}\n"
        f"IP: {alert.source_ip or 'unknown'}\n"
        f"Attack: {alert.attack_type}\n"
        f"Rule: {alert.rule_id} (level {alert.rule_level})\n"
        f"Agent: {alert.agent_name}\n"
        f"Time: {alert.timestamp}\n"
    )

    if action_taken:
        msg += f"Action: {action_taken}\n"

    return msg


def notify(alert, action_taken: str = '') -> dict:
    """Send notification for an alert."""
    message = build_message(alert, action_taken)

    # 1. Log دايماً
    if alert.severity in ('critical', 'high'):
        logger.critical(f"SECURITY ALERT: {message}")
    elif alert.severity == 'medium':
        logger.warning(f"SECURITY WARNING: {message}")
    else:
        logger.info(f"SECURITY NOTICE: {message}")

    # 2. Webhook (اختياري)
    if WEBHOOK_URL:
        try:
            requests.post(
                WEBHOOK_URL,
                json={'text': message},
                timeout=5
            )
        except Exception as e:
            logger.error(f"Webhook error: {e}")

    return {'success': True, 'message': 'Notification sent'}
