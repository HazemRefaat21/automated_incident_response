"""
Response Executor
بيشغّل الـ actions المناسبة بناءً على الـ policy
"""
import sys
import logging

sys.path.insert(0, '/home/hazem/automated_incident_response')

from response_worker.policies import get_policy
from response_worker.actions.block_ip import block_ip
from response_worker.actions.kill_process import find_suspicious_processes, kill_process
from response_worker.actions.notify import notify

logger = logging.getLogger(__name__)


def execute_response(alert) -> list:
    """
    Execute response actions for an alert.
    Returns list of ResponseAction results.
    """
    results = []

    try:
        from responses.models import ResponseAction
        from django.utils import timezone

        # جيب الـ IP threat score
        threat_score = 0
        if alert.source_ip:
            try:
                from alerts.models import IPProfile
                ip = IPProfile.objects.filter(ip_address=alert.source_ip).first()
                threat_score = ip.threat_score if ip else 0
            except Exception:
                pass

        # جيب الـ policy
        policy = get_policy(alert.severity, threat_score)

        logger.info(
            f"Executing response for Alert {alert.id} "
            f"[{alert.severity}] — policy: {policy}"
        )

        # ========================
        # Action 1: Block IP
        # ========================
        if policy['block_ip'] and alert.source_ip:
            action = ResponseAction.objects.create(
                alert=alert,
                action_type='block_ip',
                target=alert.source_ip,
                status='pending',
            )
            result = block_ip(alert.source_ip, policy['block_duration'])
            action.status         = 'executed' if result['success'] else 'failed'
            action.result_message = result['message']
            action.executed_at    = timezone.now()
            action.save()
            results.append(result)
            logger.info(f"Block IP result: {result}")

        # ========================
        # Action 2: Kill Process (critical only)
        # ========================
        if policy['kill_process']:
            suspicious = find_suspicious_processes()
            for proc in suspicious:
                action = ResponseAction.objects.create(
                    alert=alert,
                    action_type='kill_process',
                    target=str(proc['pid']),
                    status='pending',
                )
                result = kill_process(proc['pid'], reason=alert.rule_description)
                action.status         = 'executed' if result['success'] else 'failed'
                action.result_message = result['message']
                action.executed_at    = timezone.now()
                action.save()
                results.append(result)

        # ========================
        # Action 3: Notify
        # ========================
        if policy['notify']:
            action_summary = ', '.join([r['message'] for r in results if r.get('success')])
            result = notify(alert, action_summary)

            action = ResponseAction.objects.create(
                alert=alert,
                action_type='alert_only',
                target=alert.source_ip or 'system',
                status='executed',
                result_message=result['message'],
                executed_at=timezone.now(),
            )
            results.append(result)

        # Update alert status
        from alerts.models import Alert
        Alert.objects.filter(pk=alert.pk).update(status='resolved')

    except Exception as e:
        logger.error(f"Response execution error: {e}", exc_info=True)

    return results


__all__ = ['execute_response']
