"""
Response Executor

Drives responses from the DB-configured attack→response map instead of the old
hardcoded policy. For an alert it:
  1. looks up active AttackResponseMap rows for the alert's attack_type
  2. for each, resolves the handler by its ResponseDefinition.handler_key
  3. runs the handler with merged params and logs a ResponseAction
"""
import sys
import logging

sys.path.insert(0, '/home/hazem/automated_incident_response')

from django.tasks import task

logger = logging.getLogger(__name__)


@task()
def execute_response(alert_id: int) -> list:
    """Execute the mapped response actions for an alert. Returns result dicts."""
    from django.utils import timezone
    from alerts.models import Alert
    from responses.models import AttackResponseMap, ResponseAction
    from response_worker.handlers import get_handler

    results = []

    try:
        alert = Alert.objects.get(id=alert_id)
    except Alert.DoesNotExist:
        logger.error("[RESPOND] Alert %s not found", alert_id)
        return results

    mappings = (
        AttackResponseMap.objects
        .filter(attack_type=alert.attack_type, is_active=True, response__is_active=True)
        .select_related('response')
        .order_by('order')
    )

    if not mappings:
        logger.info("[RESPOND] No active responses mapped for attack_type=%s (alert %s)",
                    alert.attack_type, alert_id)

    context = {'alert': alert, 'results': results}

    for mapping in mappings:
        definition = mapping.response
        handler = get_handler(definition.handler_key)

        action = ResponseAction.objects.create(
            alert=alert,
            response_definition=definition,
            action_type=definition.handler_key,
            target='',
            status='pending',
        )

        if handler is None:
            msg = f"No handler registered for key '{definition.handler_key}'"
            logger.error("[RESPOND] %s", msg)
            action.status, action.result_message = 'failed', msg
            action.executed_at = timezone.now()
            action.save()
            results.append({'success': False, 'message': msg})
            continue

        params = {**(definition.params or {}), **(mapping.params_override or {})}

        try:
            result = handler(alert, params, context)
        except Exception as e:
            logger.error("[RESPOND] Handler '%s' raised: %s", definition.handler_key, e, exc_info=True)
            result = {'success': False, 'message': str(e)}

        action.target         = str(result.get('target', alert.source_ip or 'system'))[:100]
        action.status         = 'executed' if result.get('success') else 'failed'
        action.result_message = result.get('message', '')
        action.executed_at    = timezone.now()
        action.save()
        results.append(result)

    Alert.objects.filter(pk=alert.pk).update(status='resolved')
    return results


__all__ = ['execute_response']
