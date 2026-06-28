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


class ManualTarget:
    """Lightweight stand-in for an Alert when a response is run manually.

    Mirrors the Alert attributes that handlers read, so any response can run
    without a real alert. It has no pk, so the logged ResponseAction has
    alert=None.
    """
    pk = None
    id = None
    attack_type = 'manual'
    severity = 'medium'
    rule_id = 0
    rule_level = 0
    agent_name = 'manual'
    raw_log: dict = {}

    def __init__(self, source_ip=None, note='Manual response'):
        from django.utils import timezone
        self.source_ip = source_ip
        self.rule_description = note
        self.timestamp = timezone.now()


# action_type (handler_key) -> handler key that undoes it
REVERSIBLE = {
    'block_ip': 'unblock_ip',
}


def _run_handler(handler_key, alert, params=None, trigger='auto', definition=None, context=None):
    """Run one handler against an alert (or ManualTarget) and log a ResponseAction."""
    from django.utils import timezone
    from responses.models import ResponseAction
    from response_worker.handlers import get_handler

    action = ResponseAction.objects.create(
        alert=alert if getattr(alert, 'pk', None) else None,
        response_definition=definition,
        action_type=handler_key,
        target='',
        status='pending',
        trigger=trigger,
    )

    handler = get_handler(handler_key)
    if handler is None:
        msg = f"No handler registered for key '{handler_key}'"
        logger.error("[RESPOND] %s", msg)
        action.status, action.result_message = 'failed', msg
        action.executed_at = timezone.now()
        action.save()
        return {'success': False, 'message': msg}

    ctx = context if context is not None else {'alert': alert, 'results': []}
    try:
        result = handler(alert, params or {}, ctx)
    except Exception as e:
        logger.error("[RESPOND] Handler '%s' raised: %s", handler_key, e, exc_info=True)
        result = {'success': False, 'message': str(e)}

    action.target         = str(result.get('target', getattr(alert, 'source_ip', None) or 'system'))[:100]
    action.status         = 'executed' if result.get('success') else 'failed'
    action.result_message = result.get('message', '')
    action.executed_at    = timezone.now()
    action.save()
    return result


def run_one(definition, alert, params_override=None, trigger='auto', context=None):
    """Run a single ResponseDefinition against an alert (or ManualTarget) and log it."""
    params = {**(definition.params or {}), **(params_override or {})}
    return _run_handler(definition.handler_key, alert, params, trigger, definition, context)


def run_response_now(definition, target=None, params_override=None):
    """Run any response manually, not tied to an alert. Returns the result dict."""
    return run_one(definition, ManualTarget(source_ip=target), params_override, trigger='manual')


def revoke_action(action):
    """Undo a previously executed response, if it is reversible. Returns a result dict."""
    reverse_key = REVERSIBLE.get(action.action_type)
    if not reverse_key:
        return {'success': False, 'message': f"'{action.action_type}' is not revocable"}
    if action.status == 'revoked':
        return {'success': False, 'message': 'Action already revoked'}

    target = ManualTarget(source_ip=action.target, note=f'Revoke of action #{action.id}')
    result = _run_handler(reverse_key, target, trigger='manual',
                          definition=action.response_definition)
    if result.get('success'):
        action.status = 'revoked'
        action.save(update_fields=['status'])
    return result


@task()
def execute_response(alert_id: int) -> list:
    """Execute the mapped response actions for an alert. Returns result dicts."""
    from alerts.models import Alert
    from responses.models import AttackResponseMap

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
        result = run_one(mapping.response, alert, mapping.params_override, 'auto', context)
        results.append(result)

    Alert.objects.filter(pk=alert.pk).update(status='resolved')
    return results


__all__ = ['execute_response', 'run_response_now', 'run_one', 'revoke_action', 'ManualTarget']
