"""Notify response handler (adapter over actions.notify)."""
from response_worker.actions.notify import notify as _notify
from response_worker.handlers import register_response


@register_response('notify', label='Send Notification', description='Log + optional webhook notification for the alert')
def notify(alert, params, context):
    # Summarise the responses that already ran successfully in this execution.
    prior = context.get('results', [])
    summary = ', '.join(r['message'] for r in prior if r.get('success'))
    result = _notify(alert, summary)
    result['target'] = alert.source_ip or 'system'
    return result
