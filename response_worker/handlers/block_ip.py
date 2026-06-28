"""Block-IP response handlers (thin adapters over actions.block_ip)."""
from response_worker.actions.block_ip import block_ip as _block_ip, unblock_ip as _unblock_ip
from response_worker.handlers import register_response


@register_response('block_ip', label='Block IP', description='Block the alert source IP via iptables')
def block_ip(alert, params, context):
    if not alert.source_ip:
        return {'success': False, 'message': 'No source IP on alert — nothing to block'}
    duration = int(params.get('duration_hours', 24))
    result = _block_ip(alert.source_ip, duration)
    result['target'] = alert.source_ip
    return result


@register_response('unblock_ip', label='Unblock IP', description='Remove an iptables block for the alert source IP')
def unblock_ip(alert, params, context):
    if not alert.source_ip:
        return {'success': False, 'message': 'No source IP on alert — nothing to unblock'}
    result = _unblock_ip(alert.source_ip)
    result['target'] = alert.source_ip
    return result
