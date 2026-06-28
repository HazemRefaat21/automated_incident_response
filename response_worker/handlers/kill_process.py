"""Kill-process response handler (adapter over actions.kill_process)."""
from response_worker.actions.kill_process import find_suspicious_processes, kill_process as _kill_process
from response_worker.handlers import register_response


@register_response(
    'kill_process',
    label='Kill Suspicious Processes',
    description='Find and terminate suspicious processes (e.g. high CPU)',
)
def kill_process(alert, params, context):
    """Terminate suspicious processes. Returns one aggregated result."""
    suspicious = find_suspicious_processes()
    if not suspicious:
        return {'success': True, 'message': 'No suspicious processes found', 'target': 'system'}

    killed, failed = [], []
    for proc in suspicious:
        result = _kill_process(proc['pid'], reason=alert.rule_description)
        (killed if result['success'] else failed).append(str(proc['pid']))

    return {
        'success': not failed,
        'message': f"killed: {killed or '-'}, failed: {failed or '-'}",
        'target': ','.join(killed) or 'system',
    }
