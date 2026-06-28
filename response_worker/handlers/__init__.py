"""
Response handler registry.

This is where the *code* for each response lives. Every handler is a plain
Python function registered under a string key with @register_response('key').
A `ResponseDefinition` row in the DB stores that key (+ params), so the
dashboard/admin controls *which* responses run and *with what params*, while
the actual executable code stays version-controlled here.

Handler contract:
    def handler(alert, params: dict, context: dict) -> dict:
        return {'success': bool, 'message': str, 'target': str (optional)}

    - alert:   the alerts.models.Alert instance that triggered the response
    - params:  merged params (ResponseDefinition.params + per-mapping override)
    - context: {'alert': alert, 'results': [<previous handler result dicts>]}
               lets later handlers (e.g. notify) see what already ran.
"""
import importlib
import logging

logger = logging.getLogger(__name__)

# key -> {'func': callable, 'label': str, 'description': str}
RESPONSE_HANDLERS = {}


def register_response(key, label=None, description=''):
    """Decorator that registers a function as a response handler."""
    def decorator(func):
        if key in RESPONSE_HANDLERS:
            logger.warning("Response handler '%s' is being overwritten", key)
        RESPONSE_HANDLERS[key] = {
            'func': func,
            'label': label or key,
            'description': description or (func.__doc__ or '').strip(),
        }
        return func
    return decorator


def get_handler(key):
    """Return the callable registered under `key`, or None."""
    entry = RESPONSE_HANDLERS.get(key)
    return entry['func'] if entry else None


def list_handler_keys():
    """Return [(key, label), ...] for use as form/admin choices."""
    return [(key, entry['label']) for key, entry in sorted(RESPONSE_HANDLERS.items())]


# Import handler modules so their @register_response decorators run.
# Add new handler modules here.
for _module in ('block_ip', 'kill_process', 'notify'):
    importlib.import_module(f'{__name__}.{_module}')
