"""
Access-log middleware.

Writes one line per HTTP request to the `django.access` logger in Apache
"combined" log format. A file handler (see settings.LOGGING) persists it to
logs/django_access.log, which the Wazuh agent tails. Wazuh's built-in web
decoders/rules then flag attacks (SQLi, XSS, traversal, ...) in the request
URLs and raise alerts — which flow back into this SIEM via the custom-django
integration.
"""
import logging

from django.utils import timezone

access_logger = logging.getLogger('django.access')


class AccessLogMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        try:
            access_logger.info(self._format(request, response))
        except Exception:  # never let logging break a request
            pass
        return response

    @staticmethod
    def _client_ip(request):
        xff = request.META.get('HTTP_X_FORWARDED_FOR', '')
        if xff:
            return xff.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR', '-')

    def _format(self, request, response):
        user = '-'
        u = getattr(request, 'user', None)
        if u is not None and u.is_authenticated:
            user = u.get_username()

        now   = timezone.localtime().strftime('%d/%b/%Y:%H:%M:%S %z')
        proto = request.META.get('SERVER_PROTOCOL', 'HTTP/1.1')
        size  = response.get('Content-Length') or (
            len(response.content) if hasattr(response, 'content') else 0
        )
        # get_full_path() keeps the query string — that's where GET-based
        # SQLi/XSS payloads live, which is what Wazuh's web rules match on.
        return (
            f'{self._client_ip(request)} - {user} [{now}] '
            f'"{request.method} {request.get_full_path()} {proto}" '
            f'{response.status_code} {size} '
            f'"{request.META.get("HTTP_REFERER", "-")}" '
            f'"{request.META.get("HTTP_USER_AGENT", "-")}"'
        )
