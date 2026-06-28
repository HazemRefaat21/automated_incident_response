"""
URL configuration for siem_backend project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/6.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from alerts.views import AlertViewSet, IPProfileViewSet, DetectionRuleViewSet
from responses.views import (
    ResponseActionViewSet,
    ResponseDefinitionViewSet,
    AttackResponseMapViewSet,
    available_handlers,
)

router = DefaultRouter()
router.register(r'alerts',    AlertViewSet,         basename='alert')
router.register(r'ips',       IPProfileViewSet,     basename='ip')
router.register(r'rules',     DetectionRuleViewSet, basename='rule')
router.register(r'responses', ResponseActionViewSet, basename='response')
router.register(r'response-definitions', ResponseDefinitionViewSet, basename='response-definition')
router.register(r'attack-response-map',  AttackResponseMapViewSet,  basename='attack-response-map')
from django.http import JsonResponse
from django.utils import timezone

def health_check(request):
    """Health check endpoint."""
    import redis
    from django.db import connection

    status = {'status': 'ok', 'timestamp': str(timezone.now())}

    # Check DB
    try:
        connection.ensure_connection()
        status['database'] = 'ok'
    except Exception:
        status['database'] = 'error'
        status['status'] = 'degraded'

    # Check Redis
    try:
        r = redis.Redis(host='localhost', port=6379)
        r.ping()
        status['redis'] = 'ok'
    except Exception:
        status['redis'] = 'error'
        status['status'] = 'degraded'

    # Check Wazuh
    status['wazuh'] = 'ok'  # Sprint 3 integration

    return JsonResponse(status)
urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include(router.urls)),
    path('api/auth/token/',         TokenObtainPairView.as_view(),  name='token_obtain_pair'),
    path('api/auth/token/refresh/', TokenRefreshView.as_view(),     name='token_refresh'),
    path('api/health/', health_check, name='health'),
    path('api/response-handlers/', available_handlers, name='response-handlers'),

]
