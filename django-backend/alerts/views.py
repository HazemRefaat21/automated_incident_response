from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from django.utils import timezone
from django.conf import settings
from .models import Alert, IPProfile, DetectionRule
from .serializers import AlertSerializer, IPProfileSerializer, DetectionRuleSerializer


class AlertViewSet(viewsets.ModelViewSet):
    queryset = Alert.objects.all()
    serializer_class = AlertSerializer
    filterset_fields = ['severity', 'attack_type', 'status', 'source_ip', 'agent_name']
    search_fields = ['rule_description', 'source_ip', 'agent_name']
    ordering_fields = ['timestamp', 'severity', 'rule_level']

    @action(detail=False, methods=['post'], permission_classes=[AllowAny])
    def ingest(self, request):
        """Wazuh integration endpoint."""
        secret = request.headers.get('X-Wazuh-Secret', '')
        if secret != settings.WAZUH_INTEGRATION_SECRET:
            return Response({'error': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)

        from .tasks import process_incoming_alert
        process_incoming_alert.delay(request.data)

        return Response({'status': 'received'}, status=status.HTTP_200_OK)


class IPProfileViewSet(viewsets.ModelViewSet):
    queryset = IPProfile.objects.all()
    serializer_class = IPProfileSerializer
    filterset_fields = ['is_blocked', 'country']
    ordering_fields = ['threat_score', 'total_events', 'last_seen']

    @action(detail=True, methods=['post'])
    def block(self, request, pk=None):
        ip = self.get_object()
        ip.is_blocked = True
        ip.blocked_at = timezone.now()
        ip.blocked_reason = request.data.get('reason', 'Manual block')
        ip.save()
        return Response({'status': 'blocked', 'ip': ip.ip_address})

    @action(detail=True, methods=['post'])
    def unblock(self, request, pk=None):
        ip = self.get_object()
        ip.is_blocked = False
        ip.blocked_at = None
        ip.blocked_reason = None
        ip.save()
        return Response({'status': 'unblocked', 'ip': ip.ip_address})


class DetectionRuleViewSet(viewsets.ModelViewSet):
    queryset = DetectionRule.objects.all()
    serializer_class = DetectionRuleSerializer
