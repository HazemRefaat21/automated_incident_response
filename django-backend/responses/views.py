from rest_framework import viewsets, status
from rest_framework.decorators import api_view, action
from rest_framework.response import Response

from .models import ResponseAction, ResponseDefinition, AttackResponseMap
from .serializers import (
    ResponseActionSerializer,
    ResponseDefinitionSerializer,
    AttackResponseMapSerializer,
)


class ResponseActionViewSet(viewsets.ModelViewSet):
    queryset = ResponseAction.objects.all()
    serializer_class = ResponseActionSerializer
    filterset_fields = ['action_type', 'status', 'trigger']
    ordering_fields = ['created_at']

    @action(detail=True, methods=['post'])
    def revoke(self, request, pk=None):
        """Undo this action (e.g. unblock an IP), even if it ran automatically."""
        action_obj = self.get_object()
        from response_worker.executor import revoke_action
        result = revoke_action(action_obj)
        code = status.HTTP_200_OK if result.get('success') else status.HTTP_400_BAD_REQUEST
        return Response(result, status=code)


class ResponseDefinitionViewSet(viewsets.ModelViewSet):
    queryset = ResponseDefinition.objects.all()
    serializer_class = ResponseDefinitionSerializer
    filterset_fields = ['is_active', 'handler_key']
    ordering_fields = ['name', 'updated_at']

    @action(detail=True, methods=['post'])
    def run(self, request, pk=None):
        """Run this response manually, not tied to an alert.

        Body: {"target": "1.2.3.4", "params": {"duration_hours": 1}}
        Both optional (e.g. kill_process needs no target).
        """
        definition = self.get_object()
        target = request.data.get('target')
        params = request.data.get('params') or {}

        from response_worker.executor import run_response_now
        result = run_response_now(definition, target=target, params_override=params)

        code = status.HTTP_200_OK if result.get('success') else status.HTTP_400_BAD_REQUEST
        return Response(result, status=code)


class AttackResponseMapViewSet(viewsets.ModelViewSet):
    queryset = AttackResponseMap.objects.select_related('response').all()
    serializer_class = AttackResponseMapSerializer
    filterset_fields = ['attack_type', 'is_active', 'response']
    ordering_fields = ['attack_type', 'order']


@api_view(['GET'])
def available_handlers(request):
    """List the response handlers registered in the worker (for dashboard UI)."""
    try:
        from response_worker.handlers import RESPONSE_HANDLERS
        data = [
            {'key': key, 'label': entry['label'], 'description': entry['description']}
            for key, entry in sorted(RESPONSE_HANDLERS.items())
        ]
    except Exception as e:
        return Response({'error': str(e)}, status=500)
    return Response(data)
