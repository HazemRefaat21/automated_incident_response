from rest_framework import viewsets
from rest_framework.decorators import api_view
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
    filterset_fields = ['action_type', 'status']
    ordering_fields = ['created_at']


class ResponseDefinitionViewSet(viewsets.ModelViewSet):
    queryset = ResponseDefinition.objects.all()
    serializer_class = ResponseDefinitionSerializer
    filterset_fields = ['is_active', 'handler_key']
    ordering_fields = ['name', 'updated_at']


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
