from rest_framework import viewsets
from .models import ResponseAction
from .serializers import ResponseActionSerializer


class ResponseActionViewSet(viewsets.ModelViewSet):
    queryset = ResponseAction.objects.all()
    serializer_class = ResponseActionSerializer
    filterset_fields = ['action_type', 'status']
    ordering_fields = ['created_at']
