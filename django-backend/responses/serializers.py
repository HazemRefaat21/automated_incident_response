from rest_framework import serializers
from .models import ResponseAction, ResponseDefinition, AttackResponseMap


class ResponseActionSerializer(serializers.ModelSerializer):
    class Meta:
        model = ResponseAction
        fields = '__all__'


class ResponseDefinitionSerializer(serializers.ModelSerializer):
    class Meta:
        model = ResponseDefinition
        fields = '__all__'


class AttackResponseMapSerializer(serializers.ModelSerializer):
    response_name = serializers.CharField(source='response.name', read_only=True)

    class Meta:
        model = AttackResponseMap
        fields = '__all__'
