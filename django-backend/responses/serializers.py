from rest_framework import serializers
from .models import ResponseAction


class ResponseActionSerializer(serializers.ModelSerializer):
    class Meta:
        model = ResponseAction
        fields = '__all__'
