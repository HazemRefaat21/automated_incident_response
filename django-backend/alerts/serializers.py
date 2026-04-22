from rest_framework import serializers
from .models import Alert, IPProfile, DetectionRule


class AlertSerializer(serializers.ModelSerializer):
    class Meta:
        model = Alert
        fields = '__all__'
        read_only_fields = ['created_at', 'updated_at']


class IPProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = IPProfile
        fields = '__all__'


class DetectionRuleSerializer(serializers.ModelSerializer):
    class Meta:
        model = DetectionRule
        fields = '__all__'
