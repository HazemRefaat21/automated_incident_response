from classification_engine.config import FREQUENCY_SCORES


def get_frequency_score(events_count: int) -> float:
    for min_val, max_val, score in FREQUENCY_SCORES:
        if min_val <= events_count <= max_val:
            return float(score)
    return 0.0


def get_events_last_hour(ip_address: str) -> int:
    if not ip_address:
        return 0
    try:
        from alerts.models import Alert
        from django.utils import timezone
        from datetime import timedelta

        one_hour_ago = timezone.now() - timedelta(hours=1)
        return Alert.objects.filter(
            source_ip=ip_address,
            created_at__gte=one_hour_ago
        ).count()
    except Exception:
        return 0
