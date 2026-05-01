from classification_engine.config import (
    IP_SEEN_BEFORE_SCORE,
    IP_HIGH_THREAT_SCORE,
    IP_PREVIOUSLY_BLOCKED,
)


def get_ip_behavior_score(ip_address: str) -> float:
    if not ip_address:
        return 0.0

    score = 0.0
    try:
        from alerts.models import IPProfile

        ip = IPProfile.objects.filter(ip_address=ip_address).first()
        if ip:
            score += IP_SEEN_BEFORE_SCORE
            if ip.threat_score > 50:
                score += IP_HIGH_THREAT_SCORE
            if ip.is_blocked or ip.blocked_at:
                score += IP_PREVIOUSLY_BLOCKED
    except Exception:
        pass

    return min(score, 30.0)


def update_ip_profile(ip_address: str, alert_score: float):
    if not ip_address:
        return
    try:
        from alerts.models import IPProfile
        from django.utils import timezone

        ip, created = IPProfile.objects.get_or_create(ip_address=ip_address)

        if created or ip.threat_score == 0:
            ip.threat_score = int(alert_score)
        else:
            # Exponential Moving Average
            alpha = 0.3
            ip.threat_score = min(
                int(alpha * alert_score + (1 - alpha) * ip.threat_score),
                100
            )

        ip.total_events += 1
        ip.last_seen = timezone.now()
        ip.save()
    except Exception as e:
        import logging
        logging.getLogger(__name__).error(f"IP profile update error: {e}")
