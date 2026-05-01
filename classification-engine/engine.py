import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class ClassificationResult:
    severity:    str
    score:       float
    attack_type: str


class ClassificationEngine:

    def classify(self, alert) -> ClassificationResult:
        from classification_engine.config import (
            ATTACK_TYPE_WEIGHT,
            FREQUENCY_WEIGHT,
            IP_BEHAVIOR_WEIGHT,
            SEVERITY_THRESHOLDS,
        )
        from classification_engine.rules.attack_types import (
            get_attack_type_from_description,
            get_attack_score,
        )
        from classification_engine.rules.frequency import (
            get_frequency_score,
            get_events_last_hour,
        )
        from classification_engine.rules.ip_behavior import (
            get_ip_behavior_score,
            update_ip_profile,
        )

        try:
            # 1. Attack Type Score
            raw_log = alert.raw_log or {}
            groups  = raw_log.get('rule', {}).get('groups', [])
            if isinstance(groups, str):
                groups = [g.strip() for g in groups.split(',')]

            attack_type  = get_attack_type_from_description(alert.rule_description or "")
            attack_score = get_attack_score(attack_type)

            # Bonus من الـ rule level
            attack_score = min(attack_score + self._level_bonus(alert.rule_level or 0), 100)

            # 2. Frequency Score
            events       = get_events_last_hour(alert.source_ip)
            freq_score   = get_frequency_score(events)

            # 3. IP Behavior Score
            ip_score     = get_ip_behavior_score(alert.source_ip)

            # Final Score
            final_score  = round(
                attack_score * ATTACK_TYPE_WEIGHT +
                freq_score   * FREQUENCY_WEIGHT   +
                ip_score     * IP_BEHAVIOR_WEIGHT,
                2
            )
            final_score  = min(final_score, 100)

            # Severity
            severity = self._get_severity(final_score, SEVERITY_THRESHOLDS)

            # Update IP Profile
            update_ip_profile(alert.source_ip, final_score)

            logger.info(f"Alert {alert.id}: {severity} (score={final_score}, type={attack_type})")

            return ClassificationResult(
                severity=severity,
                score=final_score,
                attack_type=attack_type,
            )

        except Exception as e:
            logger.error(f"Classification error: {e}")
            return ClassificationResult(
                severity='low',
                score=0.0,
                attack_type='unknown',
            )

    def _get_severity(self, score: float, thresholds: dict) -> str:
        if score >= thresholds['critical']:
            return 'critical'
        elif score >= thresholds['high']:
            return 'high'
        elif score >= thresholds['medium']:
            return 'medium'
        return 'low'

    def _level_bonus(self, level: int) -> float:
        if level >= 12: return 15.0
        if level >= 8:  return 10.0
        if level >= 4:  return 5.0
        return 0.0
