"""
Thin Elasticsearch layer for shipping SIEM data into Kibana.

Indexes:
  - django-alerts    : one doc per alerts.Alert
  - django-responses : one doc per responses.ResponseAction

Everything here is best-effort: if Elasticsearch is down or misconfigured, the
helpers log and return instead of raising, so they can never break a DB write.
"""
import logging
from functools import lru_cache

from django.conf import settings

logger = logging.getLogger(__name__)

ALERTS_INDEX = "django-alerts"
RESPONSES_INDEX = "django-responses"

# Explicit mappings so Kibana gets proper field types (dates, ip, keyword).
INDEX_MAPPINGS = {
    ALERTS_INDEX: {
        "mappings": {
            "properties": {
                "id": {"type": "integer"},
                "wazuh_alert_id": {"type": "keyword"},
                "timestamp": {"type": "date"},
                "rule_id": {"type": "integer"},
                "rule_description": {"type": "text",
                                     "fields": {"keyword": {"type": "keyword", "ignore_above": 512}}},
                "rule_level": {"type": "integer"},
                "source_ip": {"type": "ip"},
                "destination_ip": {"type": "ip"},
                "agent_id": {"type": "keyword"},
                "agent_name": {"type": "keyword"},
                "attack_type": {"type": "keyword"},
                "severity": {"type": "keyword"},
                "status": {"type": "keyword"},
                "created_at": {"type": "date"},
                "updated_at": {"type": "date"},
            }
        }
    },
    RESPONSES_INDEX: {
        "mappings": {
            "properties": {
                "id": {"type": "integer"},
                "alert_id": {"type": "integer"},
                "trigger": {"type": "keyword"},
                "action_type": {"type": "keyword"},
                "target": {"type": "keyword"},
                "status": {"type": "keyword"},
                "result_message": {"type": "text"},
                "executed_at": {"type": "date"},
                "created_at": {"type": "date"},
                # denormalized from the parent alert for easy dashboards
                "attack_type": {"type": "keyword"},
                "severity": {"type": "keyword"},
                "source_ip": {"type": "ip"},
            }
        }
    },
}


@lru_cache(maxsize=1)
def get_client():
    """Lazily build a cached Elasticsearch client, or None if unavailable."""
    if not getattr(settings, "ES_ENABLED", True):
        return None
    try:
        from elasticsearch import Elasticsearch
    except ImportError:
        logger.warning("elasticsearch package not installed; ES indexing disabled.")
        return None
    try:
        return Elasticsearch(
            settings.ES_URL,
            request_timeout=getattr(settings, "ES_TIMEOUT", 5),
            max_retries=1,
            retry_on_timeout=False,
        )
    except Exception as e:  # noqa: BLE001
        logger.warning("Could not build Elasticsearch client: %s", e)
        return None


def ensure_indices():
    """Create the two indices with mappings if they don't exist."""
    es = get_client()
    if es is None:
        return False
    for index, body in INDEX_MAPPINGS.items():
        try:
            if not es.indices.exists(index=index):
                es.indices.create(index=index, body=body)
                logger.info("Created Elasticsearch index '%s'", index)
        except Exception as e:  # noqa: BLE001
            logger.warning("ensure_indices failed for '%s': %s", index, e)
            return False
    return True


def _index_doc(index, doc_id, doc):
    es = get_client()
    if es is None:
        return
    try:
        es.index(index=index, id=str(doc_id), document=doc)
    except Exception as e:  # noqa: BLE001
        # Never let a dashboard write break the application.
        logger.warning("ES index into '%s' (id=%s) failed: %s", index, doc_id, e)


def _isoformat(dt):
    return dt.isoformat() if dt else None


def alert_to_doc(alert):
    return {
        "id": alert.id,
        "wazuh_alert_id": alert.wazuh_alert_id,
        "timestamp": _isoformat(alert.timestamp),
        "rule_id": alert.rule_id,
        "rule_description": alert.rule_description,
        "rule_level": alert.rule_level,
        "source_ip": alert.source_ip,
        "destination_ip": alert.destination_ip,
        "agent_id": alert.agent_id,
        "agent_name": alert.agent_name,
        "attack_type": alert.attack_type,
        "severity": alert.severity,
        "status": alert.status,
        "created_at": _isoformat(alert.created_at),
        "updated_at": _isoformat(alert.updated_at),
    }


def response_to_doc(action):
    alert = action.alert
    return {
        "id": action.id,
        "alert_id": action.alert_id,
        "trigger": action.trigger,
        "action_type": action.action_type,
        "target": action.target,
        "status": action.status,
        "result_message": action.result_message,
        "executed_at": _isoformat(action.executed_at),
        "created_at": _isoformat(action.created_at),
        "attack_type": getattr(alert, "attack_type", None),
        "severity": getattr(alert, "severity", None),
        "source_ip": getattr(alert, "source_ip", None),
    }


def index_alert(alert):
    _index_doc(ALERTS_INDEX, alert.id, alert_to_doc(alert))


def index_response(action):
    _index_doc(RESPONSES_INDEX, action.id, response_to_doc(action))
