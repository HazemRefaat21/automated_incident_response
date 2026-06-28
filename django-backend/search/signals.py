"""
Mirror Django DB writes into Elasticsearch so Kibana can visualize them.

Uses post_save signals (kept separate from the alerts/responses business logic
hooks) and indexes on a best-effort basis. ES being down never blocks a write.
"""
import logging

from django.db.models.signals import post_save
from django.dispatch import receiver

from alerts.models import Alert
from responses.models import ResponseAction
from . import es_client

logger = logging.getLogger(__name__)


@receiver(post_save, sender=Alert, dispatch_uid="search_index_alert")
def _index_alert(sender, instance, **kwargs):
    es_client.index_alert(instance)


@receiver(post_save, sender=ResponseAction, dispatch_uid="search_index_response")
def _index_response(sender, instance, **kwargs):
    es_client.index_response(instance)
