"""
Create the Elasticsearch indices and backfill all existing Alerts / ResponseActions.

Run once after starting Elasticsearch (and any time you want to re-sync):

    python manage.py es_sync
"""
from django.core.management.base import BaseCommand

from alerts.models import Alert
from responses.models import ResponseAction
from search import es_client


class Command(BaseCommand):
    help = "Create ES indices and backfill existing alerts and response actions."

    def handle(self, *args, **options):
        es = es_client.get_client()
        if es is None:
            self.stderr.write(self.style.ERROR(
                "No Elasticsearch client. Is the package installed and ES_URL reachable?"))
            return

        try:
            info = es.info()
            self.stdout.write(self.style.SUCCESS(
                f"Connected to Elasticsearch {info['version']['number']} at {es_client.settings.ES_URL}"))
        except Exception as e:  # noqa: BLE001
            self.stderr.write(self.style.ERROR(f"Cannot reach Elasticsearch: {e}"))
            return

        if not es_client.ensure_indices():
            self.stderr.write(self.style.ERROR("Failed to create indices."))
            return
        self.stdout.write(self.style.SUCCESS("Indices ready."))

        n_alerts = 0
        for alert in Alert.objects.all().iterator():
            es_client.index_alert(alert)
            n_alerts += 1
        self.stdout.write(self.style.SUCCESS(f"Indexed {n_alerts} alerts -> '{es_client.ALERTS_INDEX}'"))

        n_actions = 0
        for action in ResponseAction.objects.select_related("alert").iterator():
            es_client.index_response(action)
            n_actions += 1
        self.stdout.write(self.style.SUCCESS(
            f"Indexed {n_actions} response actions -> '{es_client.RESPONSES_INDEX}'"))

        # Make the docs immediately searchable in Kibana.
        try:
            es.indices.refresh(index=f"{es_client.ALERTS_INDEX},{es_client.RESPONSES_INDEX}")
        except Exception:  # noqa: BLE001
            pass
        self.stdout.write(self.style.SUCCESS("Done. Create data views in Kibana for "
                                             "'django-alerts*' and 'django-responses*'."))
