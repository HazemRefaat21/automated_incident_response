from django.apps import AppConfig


class SearchConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "search"
    verbose_name = "Elasticsearch / Kibana sync"

    def ready(self):
        # Wire up the post_save signals that mirror data into Elasticsearch.
        from . import signals  # noqa: F401
