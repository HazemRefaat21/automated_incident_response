from django.apps import AppConfig


class ResponsesConfig(AppConfig):
    name = 'responses'

    def ready(self):
        # Auto-start the supervised background task worker so enqueued response
        # actions are executed without a separate `manage.py db_worker` process.
        from .worker_supervisor import start
        start()
