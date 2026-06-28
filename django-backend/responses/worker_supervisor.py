"""Self-supervising background worker for the django-tasks DB queue.

Runs the same loop as `manage.py db_worker`, but inside the web process on a
daemon thread, so response tasks (execute_response) are consumed automatically
when the app boots — no separate worker process required for dev.

The thread supervises itself: if the worker loop crashes it is logged and
restarted after a short backoff. Started once from ResponsesConfig.ready().
"""
import logging
import os
import sys
import threading
import time

logger = logging.getLogger(__name__)

_started = False
_lock = threading.Lock()

# Management commands that must NOT spin up the worker (no point, or harmful).
_SKIP_COMMANDS = {
    "migrate", "makemigrations", "collectstatic", "shell", "shell_plus",
    "dbshell", "test", "db_worker", "createsuperuser", "check",
    "loaddata", "dumpdata", "showmigrations", "flush", "sqlmigrate",
}

_RESTART_BACKOFF = 5  # seconds between supervised restarts


def _supervise():
    from django_tasks import DEFAULT_TASK_BACKEND_ALIAS
    from django_tasks.base import DEFAULT_TASK_QUEUE_NAME
    from django_tasks.utils import get_random_id
    from django_tasks_db.management.commands.db_worker import Worker

    while True:
        worker = Worker(
            queue_names=[DEFAULT_TASK_QUEUE_NAME],
            interval=1,
            batch=False,
            backend_name=DEFAULT_TASK_BACKEND_ALIAS,
            startup_delay=False,
            max_tasks=None,
            worker_id=get_random_id(),
        )
        logger.info("[worker] starting db_worker thread (id=%s)", worker.worker_id)
        try:
            # NB: never call worker.configure_signals() off the main thread.
            worker.run()
            # run() returns only if self.running was cleared; nothing clears it
            # here, so a clean return means the loop stopped unexpectedly.
            logger.warning("[worker] db_worker loop exited; restarting in %ss", _RESTART_BACKOFF)
        except Exception:  # noqa: BLE001 — keep the supervisor alive no matter what
            logger.exception("[worker] db_worker crashed; restarting in %ss", _RESTART_BACKOFF)
        time.sleep(_RESTART_BACKOFF)


def start():
    """Start the supervised worker thread once. Safe to call repeatedly."""
    global _started

    from django.conf import settings

    if not getattr(settings, "RUN_TASK_WORKER", False):
        return

    # Skip for management commands that shouldn't run the worker.
    if len(sys.argv) > 1 and sys.argv[1] in _SKIP_COMMANDS:
        return

    # Under runserver's autoreloader, ready() runs in both the reloader parent
    # and the child. Only the child sets RUN_MAIN=true — start there to avoid
    # two workers. When not using the reloader (gunicorn/uvicorn/--noreload),
    # RUN_MAIN is unset and we start normally.
    using_runserver = len(sys.argv) > 1 and sys.argv[1] == "runserver"
    autoreload = using_runserver and "--noreload" not in sys.argv
    if autoreload and os.environ.get("RUN_MAIN") != "true":
        return

    with _lock:
        if _started:
            return
        _started = True
        thread = threading.Thread(target=_supervise, name="db_worker_supervisor", daemon=True)
        thread.start()
        logger.info("[worker] background task worker supervisor started")
