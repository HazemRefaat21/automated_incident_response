from pathlib import Path
from decouple import config

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = config('SECRET_KEY')
DEBUG = config('DEBUG', default=False, cast=bool)
ALLOWED_HOSTS = ["*"]

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    # Third party
    'rest_framework',
    'rest_framework_simplejwt',
    'django_filters',
    # Our apps
    'alerts',
    'responses',
    'classification',
    'search',
    'django_tasks_db',
]

# Elasticsearch / Kibana — standalone stack (kibana/docker-compose.yml).
# Separate from the Wazuh Indexer; Django mirrors alerts + responses here so
# Kibana can visualize them.
ES_ENABLED = config('ES_ENABLED', default=True, cast=bool)
ES_URL     = config('ES_URL', default='http://localhost:9201')
ES_TIMEOUT = config('ES_TIMEOUT', default=5, cast=int)

MIDDLEWARE = [
    'siem_backend.middleware.AccessLogMiddleware',  # writes Apache-format access log for Wazuh
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'siem_backend.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'siem_backend.wsgi.application'

# Access log consumed by the Wazuh agent (Apache "combined" format).
LOGS_DIR = BASE_DIR / 'logs'
LOGS_DIR.mkdir(exist_ok=True)

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'raw': {'format': '%(message)s'},
    },
    'handlers': {
        'access_file': {
            'class': 'logging.handlers.WatchedFileHandler',  # plays nice with logrotate
            'filename': str(LOGS_DIR / 'django_access.log'),
            'formatter': 'raw',
        },
    },
    'loggers': {
        'django.access': {
            'handlers': ['access_file'],
            'level': 'INFO',
            'propagate': False,
        },
    },
}

# Database
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': config('DB_NAME'),
        'USER': config('DB_USER'),
        'PASSWORD': config('DB_PASSWORD'),
        'HOST': config('DB_HOST', default='localhost'),
        'PORT': config('DB_PORT', default='5432'),
    }
}

AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'Africa/Cairo'
USE_I18N = True
USE_TZ = True
STATIC_URL = 'static/'
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# Django REST Framework
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ),
    'DEFAULT_PERMISSION_CLASSES': (
        'rest_framework.permissions.IsAuthenticated',
    ),
    'DEFAULT_FILTER_BACKENDS': (
        'django_filters.rest_framework.DjangoFilterBackend',
        'rest_framework.filters.SearchFilter',
        'rest_framework.filters.OrderingFilter',
    ),
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.PageNumberPagination',
    'PAGE_SIZE': 50,
}

# JWT
from datetime import timedelta
SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(hours=24),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=7),
}


# Wazuh
WAZUH_API_URL = config('WAZUH_API_URL', default='https://127.0.0.1:55000')
WAZUH_API_USER = config('WAZUH_API_USER', default='admin')
WAZUH_INTEGRATION_SECRET = config('WAZUH_INTEGRATION_SECRET', default='change-me')
TASKS = {
    "default": {
        "BACKEND": "django_tasks_db.DatabaseBackend"
    }
}

# Auto-run the django-tasks DB worker in a background thread when the app boots,
# so enqueued response tasks are consumed without a separate `manage.py db_worker`
# process. Set RUN_TASK_WORKER=false to disable (e.g. when running a dedicated
# worker process in production).
RUN_TASK_WORKER = config('RUN_TASK_WORKER', default=True, cast=bool)