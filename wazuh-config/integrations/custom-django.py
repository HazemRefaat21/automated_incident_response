#!/usr/bin/env python3
"""
Wazuh Custom Integration — Django SIEM
بيبعت كل alert لـ Django API
"""

import sys
import json
import requests
import logging
from datetime import datetime

# =====================
# CONFIG
# =====================
DJANGO_URL = "http://172.18.0.1:8000/api/alerts/ingest/"
WAZUH_SECRET = "wazuh-django-secret-key-123"
LOG_FILE = "/var/ossec/logs/integrations.log"

# =====================
# LOGGING
# =====================
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s'
)
logger = logging.getLogger(__name__)


def main():
    # Wazuh بيبعت 3 arguments:
    # sys.argv[1] = path للـ alert JSON file
    # sys.argv[2] = api_key (الـ secret بتاعنا)
    # sys.argv[3] = hook_url

    if len(sys.argv) < 2:
        logger.error("No alert file provided")
        sys.exit(1)

    alert_file = sys.argv[1]

    # قراءة الـ alert
    try:
        with open(alert_file, 'r') as f:
            alert_data = json.load(f)
    except Exception as e:
        logger.error(f"Failed to read alert file: {e}")
        sys.exit(1)

    logger.info(f"Processing alert ID: {alert_data.get('id', 'unknown')}")

    # إرسال لـ Django
    try:
        response = requests.post(
            DJANGO_URL,
            json=alert_data,
            headers={
                'Content-Type': 'application/json',
                'X-Wazuh-Secret': WAZUH_SECRET,
            },
            timeout=5
        )

        if response.status_code == 200:
            logger.info(f"Alert sent successfully: {alert_data.get('id')}")
        else:
            logger.error(f"Django returned {response.status_code}: {response.text}")

    except requests.exceptions.ConnectionError:
        logger.error(f"Cannot connect to Django at {DJANGO_URL}")
    except requests.exceptions.Timeout:
        logger.error("Django request timed out")
    except Exception as e:
        logger.error(f"Unexpected error: {e}")


if __name__ == "__main__":
    main()
