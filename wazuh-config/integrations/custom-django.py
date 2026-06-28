#!/usr/bin/env python3
"""
Wazuh Custom Integration — Django SIEM
بيبعت كل alert لـ Django API

Uses only the Python standard library (urllib) so it never depends on
pip packages like `requests`, which are not in the Wazuh manager image and
get lost whenever the container is recreated.
"""

import sys
import json
import logging
import urllib.request
import urllib.error

# =====================
# CONFIG
# =====================
DJANGO_URL = "http://172.18.0.1:8001/api/alerts/ingest/"
WAZUH_SECRET = "wazuh-django-secret-key-123"
LOG_FILE = "/var/ossec/logs/integrations.log"
TIMEOUT = 5

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
    payload = json.dumps(alert_data).encode('utf-8')
    req = urllib.request.Request(
        DJANGO_URL,
        data=payload,
        headers={
            'Content-Type': 'application/json',
            'X-Wazuh-Secret': WAZUH_SECRET,
        },
        method='POST',
    )

    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            if resp.status == 200:
                logger.info(f"Alert sent successfully: {alert_data.get('id')}")
            else:
                logger.error(f"Django returned {resp.status}: {resp.read().decode('utf-8', 'replace')}")
    except urllib.error.HTTPError as e:
        logger.error(f"Django returned {e.code}: {e.read().decode('utf-8', 'replace')}")
    except urllib.error.URLError as e:
        logger.error(f"Cannot connect to Django at {DJANGO_URL}: {e.reason}")
    except Exception as e:
        logger.error(f"Unexpected error: {e}")


if __name__ == "__main__":
    main()
