#!/usr/bin/env bash
#
# Registers Django's access log with the local Wazuh agent so wazuh-logcollector
# tails it and the manager's web ruleset can flag SQLi/XSS/traversal/etc.
#
# Run with sudo:   sudo bash wazuh-config/install-django-localfile.sh
#
set -euo pipefail

OSSEC_CONF=/var/ossec/etc/ossec.conf
LOG_PATH=/home/hazem/automated_incident_response/django-backend/logs/django_access.log

if [[ $EUID -ne 0 ]]; then
  echo "Please run as root:  sudo bash $0" >&2
  exit 1
fi

if [[ ! -f "$OSSEC_CONF" ]]; then
  echo "ossec.conf not found at $OSSEC_CONF" >&2
  exit 1
fi

# Idempotent: bail out if this log is already registered.
if grep -qF "$LOG_PATH" "$OSSEC_CONF"; then
  echo "Django access log already registered in ossec.conf — nothing to do."
else
  cp -a "$OSSEC_CONF" "${OSSEC_CONF}.bak.$(date +%Y%m%d%H%M%S)"

  BLOCK="  <localfile>\n    <log_format>apache</log_format>\n    <location>${LOG_PATH}</location>\n  </localfile>\n"

  # Insert the block just before the final </ossec_config> closing tag.
  awk -v block="$BLOCK" '
    /<\/ossec_config>/ && !done { printf block; done=1 }
    { print }
  ' "$OSSEC_CONF" > "${OSSEC_CONF}.new"
  mv "${OSSEC_CONF}.new" "$OSSEC_CONF"
  chown root:wazuh "$OSSEC_CONF"
  chmod 640 "$OSSEC_CONF"
  echo "Added <localfile> block for $LOG_PATH"
fi

echo "Restarting Wazuh agent..."
/var/ossec/bin/wazuh-control restart

echo
echo "Done. Verify the agent is now tailing the log:"
echo "  sudo grep -F '$LOG_PATH' /var/ossec/logs/ossec.log | tail"
