#!/usr/bin/env bash
# Diagnose why Django access-log attacks aren't producing Wazuh alerts.
# Run: sudo bash wazuh-config/diagnose-django-detection.sh
set -uo pipefail
[[ $EUID -ne 0 ]] && { echo "run with sudo"; exit 1; }

echo "================ 1) Is the agent connected to the manager? ================"
/var/ossec/bin/agent_control -l 2>/dev/null || echo "agent_control failed (manager not local?)"

echo; echo "================ 2) agentd state ================"
grep -E "status|last_keepalive|last_ack|target" /var/ossec/var/run/wazuh-agentd.state 2>/dev/null

echo; echo "================ 3) wazuh-logtest on a real attack line ================"
echo "Feeding a SQLi + a union-select line through the rule engine..."
printf '%s\n' \
'127.0.0.1 - - [28/Jun/2026:08:19:51 +0300] "GET /index.php?union+select+1,2,3 HTTP/1.1" 200 100 "-" "curl/8.5.0"' \
| /var/ossec/bin/wazuh-logtest 2>&1 | sed -n '1,40p'

echo; echo "================ 4) Recent alerts mentioning django ================"
grep -F "django_access.log" /var/ossec/logs/alerts/alerts.log 2>/dev/null | tail -5 || echo "none in alerts.log"

echo; echo "================ 5) Did the manager even receive the events? (archives) ================"
if grep -q "<logall>yes</logall>\|<logall_json>yes</logall_json>" /var/ossec/etc/ossec.conf 2>/dev/null; then
  grep -F "django_access.log" /var/ossec/logs/archives/archives.log 2>/dev/null | tail -3 || echo "no django lines in archives"
else
  echo "archiving (<logall>) is OFF — can't confirm raw receipt this way (that's normal/fine)"
fi
