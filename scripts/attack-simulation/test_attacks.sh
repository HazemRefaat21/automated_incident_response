#!/bin/bash
TARGET="http://localhost"
echo "🎯 Attack Simulation Started"
echo "================================"

echo ""
echo "--- [1] SQL Injection ---"
curl -s "$TARGET/?id=1+OR+1=1" > /dev/null
curl -s "$TARGET/?q=union+select+username+from+users" > /dev/null
curl -s "$TARGET/?id=1+union+select+1,2,3--" > /dev/null
echo "✅ Done"

echo ""
echo "--- [2] XSS ---"
curl -s "$TARGET/?q=<script>alert(1)</script>" > /dev/null
curl -s "$TARGET/?name=<img+onerror=alert(1)>" > /dev/null
echo "✅ Done"

echo ""
echo "--- [3] Directory Traversal ---"
curl -s "$TARGET/../../etc/passwd" > /dev/null
curl -s "$TARGET/?file=../../../etc/shadow" > /dev/null
echo "✅ Done"

echo ""
echo "--- [4] Admin Scanning ---"
curl -s "$TARGET/admin" > /dev/null
curl -s "$TARGET/phpmyadmin" > /dev/null
curl -s "$TARGET/.env" > /dev/null
curl -s "$TARGET/.git" > /dev/null
echo "✅ Done"

echo ""
echo "--- [5] Scanner User-Agent ---"
curl -s -A "sqlmap/1.0" "$TARGET/" > /dev/null
curl -s -A "nikto/2.1" "$TARGET/" > /dev/null
curl -s -A "nmap scripting" "$TARGET/" > /dev/null
echo "✅ Done"

echo ""
echo "--- [6] Command Injection ---"
curl -s "$TARGET/?cmd=whoami" > /dev/null
curl -s "$TARGET/?q=/bin/bash" > /dev/null
echo "✅ Done"

echo ""
echo "--- [7] SSH Brute Force ---"
for i in {1..10}; do
  ssh -o StrictHostKeyChecking=no \
      -o ConnectTimeout=2 \
      -o BatchMode=yes \
      fakeuser@localhost 2>/dev/null || true
done
echo "✅ Done"

echo ""
echo "================================"
echo "✅ All attacks simulated!"
echo "Wait 30 seconds then check:"
echo "  - Wazuh Dashboard → Threat Hunting"
echo "  - Django: http://localhost:8000/admin/"
echo "================================"
