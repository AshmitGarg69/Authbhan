#!/usr/bin/env bash
# =============================================================================
# CRISPR Smart Tunnel — server FIX script (run ONCE with sudo)
# Fixes: (1) squid v1 config blocked CONNECT to port 443 (all HTTPS!),
#        (2) loopback missing from client ACL (server self-test 403),
#        (3) broken delay-pool parameters.
# Idempotent: safe to re-run.
# =============================================================================
set -uo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: run with sudo:  sudo bash /tmp/apply-fixes.sh" >&2
    exit 1
fi

echo "[1/4] Checking the NEW Squid config BEFORE installing it..."
if squid -k parse -f /tmp/squid.conf > /tmp/squid-parse.log 2>&1; then
    echo "      syntax OK"
else
    echo "ERROR: /tmp/squid.conf failed to parse — nothing was changed." >&2
    tail -20 /tmp/squid-parse.log >&2
    exit 1
fi

echo "[2/4] Installing fixed Squid config (v2)..."
if [ -f /etc/squid/squid.conf ]; then
    cp /etc/squid/squid.conf "/etc/squid/squid.conf.bak.$(date +%s)"
fi
install -m 0644 /tmp/squid.conf /etc/squid/squid.conf

echo "[3/4] Restarting Squid..."
systemctl restart squid
sleep 1
if systemctl is-active --quiet squid; then
    echo "      squid is active"
else
    echo "ERROR: squid failed to start — journalctl -u squid -n 20" >&2
    journalctl -u squid -n 20 --no-pager >&2
    exit 1
fi

echo "[4/4] Verification:"
echo "--- Squid HTTPS test (must print an IP, not 403) ---"
curl -sS -m 10 -x http://127.0.0.1:3128 https://icanhazip.com && echo "[OK] proxy works" || echo "[FAIL] proxy still broken"
echo "--- Shared list ---"
curl -sS -m 5 http://127.0.0.1:8081/smart/list || true
echo ""
echo "Done."
