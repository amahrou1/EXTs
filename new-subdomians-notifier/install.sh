#!/usr/bin/env bash
# ------------------------------------------------------------------------------
# Installer for the subdomain-monitoring + Discord notifier.
#
# Copies files into /root/monitor/, sets permissions, and installs a cron
# entry that runs the monitor every 72 hours. Safe to re-run (idempotent).
#
# Usage:
#   sudo ./install.sh
# ------------------------------------------------------------------------------

set -Eeuo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: run as root (sudo ./install.sh)" >&2
    exit 1
fi

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MON_DIR="/root/monitor"
DATA_DIR="${MON_DIR}/data"

echo "[*] Creating ${MON_DIR} ..."
mkdir -p "$DATA_DIR"

echo "[*] Installing monitor.sh ..."
install -m 700 "${SRC_DIR}/monitor.sh" "${MON_DIR}/monitor.sh"

echo "[*] Installing targets.txt (preserving existing) ..."
if [[ ! -f "${MON_DIR}/targets.txt" ]]; then
    install -m 600 "${SRC_DIR}/targets.txt" "${MON_DIR}/targets.txt"
else
    echo "    -> kept existing ${MON_DIR}/targets.txt"
fi

echo "[*] Installing config.env (preserving existing) ..."
if [[ ! -f "${MON_DIR}/config.env" ]]; then
    if [[ ! -f "${SRC_DIR}/config.env.example" ]]; then
        echo "ERROR: ${SRC_DIR}/config.env.example not found" >&2
        exit 1
    fi
    install -m 600 "${SRC_DIR}/config.env.example" "${MON_DIR}/config.env"
    echo "    -> edit ${MON_DIR}/config.env and set DISCORD_WEBHOOK_URL"
else
    chmod 600 "${MON_DIR}/config.env"
    echo "    -> kept existing ${MON_DIR}/config.env (chmod 600 enforced)"
fi

echo "[*] Installing README.md ..."
install -m 644 "${SRC_DIR}/README.md" "${MON_DIR}/README.md"

echo "[*] Tool pre-flight (subfinder / amass / assetfinder / findomain / httpx / curl) ..."
missing=0
for t in subfinder amass assetfinder findomain httpx curl; do
    if ! command -v "$t" >/dev/null 2>&1; then
        echo "    ! missing: $t"
        missing=1
    else
        printf '    ok: %-12s -> %s\n' "$t" "$(command -v "$t")"
    fi
done
if [[ $missing -ne 0 ]]; then
    echo "[!] Install the missing tools before the first run (see README)."
fi

echo "[*] Installing cron entry (every 72 hours) ..."
# Build a PATH that includes typical go-install locations so cron can find the
# enumeration binaries (subfinder/amass/assetfinder/httpx frequently live in
# $GOPATH/bin rather than /usr/local/bin).
CRON_PATH="PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/root/go/bin"
CRON_LINE="0 3 */3 * * /root/monitor/monitor.sh >/dev/null 2>&1"
TMP_CRON="$(mktemp)"
# Strip any prior monitor.sh line AND any prior PATH line we wrote, then rewrite.
crontab -l 2>/dev/null \
    | grep -v -F '/root/monitor/monitor.sh' \
    | grep -v -F '/root/go/bin' \
    > "$TMP_CRON" || true
echo "$CRON_PATH" >> "$TMP_CRON"
echo "$CRON_LINE" >> "$TMP_CRON"
crontab "$TMP_CRON"
rm -f "$TMP_CRON"
echo "    -> $CRON_PATH"
echo "    -> $CRON_LINE"

echo ""
echo "============================================================"
echo "[+] Install complete."
echo "============================================================"
echo ""
echo "  IMPORTANT: from now on ONLY edit files under /root/monitor/."
echo "  NEVER edit files under this repo directory ($SRC_DIR)."
echo "  Files in the repo are templates that get committed to git;"
echo "  files in /root/monitor/ are your real local config."
echo ""
echo "  Run these commands now, in order:"
echo ""
echo "    # 1. Set your Discord webhook URL"
echo "    sudoedit /root/monitor/config.env"
echo ""
echo "    # 2. Add one bug-bounty root domain per line"
echo "    sudoedit /root/monitor/targets.txt"
echo ""
echo "    # 3. Build the first baseline (silent, no Discord message)"
echo "    sudo /root/monitor/monitor.sh"
echo ""
echo "    # 4. Verify baselines were created"
echo "    ls -la /root/monitor/data/"
echo ""
echo "    # 5. Send a test Discord message to confirm the webhook"
echo "    source /root/monitor/config.env && \\"
echo "      curl -sS -o /dev/null -w '%{http_code}\\n' \\"
echo "        -H 'Content-Type: application/json' \\"
echo "        -d '{\"content\":\"OK subdomain monitor installed and ready\"}' \\"
echo "        \"\$DISCORD_WEBHOOK_URL\"   # expect 204"
echo ""
echo "    # 6. Confirm cron entry"
echo "    crontab -l"
echo ""
echo "  After that, cron runs the monitor every 72 hours automatically."
echo "============================================================"
