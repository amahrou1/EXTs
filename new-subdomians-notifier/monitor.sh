#!/usr/bin/env bash
# ------------------------------------------------------------------------------
# Subdomain monitoring + Discord notifier
#
# Runs passive enumeration (subfinder, amass, assetfinder, findomain) against
# every root domain listed in ${MON_DIR}/targets.txt, probes liveness with
# httpx, diffs against a per-target cumulative baseline, and pushes a single
# combined Discord message listing every NEW alive subdomain discovered.
#
# Intended to run via cron every 72h. Safe to run as root.
# ------------------------------------------------------------------------------

set -Eeuo pipefail

# ----- Config -----------------------------------------------------------------
MON_DIR="/root/monitor"
DATA_DIR="${MON_DIR}/data"
TARGETS_FILE="${MON_DIR}/targets.txt"
CONFIG_FILE="${MON_DIR}/config.env"
LOCKFILE="/tmp/subdomain-monitor.lock"
DISCORD_LIMIT=1900   # leave headroom under the hard 2000 char ceiling

REQUIRED_TOOLS=(subfinder amass assetfinder findomain httpx curl flock comm sort mktemp)

# ----- Pre-flight -------------------------------------------------------------
for tool in "${REQUIRED_TOOLS[@]}"; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "ERROR: required tool '$tool' not found in PATH" >&2
        exit 1
    fi
done

if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "ERROR: config file not found: $CONFIG_FILE" >&2
    exit 1
fi

# shellcheck disable=SC1090
source "$CONFIG_FILE"

if [[ -z "${DISCORD_WEBHOOK_URL:-}" || "$DISCORD_WEBHOOK_URL" == "PUT_YOUR_NEW_WEBHOOK_URL_HERE" ]]; then
    echo "ERROR: DISCORD_WEBHOOK_URL is unset or still holds the placeholder in $CONFIG_FILE" >&2
    exit 1
fi

if [[ ! -f "$TARGETS_FILE" ]]; then
    echo "ERROR: targets file not found: $TARGETS_FILE" >&2
    exit 1
fi

mkdir -p "$DATA_DIR"

# ----- Locking ----------------------------------------------------------------
# If a previous run is still in progress, exit silently. No queueing.
exec 9>"$LOCKFILE"
if ! flock -n 9; then
    exit 0
fi

# ----- Temp + cleanup ---------------------------------------------------------
TMP_DIR="$(mktemp -d /tmp/subdomain-monitor.XXXXXX)"
cleanup() {
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

NOTIF_FILE="${TMP_DIR}/notifications.tsv"   # "target<TAB>enriched-httpx-line"
: > "$NOTIF_FILE"

# ----- Helpers ----------------------------------------------------------------

# JSON-escape stdin -> stdout, pure bash.
json_escape() {
    local s
    s=$(cat)
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\r'/}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
}

# Send a Discord message. One retry after 30s, then give up silently.
send_discord() {
    local content="$1"
    local payload attempt code
    payload=$(printf '%s' "$content" | json_escape)
    payload="{\"content\":\"${payload}\"}"

    for attempt in 1 2; do
        code=$(curl -sS -o /dev/null -w '%{http_code}' \
                    --max-time 20 \
                    -H 'Content-Type: application/json' \
                    -d "$payload" \
                    "$DISCORD_WEBHOOK_URL" 2>/dev/null || echo "000")
        if [[ "$code" =~ ^2[0-9][0-9]$ ]]; then
            return 0
        fi
        [[ "$attempt" -eq 1 ]] && sleep 30
    done
    return 1
}

# Enumerate one root domain and record any new alive subs to $NOTIF_FILE.
process_target() {
    local target="$1"
    local target_dir="${DATA_DIR}/${target}"
    local baseline="${target_dir}/baseline.txt"
    local work="${TMP_DIR}/${target}"
    mkdir -p "$target_dir" "$work"

    # --- Enumeration (passive only, all four sources) -------------------------
    subfinder -d "$target" -all -silent \
        -o "${work}/subfinder.txt" >/dev/null 2>&1 || true

    amass enum -passive -d "$target" -nolog \
        -o "${work}/amass.txt" >/dev/null 2>&1 || true

    assetfinder --subs-only "$target" \
        > "${work}/assetfinder.txt" 2>/dev/null || true

    findomain --quiet -t "$target" -u "${work}/findomain.txt" \
        >/dev/null 2>&1 || true

    # --- Merge + dedupe -------------------------------------------------------
    cat "${work}"/subfinder.txt \
        "${work}"/amass.txt \
        "${work}"/assetfinder.txt \
        "${work}"/findomain.txt 2>/dev/null \
      | tr '[:upper:]' '[:lower:]' \
      | sed -E 's/^\*\.//; s/[[:space:]]+$//' \
      | grep -E '^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$' \
      | grep -E "(^|\.)${target//./\\.}$" \
      | sort -u > "${work}/all.txt" || true

    if [[ ! -s "${work}/all.txt" ]]; then
        # Nothing discovered. First run? Still create an empty baseline so we
        # don't notify for a late-arriving result next time.
        [[ -f "$baseline" ]] || : > "$baseline"
        return 0
    fi

    # --- Liveness probe -------------------------------------------------------
    httpx -l "${work}/all.txt" \
        -silent -no-color \
        -o "${work}/alive.txt" >/dev/null 2>&1 || true

    if [[ ! -s "${work}/alive.txt" ]]; then
        [[ -f "$baseline" ]] || : > "$baseline"
        return 0
    fi

    # Normalize alive URLs -> bare hostnames for baseline comparison.
    sed -E 's#^https?://##; s#[:/].*$##' "${work}/alive.txt" \
      | sort -u > "${work}/alive_hosts.txt"

    # --- First-run baseline ---------------------------------------------------
    if [[ ! -f "$baseline" ]]; then
        cp "${work}/alive_hosts.txt" "$baseline"
        return 0
    fi

    # --- Diff against baseline ------------------------------------------------
    comm -23 "${work}/alive_hosts.txt" <(sort -u "$baseline") \
        > "${work}/new_hosts.txt" || true

    # Union-update baseline (never shrink).
    sort -u "$baseline" "${work}/alive_hosts.txt" -o "$baseline"

    [[ -s "${work}/new_hosts.txt" ]] || return 0

    # --- Enrich new hosts -----------------------------------------------------
    httpx -l "${work}/new_hosts.txt" \
        -sc -title -tech-detect -cl \
        -silent -no-color \
        -o "${work}/enriched.txt" >/dev/null 2>&1 || true

    [[ -s "${work}/enriched.txt" ]] || return 0

    # Record "<target>\t<enriched-line>" for later message assembly.
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        printf '%s\t%s\n' "$target" "$line" >> "$NOTIF_FILE"
    done < "${work}/enriched.txt"
}

# ----- Main loop: iterate targets --------------------------------------------
while IFS= read -r raw || [[ -n "$raw" ]]; do
    # strip leading/trailing whitespace
    line="${raw#"${raw%%[![:space:]]*}"}"
    line="${line%"${line##*[![:space:]]}"}"
    [[ -z "$line" ]] && continue
    [[ "${line:0:1}" == "#" ]] && continue

    # only accept something that looks like a domain
    if ! [[ "$line" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        continue
    fi

    process_target "$line"
done < "$TARGETS_FILE"

# ----- Assemble Discord message(s) -------------------------------------------
if [[ ! -s "$NOTIF_FILE" ]]; then
    exit 0
fi

# Preserve target order of first appearance, group entries per target.
targets_order=()
declare -A target_entries
declare -A target_count

while IFS=$'\t' read -r tgt entry; do
    if [[ -z "${target_entries[$tgt]+x}" ]]; then
        targets_order+=("$tgt")
        target_entries["$tgt"]=""
        target_count["$tgt"]=0
    fi
    target_entries["$tgt"]+="• ${entry}"$'\n'
    target_count["$tgt"]=$(( target_count["$tgt"] + 1 ))
done < "$NOTIF_FILE"

HEADER="🚨 New alive subdomains found"
CONT_HEADER="🚨 New alive subdomains found (cont.)"

messages=()
current="$HEADER"

append_line() {
    # Append $1 as its own line to $current, flushing when the 1900-char
    # budget would be exceeded. Never breaks in the middle of a line.
    local line="$1"
    local candidate="${current}"$'\n'"${line}"
    if (( ${#candidate} > DISCORD_LIMIT )); then
        messages+=("$current")
        current="${CONT_HEADER}"$'\n'"${line}"
    else
        current="$candidate"
    fi
}

for tgt in "${targets_order[@]}"; do
    append_line ""
    append_line "**${tgt}** (${target_count[$tgt]} new)"
    while IFS= read -r bullet; do
        [[ -z "$bullet" ]] && continue
        append_line "$bullet"
    done <<< "${target_entries[$tgt]}"
done

messages+=("$current")

for msg in "${messages[@]}"; do
    send_discord "$msg" || true
done

exit 0
