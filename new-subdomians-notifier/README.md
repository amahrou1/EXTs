# new-subdomians-notifier

Passive subdomain-monitoring daemon for bug-bounty recon. On every run it:

1. Enumerates subdomains for each root domain in `targets.txt` using
   `subfinder`, `amass` (passive), `assetfinder`, and `findomain`.
2. Merges + deduplicates, then probes liveness with `httpx`.
3. Diffs the alive list against a per-target cumulative baseline.
4. Enriches each *new* alive subdomain with status / title / tech / length.
5. Pushes a single combined Discord message grouped by target.

First-run targets get a baseline with **no** notification. Removing a target
from `targets.txt` keeps its historical baseline on disk — re-adding the
target resumes monitoring without sending a flood of fake "new" subs.

---

## 1. VPS prerequisites

Tested on Ubuntu 22.04 / 24.04, running as **root**. Install the binaries the
script shells out to. These need to live somewhere in root's `$PATH`
(`/usr/local/bin` is the easiest choice).

```bash
# --- Go toolchain (required for subfinder, amass, assetfinder, httpx) -------
apt update
apt install -y golang-go git curl unzip jq

# Make sure /usr/local/bin is on root's PATH (it is by default) and that
# go-installed binaries land there.
export GOPATH="${GOPATH:-/root/go}"
export PATH="$PATH:/usr/local/bin:$GOPATH/bin"

# --- subfinder, httpx (projectdiscovery) ------------------------------------
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
install -m 755 "$GOPATH/bin/subfinder" /usr/local/bin/subfinder
install -m 755 "$GOPATH/bin/httpx"     /usr/local/bin/httpx

# --- assetfinder ------------------------------------------------------------
go install -v github.com/tomnomnom/assetfinder@latest
install -m 755 "$GOPATH/bin/assetfinder" /usr/local/bin/assetfinder

# --- amass (v4) -------------------------------------------------------------
# Prefer the prebuilt release — it drops an `amass` binary in the archive.
AMASS_VER="v4.2.0"
curl -sL -o /tmp/amass.zip \
  "https://github.com/owasp-amass/amass/releases/download/${AMASS_VER}/amass_Linux_amd64.zip"
unzip -o /tmp/amass.zip -d /tmp/amass-extract
install -m 755 "$(find /tmp/amass-extract -name amass -type f | head -n1)" /usr/local/bin/amass
rm -rf /tmp/amass.zip /tmp/amass-extract

# --- findomain --------------------------------------------------------------
curl -sL -o /tmp/findomain.zip \
  https://github.com/findomain/findomain/releases/latest/download/findomain-linux.zip
unzip -o /tmp/findomain.zip -d /tmp/findomain-extract
install -m 755 /tmp/findomain-extract/findomain /usr/local/bin/findomain
rm -rf /tmp/findomain.zip /tmp/findomain-extract
```

Verify everything resolved:

```bash
for t in subfinder amass assetfinder findomain httpx curl; do
    printf '%-12s %s\n' "$t" "$(command -v "$t" || echo MISSING)"
done
```

All six must resolve. `monitor.sh` aborts early if any are missing.

### API keys (optional but recommended)

`subfinder` and `amass` hit more sources when you give them API keys.

* `subfinder` — `~/.config/subfinder/provider-config.yaml`
  (docs: <https://github.com/projectdiscovery/subfinder#post-installation-instructions>)
* `amass` — `~/.config/amass/config.yaml` (datasources section)

Without keys, passive-only enumeration still works; it just sees fewer sources.

---

## 2. Install the notifier

From this folder (on the VPS):

```bash
cd /path/to/EXTs/new-subdomians-notifier
sudo ./install.sh
```

`install.sh` is idempotent. It:

* creates `/root/monitor/{data,}`
* copies `monitor.sh` (0700), `targets.txt` (0600, only if absent),
  `config.env` (0600, only if absent), and `README.md` (0644)
* runs a tool pre-flight
* installs the crontab entry

After it finishes, the tree on the VPS looks like:

```
/root/monitor/
├── config.env             # webhook URL (chmod 600)
├── targets.txt            # you edit this manually
├── monitor.sh             # main script (chmod 700)
├── README.md
└── data/
    ├── dell.com/
    │   └── baseline.txt
    ├── fisglobal.com/
    │   └── baseline.txt
    └── ...
```

---

## 3. Configure

### 3.1 Add the Discord webhook

`config.env` ships containing:

```
DISCORD_WEBHOOK_URL="PUT_YOUR_NEW_WEBHOOK_URL_HERE"
```

Replace the placeholder with your real webhook (Discord → channel → Edit
Channel → Integrations → Webhooks → New Webhook → Copy URL):

```bash
sudoedit /root/monitor/config.env
chmod 600 /root/monitor/config.env   # already 600, but enforce anyway
```

### 3.2 Add targets

One root domain per line. Blank lines and `#` comments are ignored:

```bash
sudoedit /root/monitor/targets.txt
```

```
# bug-bounty scope
dell.com
fisglobal.com
```

### 3.3 Removing targets

Just delete the line. The monitor skips it on the next run. The historical
`data/<domain>/baseline.txt` is **not** touched — re-adding the domain
resumes monitoring from where you left off without a flood of false positives.

### 3.4 Rotating the webhook

```bash
sudoedit /root/monitor/config.env
# replace the URL, save
/root/monitor/monitor.sh    # optional smoke-test run
```

No restart is needed — the script sources `config.env` every run.

---

## 4. Scheduling

`install.sh` installs this line in root's crontab:

```
0 3 */3 * * /root/monitor/monitor.sh >/dev/null 2>&1
```

That fires at 03:00 every 3rd day (≈ every 72h). If two runs overlap, the
second exits silently thanks to the `flock` on `/tmp/subdomain-monitor.lock`.

Check it's installed:

```bash
crontab -l | grep monitor.sh
```

Follow cron's eye-view of when it actually ran:

```bash
# Ubuntu ships cron logs via journald on most modern releases:
journalctl -u cron --since "7 days ago" | grep monitor

# On systems still using syslog:
grep CRON /var/log/syslog | grep monitor
```

---

## 5. Manual testing

### 5.1 Baseline-creation smoke test

```bash
# 1. Start from an empty targets file
echo 'example.com' | sudo tee /root/monitor/targets.txt

# 2. Run once — should create /root/monitor/data/example.com/baseline.txt
#    and send ZERO Discord messages
sudo /root/monitor/monitor.sh

# 3. Verify
ls -la /root/monitor/data/example.com/
wc -l  /root/monitor/data/example.com/baseline.txt

# 4. Remove example.com from targets.txt — data must persist
sudo sed -i '/^example\.com$/d' /root/monitor/targets.txt
ls -la /root/monitor/data/example.com/   # still there
```

### 5.2 Webhook reachability test

```bash
# shellcheck disable=SC1091
source /root/monitor/config.env
curl -sS -H 'Content-Type: application/json' \
     -d '{"content":"✅ subdomain monitor installed and ready"}' \
     "$DISCORD_WEBHOOK_URL"
```

A `2xx` (typically `204`) means the webhook works.

### 5.3 End-to-end "fake new sub" test

To exercise the notification path without waiting 72h, truncate the baseline
for a well-known target and run again — everything currently alive becomes
"new" and should be reported in Discord:

```bash
sudo : > /root/monitor/data/<some-domain>/baseline.txt
sudo /root/monitor/monitor.sh
```

Restore the baseline afterwards (or just let the next run rebuild it).

---

## 6. File layout recap

| Path                                      | Purpose                                           | Perms |
|-------------------------------------------|---------------------------------------------------|-------|
| `/root/monitor/monitor.sh`                | main script                                       | 0700  |
| `/root/monitor/config.env`                | `DISCORD_WEBHOOK_URL=...`                         | 0600  |
| `/root/monitor/targets.txt`               | one root domain per line, `#` for comments       | 0600  |
| `/root/monitor/data/<domain>/baseline.txt`| cumulative alive subs ever seen for that target  | 0600  |
| `/tmp/subdomain-monitor.lock`             | `flock` lockfile (auto-managed)                   | -     |
| `/tmp/subdomain-monitor.XXXXXX/`          | per-run scratch dir, wiped on exit (trap)         | -     |

---

## 7. Troubleshooting

**Nothing was sent to Discord.**
Either no target had new subs this run (expected), or the webhook call failed.
Re-run manually and watch for `curl` errors:

```bash
sudo bash -x /root/monitor/monitor.sh 2>&1 | tail -n 80
```

**`ERROR: required tool 'xxx' not found in PATH`.**
Cron runs with a minimal `PATH`. If the tool lives outside `/usr/bin:/bin`,
either symlink it into `/usr/local/bin` or prepend a `PATH=...` line to the
crontab entry:

```
PATH=/usr/local/bin:/usr/bin:/bin:/root/go/bin
0 3 */3 * * /root/monitor/monitor.sh >/dev/null 2>&1
```

**A run seems stuck.**
Check the lockfile owner:

```bash
sudo fuser -v /tmp/subdomain-monitor.lock
ps -fp "$(sudo fuser /tmp/subdomain-monitor.lock 2>/dev/null)"
```

If truly hung, kill the PID; `flock` releases automatically.

**I want to force a "fresh start" for a target.**
Delete its folder:

```bash
sudo rm -rf /root/monitor/data/<domain>
```

The next run will re-baseline it with no notification (first-run behavior).
