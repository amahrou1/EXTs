# new-subdomians-notifier

Passive subdomain-monitoring daemon for bug-bounty recon. On every run it:

1. Enumerates subdomains for each root domain in `targets.txt` using
   `subfinder`, `amass` (passive), `assetfinder`, and `findomain`.
2. Merges + deduplicates, then probes liveness with `httpx`.
3. Diffs the alive list against a per-target cumulative baseline.
4. Enriches each *new* alive subdomain with status / title / tech / length.
5. Pushes a single combined Discord message grouped by target.

First-run targets get a baseline with **no** notification. Removing a target
from `targets.txt` keeps its historical baseline on disk — re-adding it
resumes monitoring without sending a flood of fake "new" subs.

---

## RULES — read this once, never get lost again

There are **two copies** of the config files on the VPS. Get this distinction
right and you will never have a problem:

| Location                          | What it is        | Edit it? |
|-----------------------------------|-------------------|----------|
| `/root/EXTs/new-subdomians-notifier/` | git repo template | NO  — never edit, never put real data here |
| `/root/monitor/`                      | live runtime      | YES — this is the only place you ever edit |

**Always edit files under `/root/monitor/`.**
**Never edit files under the repo directory.**

If you ever accidentally edit a repo file, fix it with:

```bash
cd /root/EXTs/new-subdomians-notifier
git restore <file>
```

---

## 1. One-time VPS setup (install the recon binaries)

The script shells out to six binaries — they must be on root's `$PATH`. If
you already have them, skip this section. Otherwise, on Ubuntu 22.04 / 24.04:

```bash
apt update
apt install -y golang-go git curl unzip jq cron

export GOPATH="${GOPATH:-/root/go}"
export PATH="$PATH:/usr/local/bin:$GOPATH/bin"

# subfinder + httpx (projectdiscovery)
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
install -m 755 "$GOPATH/bin/subfinder" /usr/local/bin/subfinder
install -m 755 "$GOPATH/bin/httpx"     /usr/local/bin/httpx

# assetfinder
go install -v github.com/tomnomnom/assetfinder@latest
install -m 755 "$GOPATH/bin/assetfinder" /usr/local/bin/assetfinder

# amass v4 (use the prebuilt release archive)
AMASS_VER="v4.2.0"
curl -sL -o /tmp/amass.zip \
  "https://github.com/owasp-amass/amass/releases/download/${AMASS_VER}/amass_Linux_amd64.zip"
unzip -o /tmp/amass.zip -d /tmp/amass-extract
install -m 755 "$(find /tmp/amass-extract -name amass -type f | head -n1)" /usr/local/bin/amass
rm -rf /tmp/amass.zip /tmp/amass-extract

# findomain
curl -sL -o /tmp/findomain.zip \
  https://github.com/findomain/findomain/releases/latest/download/findomain-linux.zip
unzip -o /tmp/findomain.zip -d /tmp/findomain-extract
install -m 755 /tmp/findomain-extract/findomain /usr/local/bin/findomain
rm -rf /tmp/findomain.zip /tmp/findomain-extract

systemctl enable --now cron
```

Verify all six tools resolve:

```bash
for t in subfinder amass assetfinder findomain httpx curl; do
    printf '%-12s %s\n' "$t" "$(command -v "$t" || echo MISSING)"
done
```

If any line says `MISSING`, fix it before continuing.

### Optional — API keys for richer enumeration

`subfinder` and `amass` discover more sources with API keys. Without them,
passive enumeration still works.

* subfinder: `~/.config/subfinder/provider-config.yaml`
  (<https://github.com/projectdiscovery/subfinder#post-installation-instructions>)
* amass:     `~/.config/amass/config.yaml`

---

## 2. Quick-start — install the notifier (clean slate)

If you previously installed this and want a clean start:

```bash
# wipe ANY previous install (deletes baselines too — keep them if you want history)
sudo rm -rf /root/monitor

# wipe old crontab entries from a previous install
crontab -l 2>/dev/null \
  | grep -v -F '/root/monitor/monitor.sh' \
  | grep -v -F '/root/go/bin' \
  | crontab -
```

Then clone (or `git pull` if already cloned) and run the installer:

```bash
# clone (skip if /root/EXTs already exists; just `cd` into it and `git pull`)
cd /root
git clone https://github.com/amahrou1/EXTs.git
cd EXTs/new-subdomians-notifier
git checkout claude/subdomain-monitoring-discord-gU5Wz
git pull

# install
sudo ./install.sh
```

The installer creates `/root/monitor/`, copies the script and templates,
sets permissions, runs a tool pre-flight, and installs the cron entry.

---

## 3. Configure the notifier (do this AFTER `install.sh` finishes)

> Reminder: edit ONLY the files under `/root/monitor/`. Never touch the
> ones under `/root/EXTs/new-subdomians-notifier/`.

### 3a. Set the Discord webhook URL

```bash
sudoedit /root/monitor/config.env
```

Replace the placeholder line so it reads:

```
DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/XXXX/YYYY"
```

(Get this URL from Discord → channel → Edit Channel → Integrations →
Webhooks → New Webhook → Copy Webhook URL.)

### 3b. Add bug-bounty targets

```bash
sudoedit /root/monitor/targets.txt
```

One root domain per line. Blank lines and `#` comments are ignored:

```
dell.com
fisglobal.com
bol.com
```

### 3c. Build the initial baselines (silent run)

```bash
sudo /root/monitor/monitor.sh
```

This may take several minutes per target (passive enum + httpx liveness
across thousands of subs is not instant). You will see **no output** on
success — that's intentional; the script only speaks via Discord.

### 3d. Verify baselines exist

```bash
ls -la /root/monitor/data/
wc -l  /root/monitor/data/*/baseline.txt
```

You should see one directory per target with a non-empty `baseline.txt`.
A baseline of `0` lines just means that target had no live subs in this
pass — that's still a valid baseline.

### 3e. Send a Discord smoke-test message

```bash
source /root/monitor/config.env
curl -sS -o /dev/null -w '%{http_code}\n' \
     -H 'Content-Type: application/json' \
     -d '{"content":"OK subdomain monitor installed and ready"}' \
     "$DISCORD_WEBHOOK_URL"
```

Expect `204`. You should see the message appear in your Discord channel.
Anything other than `204` means the URL in `config.env` is wrong or the
webhook was deleted.

### 3f. Confirm cron is wired up

```bash
crontab -l
```

You should see exactly these two lines (among any other entries you have):

```
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/root/go/bin
0 3 */3 * * /root/monitor/monitor.sh >/dev/null 2>&1
```

That schedule fires at 03:00 every 3rd day (~ every 72h). **From this point
on, no further action is required from you.** You will get a Discord
message whenever new alive subdomains appear for any monitored target.

---

## 4. Day-to-day operations

### Add or remove a target

```bash
sudoedit /root/monitor/targets.txt
```

* New domain → next run silently builds its baseline; the run after that
  starts notifying you about new alive subs.
* Removed domain → its `data/<domain>/baseline.txt` stays on disk
  untouched. Re-add it later and monitoring resumes from where it stopped.

### Rotate the Discord webhook

```bash
sudoedit /root/monitor/config.env
# replace the URL, save, that's it — no restart needed
```

### Force an immediate run

```bash
sudo /root/monitor/monitor.sh
```

Won't double up with cron — `flock` makes overlapping runs exit silently.

### Force a notification end-to-end test

To prove the alert path without waiting 72h, blank one target's baseline so
everything currently alive becomes "new":

```bash
sudo : > /root/monitor/data/<domain>/baseline.txt
sudo /root/monitor/monitor.sh
```

You should receive a Discord message grouped by that target. The baseline
gets rebuilt by the same run.

### Reset one target completely

```bash
sudo rm -rf /root/monitor/data/<domain>
```

Next run treats it as a fresh first-run target (silent baseline, no alert).

---

## 5. File layout

```
/root/monitor/
├── monitor.sh                  # main script (chmod 700)
├── config.env                  # DISCORD_WEBHOOK_URL=... (chmod 600)
├── targets.txt                 # one root domain per line (chmod 600)
├── README.md                   # copy of this file
└── data/
    ├── dell.com/
    │   └── baseline.txt        # cumulative alive subs ever seen
    ├── fisglobal.com/
    │   └── baseline.txt
    └── ...

/tmp/subdomain-monitor.lock     # flock lockfile (auto-managed)
/tmp/subdomain-monitor.XXXXXX/  # per-run scratch dir (cleaned by trap)
```

---

## 6. Troubleshooting

**Cron didn't fire / nothing arrived in Discord after 72h.**

```bash
systemctl is-active cron                                # should print "active"
crontab -l                                              # both lines present?
journalctl -u cron --since "4 days ago" | grep monitor  # cron actually ran it?
sudo /root/monitor/monitor.sh                           # manual run, see if it errors
```

**`ERROR: required tool 'xxx' not found in PATH` when run from cron.**

The cron entry installed by `install.sh` already prepends
`/root/go/bin` to `PATH`. If your binaries live somewhere else, edit the
`PATH=` line in `crontab -e` to include that path.

**A run looks stuck.**

```bash
sudo fuser -v /tmp/subdomain-monitor.lock
ps -fp "$(sudo fuser /tmp/subdomain-monitor.lock 2>/dev/null)"
```

If genuinely hung, kill the PID; `flock` releases automatically.

**I edited a file in the repo by accident.**

```bash
cd /root/EXTs/new-subdomians-notifier
git restore <file>             # or `git restore .` to reset everything
git status                     # should be clean
```

If you've already committed real data to the repo, **rotate any secrets
involved** (Discord webhook etc.) and rewrite history with `git rebase` or
`git filter-repo` before pushing.

**Webhook URL was leaked / committed / pasted somewhere public.**

Delete it in Discord (Edit Channel → Integrations → Webhooks → Delete),
create a new one, and update `/root/monitor/config.env`. The old URL
becomes inert the moment you delete it on Discord's side.

---

## 7. Safety / privacy notes

* `config.env` is `chmod 600` — only root can read it.
* `config.env` is gitignored in this repo, so even an accidental
  `git add .` won't stage your real webhook URL.
* The script never writes log files. All intermediate output lives in
  `/tmp/subdomain-monitor.XXXXXX/` and is wiped on exit (including on
  crash/SIGTERM via `trap`).
* All enumeration is **passive only**. No bruteforce, no DNS resolver
  hammering, no port scanning. Stays well within bug-bounty scope rules.
