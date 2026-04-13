+++
title = 'ACME Clients'
weight = 40
BookToC = true
+++

# ACME Clients

This guide covers installation and system-level configuration of ACME clients for use with acme-proxy. It is intended for system administrators deploying certificate automation on behalf of end users.

For certificate issuance commands and per-scenario usage, see [user.md](./user.md).

---

## Table of Contents

- [Installing ACME Clients](#installing-acme-clients)
- [Account Registration](#account-registration)
- [Configuring Auto-Renewal via Systemd](#configuring-auto-renewal-via-systemd)
- [Log Management](#log-management)

---

## Installing ACME Clients

### Certbot

> **Note:** Certbot's actively maintained distribution is via Snap. The `.deb` packages available in apt repositories are no longer maintained by the Certbot project and ship outdated versions.

Install via Snap:

```bash
sudo snap install --classic certbot
sudo ln -s /snap/bin/certbot /usr/local/bin/certbot
```

The Snap package installs `certbot.timer` and `certbot.service` systemd units automatically.

For the NGINX plugin:

```bash
sudo snap set certbot trust-plugin-with-root=ok
sudo snap install certbot-nginx
```

For the Apache plugin:

```bash
sudo snap set certbot trust-plugin-with-root=ok
sudo snap install certbot-apache
```

---

### acme.sh

**Debian / Ubuntu:**

```bash
sudo apt-get update
sudo apt-get install -y acme.sh socat
```

**RHEL / Rocky / AlmaLinux** — requires EPEL:

```bash
sudo dnf install -y epel-release
sudo dnf install -y acme.sh socat
```

The package installs the binary to `/usr/bin/acme.sh`. Use `/etc/acme.sh` as the configuration home for system-wide installations (passed via `--home` in all commands).

> **`socat` is required for standalone mode.** acme.sh uses `socat` to bind port 80 for HTTP-01 challenges in standalone mode. It is installed above alongside acme.sh. This is not required if you use NGINX or Apache plugin mode.

---

### Lego

Lego has no official packages in major Linux distribution repositories. Install the release binary directly:

```bash
LEGO_VERSION=4.33.0
curl -fsSL "https://github.com/go-acme/lego/releases/download/v${LEGO_VERSION}/lego_v${LEGO_VERSION}_linux_amd64.tar.gz" \
  | tar xz lego
sudo install -o root -g root -m 0755 lego /usr/local/bin/lego
rm lego
lego --version
```

> Verify the checksum from the [GitHub releases page](https://github.com/go-acme/lego/releases) before deploying to production. Pin `LEGO_VERSION` in your configuration management tool and treat upgrades as a deliberate change.

---

## Account Registration

Each ACME client must register an account with acme-proxy before any certificates can be issued. This is a one-time step per host.

### Certbot

Certbot registers automatically on first use. No separate registration step is required.

### acme.sh

```bash
sudo acme.sh --register-account \
  --server https://acme-proxy.example.com/acme/acme/directory \
  --email admin@example.com \
  --home /etc/acme.sh
```

### Lego

Lego registers automatically on the first `run` invocation. No separate registration step is required.

---

## Configuring Auto-Renewal via Systemd

Replacing cron-based renewal with systemd timers provides:

- Missed-run recovery via `Persistent=true` — if the system was off at the scheduled time, the timer fires on next boot.
- Structured log output to the systemd journal, queryable and forwardable to syslog.
- Visibility via `systemctl list-timers`.

All service units below set `SyslogIdentifier` so logs can be filtered by tag regardless of which syslog daemon is in use.

---

### Certbot

The Snap-installed certbot ships `certbot.timer` and `certbot.service` units automatically. Enable the timer and confirm it is active:

```bash
sudo systemctl enable --now certbot.timer
systemctl status certbot.timer
```

**Configure the SyslogIdentifier** so certbot's renewal logs are tagged consistently alongside other ACME clients:

```bash
sudo mkdir -p /etc/systemd/system/certbot.service.d
sudo tee /etc/systemd/system/certbot.service.d/logging.conf <<'EOF'
[Service]
StandardOutput=journal
StandardError=journal
SyslogIdentifier=certbot-renewal
EOF
sudo systemctl daemon-reload
```

**Test renewal without issuing:**

```bash
sudo certbot renew --dry-run
```

---

### acme.sh

acme.sh's `--cron` flag iterates over all configured certificates and renews those expiring within 30 days. A single service and timer unit covers all certificates on the host.

**Create the service unit:**

```bash
sudo tee /etc/systemd/system/acme-renewal.service <<'EOF'
[Unit]
Description=Renew ACME certificates (acme.sh)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=root
ExecStart=/usr/bin/acme.sh --cron --home /etc/acme.sh
StandardOutput=journal
StandardError=journal
SyslogIdentifier=acme-renewal
EOF
```

**Create the timer unit:**

```bash
sudo tee /etc/systemd/system/acme-renewal.timer <<'EOF'
[Unit]
Description=Daily ACME certificate renewal check (acme.sh)

[Timer]
OnCalendar=daily
RandomizedDelaySec=1h
Persistent=true

[Install]
WantedBy=timers.target
EOF
```

**Enable and start:**

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now acme-renewal.timer
```

**Verify:**

```bash
systemctl status acme-renewal.timer
systemctl list-timers acme-renewal.timer
```

---

### Lego

Lego has no built-in renewal scheduling. Create service and timer units manually.

Unlike acme.sh and certbot, lego's `renew` command targets one domain at a time. If you manage multiple certificates, use a wrapper script.

**Wrapper script for multiple certificates:**

```bash
sudo tee /usr/local/sbin/lego-renew-all.sh <<'EOF'
#!/bin/bash
set -euo pipefail

LEGO=/usr/local/bin/lego
SERVER=https://acme-proxy.example.com/acme/acme/directory
EMAIL=admin@example.com

# Add each managed domain below
domains=(
  myserver.example.com
  anotherserver.example.com
)

for domain in "${domains[@]}"; do
  "$LEGO" \
    --server "$SERVER" \
    --accept-tos \
    --email "$EMAIL" \
    --http \
    -d "$domain" \
    renew
done
EOF
sudo chmod 0700 /usr/local/sbin/lego-renew-all.sh
```

**Create the service unit:**

```bash
sudo tee /etc/systemd/system/lego-renewal.service <<'EOF'
[Unit]
Description=Renew ACME certificates (lego)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=root
ExecStart=/usr/local/sbin/lego-renew-all.sh
StandardOutput=journal
StandardError=journal
SyslogIdentifier=lego-renewal
EOF
```

**Create the timer unit:**

```bash
sudo tee /etc/systemd/system/lego-renewal.timer <<'EOF'
[Unit]
Description=Daily ACME certificate renewal check (lego)

[Timer]
OnCalendar=daily
RandomizedDelaySec=1h
Persistent=true

[Install]
WantedBy=timers.target
EOF
```

**Enable and start:**

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now lego-renewal.timer
```

**Verify:**

```bash
systemctl status lego-renewal.timer
systemctl list-timers lego-renewal.timer
```

---

## Log Management

All service units above write to the systemd journal with a unique `SyslogIdentifier`. Logs are accessible via `journalctl` and forwarded to syslog if your system runs rsyslog or syslog-ng with journal forwarding enabled.

**Filter renewal logs by client:**

| Client  | Command                               |
|---------|---------------------------------------|
| Certbot | `journalctl -t certbot-renewal`       |
| acme.sh | `journalctl -t acme-renewal`          |
| Lego    | `journalctl -t lego-renewal`          |

**Follow logs in real time:**

```bash
journalctl -t acme-renewal -f
```

**Forward to syslog — rsyslog:**

Ensure the journal input module is loaded in `/etc/rsyslog.conf` or a drop-in under `/etc/rsyslog.d/`:

```
module(load="imjournal" StateFile="imjournal.state")
```

**Forward to syslog — syslog-ng:**

Ensure the `systemd-journal` source is present in your syslog-ng configuration:

```
source s_systemd { systemd-journal(); };
```

**Log retention:**

Journal retention is controlled by `/etc/systemd/journald.conf`. Set `MaxRetentionSec` and `SystemMaxUse` appropriate to your environment:

```ini
[Journal]
SystemMaxUse=500M
MaxRetentionSec=90day
```

Apply changes with:

```bash
sudo systemctl restart systemd-journald
```
