# Deploying Astraccounts on Linux

This guide covers production deployment on a Linux server with systemd, nginx as a reverse proxy, and proper mail server integration.

## 1. Build the binary

```bash
# On the build machine (or CI)
GOOS=linux GOARCH=amd64 go build -o astraccounts .
# Or build directly on the target
go build -o astraccounts .
```

The binary is ~30 MB, statically linked except for libc. Copy it to `/usr/local/bin/astraccounts` on the target.

## 2. Create a service user and data directory

```bash
sudo useradd --system --home-dir /var/lib/astraccounts --shell /usr/sbin/nologin astraccounts
sudo mkdir -p /var/lib/astraccounts
sudo chown astraccounts:astraccounts /var/lib/astraccounts
```

The service runs as this user; all runtime data (user accounts, mailboxes, mail queue) lives under `/var/lib/astraccounts`.

## 3. Configure environment

Copy `.env.example` to `/etc/astraccounts.env` and edit:

```bash
sudo cp .env.example /etc/astraccounts.env
sudo chown astraccounts:astraccounts /etc/astraccounts.env
sudo chmod 600 /etc/astraccounts.env
```

**Required settings for production:**

```env
# Core
GIN_MODE=release
GIN_TRUSTED_PROXIES=127.0.0.1,::1,<your-server-IP>  # or your load balancer CIDR
TOKEN_VALID_SECS=3600
TOKEN_SECRET=<generate with: openssl rand -hex 32>
ALLOWED_PROFILE_KEY=bio:string,secret:string:private

# Mail (optional — remove MAIL_DOMAIN to disable)
MAIL_DOMAIN=mail.example.com
MAIL_HOSTNAME=mx.example.com
MAIL_EXTRA_DOMAINS=example.com,mail.example.com

# Listeners — use unprivileged ports since the service runs as non-root
MAIL_SMTP_ADDR=127.0.0.1:2525          # MX delivery
MAIL_SUBMISSION_ADDR=127.0.0.1:5587    # Authenticated submission (STARTTLS)
MAIL_SUBMISSION_TLS_ADDR=off           # Implicit TLS off (handled by nginx)
MAIL_POP3_ADDR=127.0.0.1:1110
MAIL_POP3_TLS_ADDR=off
MAIL_IMAP_ADDR=127.0.0.1:1143
MAIL_IMAP_TLS_ADDR=off

# TLS certificate (shared by all mail listeners)
MAIL_TLS_CERT_FILE=/etc/ssl/certs/astraccounts.pem
MAIL_TLS_KEY_FILE=/etc/ssl/private/astraccounts.key

# Relay and outbound
MAIL_RELAY=true
MAIL_SMARTHOST_ADDR=                    # Empty = direct MX delivery
# MAIL_SMARTHOST_ADDR=smtp.provider.com:587  # Use this if port 25 is blocked
# MAIL_SMARTHOST_USER=user
# MAIL_SMARTHOST_PASSWORD=pass

# DKIM signing
MAIL_DKIM_DOMAIN=example.com
MAIL_DKIM_SELECTOR=default
MAIL_DKIM_KEY_FILE=/etc/astraccounts/dkim.key
```

Generate the DKIM key:

```bash
sudo mkdir -p /etc/astraccounts
openssl genrsa -out /etc/astraccounts/dkim.key 2048
sudo chown astraccounts:astraccounts /etc/astraccounts/dkim.key
sudo chmod 600 /etc/astraccounts/dkim.key
# The public key goes in your DNS as a TXT record:
# default._domainkey.example.com IN TXT "v=DKIM1; k=rsa; p=<public-key>"
openssl rsa -in /etc/astraccounts/dkim.key -pubout -outform der | openssl base64 -A
```

## 4. TLS certificate

Use Let's Encrypt via certbot or your existing certificate workflow. The same cert/key is used by:
- nginx (HTTPS for HTTP API + STARTTLS for mail submission/POP3/IMAP)
- Astraccounts mail server (STARTTLS on 2525/5587/1110/1143)

```bash
sudo certbot certonly --standalone -d mail.example.com
# Certs land in /etc/letsencrypt/live/mail.example.com/
# Combine for Astraccounts:
sudo cat /etc/letsencrypt/live/mail.example.com/fullchain.pem /etc/letsencrypt/live/mail.example.com/privkey.pem > /etc/ssl/certs/astraccounts.pem
sudo cp /etc/letsencrypt/live/mail.example.com/privkey.pem /etc/ssl/private/astraccounts.key
sudo chown astraccounts:astraccounts /etc/ssl/certs/astraccounts.pem /etc/ssl/private/astraccounts.key
sudo chmod 644 /etc/ssl/certs/astraccounts.pem
sudo chmod 600 /etc/ssl/private/astraccounts.key
```

## 5. Systemd service

Create `/etc/systemd/system/astraccounts.service`:

```ini
[Unit]
Description=Astraccounts account + mail server
After=network.target
Wants=network.target

[Service]
Type=simple
User=astraccounts
Group=astraccounts
WorkingDirectory=/var/lib/astraccounts
EnvironmentFile=/etc/astraccounts.env
ExecStart=/usr/local/bin/astraccounts
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

# Hardening
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/astraccounts
NoNewPrivileges=true
CapabilityBoundingSet=

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now astraccounts
sudo systemctl status astraccounts
```

Check logs:

```bash
journalctl -u astraccounts -f
```

## 6. Nginx reverse proxy

Install nginx and create `/etc/nginx/sites-available/astraccounts`:

```nginx
# HTTP API
server {
    listen 80;
    listen [::]:80;
    server_name api.example.com;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

# HTTPS API (certbot will add this)
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name api.example.com;

    ssl_certificate /etc/letsencrypt/live/api.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/api.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

# Mail submission (port 587 with STARTTLS) — nginx terminates TLS
server {
    listen 587 ssl;
    listen [::]:587 ssl;
    server_name mail.example.com;

    ssl_certificate /etc/letsencrypt/live/mail.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/mail.example.com/privkey.pem;

    proxy_pass 127.0.0.1:5587;
    proxy_protocol on;
}

# IMAP (port 143 with STARTTLS) — nginx terminates TLS
server {
    listen 143 ssl;
    listen [::]:143 ssl;
    server_name mail.example.com;

    ssl_certificate /etc/letsencrypt/live/mail.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/mail.example.com/privkey.pem;

    proxy_pass 127.0.0.1:1143;
    proxy_protocol on;
}

# POP3 (port 110 with STLS) — nginx terminates TLS
server {
    listen 110 ssl;
    listen [::]:110 ssl;
    server_name mail.example.com;

    ssl_certificate /etc/letsencrypt/live/mail.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/mail.example.com/privkey.pem;

    proxy_pass 127.0.0.1:1110;
    proxy_protocol on;
}

# MX delivery (port 25) — nginx terminates TLS and forwards to astraccounts:2525
# Most MTAs expect STARTTLS on 25. If you want to terminate TLS here:
server {
    listen 25 ssl;
    listen [::]:25 ssl;
    server_name mail.example.com;

    ssl_certificate /etc/letsencrypt/live/mail.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/mail.example.com/privkey.pem;

    proxy_pass 127.0.0.1:2525;
    proxy_protocol on;
}
```

Enable and reload:

```bash
sudo ln -s /etc/nginx/sites-available/astraccounts /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

**Important:** The mail listeners in Astraccounts expect the `proxy_protocol` header so they see the real client IP in `Received` headers. The nginx config above uses `proxy_protocol on;` which requires nginx compiled with `--with-stream_ssl_preread_module` (standard in most distros).

## 7. Firewall

```bash
# HTTP API
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Mail
sudo ufw allow 25/tcp    # MX delivery
sudo ufw allow 587/tcp   # Submission
sudo ufw allow 110/tcp   # POP3
sudo ufw allow 143/tcp   # IMAP
# Implicit TLS ports not used (handled by nginx on standard ports)
sudo ufw enable
```

If you run Astraccounts directly on privileged ports (not recommended), you'd need `setcap`:

```bash
sudo setcap 'cap_net_bind_service=+ep' /usr/local/bin/astraccounts
# Then change MAIL_*_ADDR to :25, :587, :110, :143, :465, :993, :995
```

## 8. DNS records

| Type | Name | Value |
|------|------|-------|
| A | mail | <your-server-IP> |
| A | api | <your-server-IP> |
| MX | @ | mail.example.com (priority 10) |
| TXT | @ | "v=spf1 mx ~all" |
| TXT | default._domainkey | "v=DKIM1; k=rsa; p=<public-key>" |
| TXT | _dmarc | "v=DMARC1; p=none; rua=mailto:dmarc@example.com" |

## 9. Monitoring

The service logs structured JSON to stdout. Ship logs to your log aggregator (Loki, Elasticsearch, etc.):

```bash
# Example: journalctl with JSON output
journalctl -u astraccounts -o json -f
```

Key log fields to alert on:
- `level=ERROR` — any error
- `msg="Failed to register user"` — registration failures
- `msg="Failed to deliver mail"` — mail delivery issues
- `msg="Failed to queue outbound mail"` — relay problems

## 10. Backup

```bash
# Daily backup of /var/lib/astraccounts
tar -czf /backup/astraccounts-$(date +%F).tar.gz -C /var/lib astraccounts
```

The data directory contains:
- `user/<UID>/user.json` — accounts and profiles
- `user/<UID>/mail/` — mailboxes and indexes
- `queue/` — outbound mail queue (transient)

## 11. Upgrading

```bash
sudo systemctl stop astraccounts
cp new-astraccounts /usr/local/bin/astraccounts
sudo systemctl start astraccounts
```

No migrations; the on-disk format is forward-compatible.

## 12. Troubleshooting

| Symptom | Check |
|---------|-------|
| Service exits immediately | `journalctl -u astraccounts` — usually bad `.env` (invalid domain, missing TLS files) |
| "TLS is required" on submission | Client didn't send EHLO; nginx `proxy_protocol` not configured |
| Mail not delivered externally | `MAIL_RELAY=true`, port 25 outbound open, valid DKIM, SPF/DMARC in DNS |
| IMAP/POP3 connection refused | Listener addresses in `.env` match nginx `proxy_pass` |
| "Invalid GIN_TRUSTED_PROXIES" | Must be valid CIDR/IP; empty = no proxies trusted |

## 13. Running without mail

Simply omit `MAIL_DOMAIN` from `/etc/astraccounts.env` (or set it empty). The service runs as a pure HTTP account server on port 8080.