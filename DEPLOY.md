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

Alternatively, `scripts/setup-env.sh` is an interactive generator that asks for
the domain whose DNS you control, generates a random `TOKEN_SECRET`, and writes a
valid `.env` (existing files are backed up to `.env.bak.<timestamp>`). It also
prints a DNS checklist for the mail domain.

```bash
bash scripts/setup-env.sh                            # writes ./.env
bash scripts/setup-env.sh /etc/astraccounts.env      # or a specific path
```

It is a convenience for getting a working file quickly. Its comments go on their
own lines, so it is safe as a systemd `EnvironmentFile`, but it leaves the mail
listeners at their standard ports (`:25`, `:587`, ...). Production behind nginx
runs non-root, so set `GIN_MODE=release` and override the `MAIL_*_ADDR` values as
in the block below.

> **systemd note:** `EnvironmentFile=` does **not** support inline comments. A
> line like `MAIL_SMTP_ADDR=:25  # MX` sets the value to `:25  # MX`, which then
> fails to bind. The shipped `.env.example` uses inline comments on the mail
> listener lines (godotenv accepts them), so replace those lines with the
> comment-free block below rather than copying the file verbatim.

**Required settings for production:**

```env
# Core
GIN_MODE=release
# Trusted proxy IPs/CIDRs. nginx runs on localhost; add your load balancer CIDR
# if there is one in front of nginx.
GIN_TRUSTED_PROXIES=127.0.0.1,::1
TOKEN_VALID_SECS=3600
# Generate the value with: openssl rand -hex 32
TOKEN_SECRET=
ALLOWED_PROFILE_KEY=bio:string,secret:string:private

# Mail is optional: remove or blank MAIL_DOMAIN to disable it.
# Email addresses are user@mail.example.com
MAIL_DOMAIN=mail.example.com
# SMTP banner: 220 mx.example.com ESMTP
MAIL_HOSTNAME=mx.example.com
# Also accept mail for user@example.com
MAIL_EXTRA_DOMAINS=example.com

# Listeners use unprivileged ports because the service runs as non-root.
MAIL_SMTP_ADDR=127.0.0.1:2525
MAIL_SUBMISSION_ADDR=127.0.0.1:5587
MAIL_SUBMISSION_TLS_ADDR=off
MAIL_POP3_ADDR=127.0.0.1:1110
MAIL_POP3_TLS_ADDR=off
MAIL_IMAP_ADDR=127.0.0.1:1143
MAIL_IMAP_TLS_ADDR=off

# TLS certificate shared by all mail listeners, used for STARTTLS.
MAIL_TLS_CERT_FILE=/etc/ssl/certs/astraccounts.pem
MAIL_TLS_KEY_FILE=/etc/ssl/private/astraccounts.key

# Relay and outbound
MAIL_RELAY=true
# Empty = direct MX delivery
MAIL_SMARTHOST_ADDR=
# Use these if outbound port 25 is blocked:
# MAIL_SMARTHOST_ADDR=smtp.provider.com:587
# MAIL_SMARTHOST_USER=user
# MAIL_SMARTHOST_PASSWORD=pass

# DKIM signing. Use the domain mail is actually sent from (MAIL_DOMAIN) so the
# DKIM signature is aligned with the From header.
MAIL_DKIM_DOMAIN=mail.example.com
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
# default._domainkey.mail.example.com IN TXT "v=DKIM1; k=rsa; p=<public-key>"
openssl rsa -in /etc/astraccounts/dkim.key -pubout -outform der | openssl base64 -A
```

## 4. TLS certificate

Use Let's Encrypt via certbot or your existing certificate workflow. One
certificate covers every hostname clients connect to and is used by:
- nginx, for HTTPS on the HTTP API
- Astraccounts, for STARTTLS (and any implicit-TLS ports) on the mail listeners

Get certificates for all hostnames clients will connect to:

```bash
sudo certbot certonly --standalone \
  -d api.example.com \
  -d mail.example.com \
  -d mx.example.com
# certbot names the lineage after the FIRST -d, so the files live under
# /etc/letsencrypt/live/api.example.com/ and the cert carries a SAN for all
# three names.
sudo cp /etc/letsencrypt/live/api.example.com/fullchain.pem /etc/ssl/certs/astraccounts.pem
sudo cp /etc/letsencrypt/live/api.example.com/privkey.pem   /etc/ssl/private/astraccounts.key
sudo chown astraccounts:astraccounts /etc/ssl/certs/astraccounts.pem /etc/ssl/private/astraccounts.key
sudo chmod 644 /etc/ssl/certs/astraccounts.pem
sudo chmod 600 /etc/ssl/private/astraccounts.key
```

Do **not** concatenate the private key into the certificate file: the cert file
is world-readable (`chmod 644`), while the key must stay `600`.

nginx (HTTP) uses the same lineage directly, from
`/etc/letsencrypt/live/api.example.com/`.

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
```

The mail protocols are forwarded through nginx's **stream** module, and only so
that nginx can bind the privileged ports (<1024) while Astraccounts stays
non-root. Create `/etc/nginx/stream-astraccounts.conf` — it must be included from
`nginx.conf` inside a `stream {}` block, not from `http {}`:

```nginx
# /etc/nginx/stream-astraccounts.conf
stream {
    # Astraccounts offers STARTTLS itself, using MAIL_TLS_CERT_FILE. These must
    # therefore be plain TCP proxies:
    #   * no `ssl`: if nginx terminated TLS, Astraccounts would see the backend
    #     connection as unencrypted. With a certificate configured,
    #     AllowInsecureAuth is false, so SMTP/IMAP AUTH would be refused and
    #     STARTTLS clients would break.
    #   * no `proxy_protocol on;`: Astraccounts does not parse the PROXY
    #     protocol; the injected header would be fed to the mail parser.
    # The trade-off is that Astraccounts sees nginx (127.0.0.1) as the peer, so
    # `Received` headers and logs show the proxy address. If the real client IP
    # matters, bind Astraccounts directly to the mail ports with setcap (see
    # section 7) instead of proxying them.

    # MX delivery (STARTTLS)
    server {
        listen 25;
        listen [::]:25;
        proxy_pass 127.0.0.1:2525;
    }

    # Authenticated submission (STARTTLS)
    server {
        listen 587;
        listen [::]:587;
        proxy_pass 127.0.0.1:5587;
    }

    # POP3 (STLS)
    server {
        listen 110;
        listen [::]:110;
        proxy_pass 127.0.0.1:1110;
    }

    # IMAP (STARTTLS)
    server {
        listen 143;
        listen [::]:143;
        proxy_pass 127.0.0.1:1143;
    }
}
```

Enable and reload:

```bash
# HTTP config (sites-enabled)
sudo ln -s /etc/nginx/sites-available/astraccounts /etc/nginx/sites-enabled/

# The stream config was created above at /etc/nginx/stream-astraccounts.conf.
# Add it to nginx.conf in the main context:
#   include /etc/nginx/stream-astraccounts.conf;

sudo nginx -t
sudo systemctl reload nginx
```

**Important:** This requires nginx built with the stream module. Check with
`nginx -V 2>&1 | grep -- --with-stream`. Some distros ship it as a separate
package or dynamic module.

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
# Implicit-TLS ports are disabled in .env; open 465/995/993 only if you enable them
sudo ufw enable
```

If you run Astraccounts directly on privileged ports (not recommended), you'd need `setcap`:

```bash
sudo setcap 'cap_net_bind_service=+ep' /usr/local/bin/astraccounts
# Then change MAIL_*_ADDR to :25, :587, :110, :143, :465, :993, :995
```

## 8. Mail domain, hostname, and DNS — explained

### What the three settings mean

| Setting | Purpose | Example |
|---------|---------|---------|
| `MAIL_DOMAIN` | The domain in users' email addresses. If `MAIL_DOMAIN=mail.example.com`, user `alice` gets `alice@mail.example.com`. | `mail.example.com` |
| `MAIL_HOSTNAME` | The name this server announces in the SMTP banner (`220 mx.example.com ESMTP`) and in `Received` headers. It's the server's identity. | `mx.example.com` |
| `MAIL_EXTRA_DOMAINS` | Additional domains this server treats as local. If you also want `alice@example.com` to deliver here (not just `alice@mail.example.com`), add it here. | `example.com,mail.example.com` |

**Rule of thumb:** `MAIL_HOSTNAME` is an A record clients connect to. `MAIL_DOMAIN` is the domain part of email addresses. They can be the same or different.

---

### Recommended DNS for the example above

With:
```
MAIL_DOMAIN=mail.example.com
MAIL_HOSTNAME=mx.example.com
MAIL_EXTRA_DOMAINS=example.com
```

You need these DNS records:

| Type | Name | Value | Notes |
|------|------|-------|-------|
| A | mx | <your-server-IP> | The hostname mail clients and other MTAs connect to |
| A | mail | <your-server-IP> | Optional alias; nginx listens here for submission/IMAP/POP3 |
| A | api | <your-server-IP> | Your HTTP API hostname |
| MX | @ | mx.example.com (priority 10) | Tells the world where mail for `example.com` goes |
| MX | mail | mx.example.com (priority 10) | Mail for `mail.example.com` also goes here |
| TXT | @ | "v=spf1 mx ~all" | SPF for example.com |
| TXT | mail | "v=spf1 mx ~all" | SPF for mail.example.com |
| TXT | default._domainkey.mail | "v=DKIM1; k=rsa; p=<public-key>" | DKIM for mail.example.com (must match `MAIL_DKIM_DOMAIN`) |
| TXT | _dmarc | "v=DMARC1; p=none; rua=mailto:dmarc@example.com" | DMARC for example.com |
| TXT | _dmarc.mail | "v=DMARC1; p=none; rua=mailto:dmarc@example.com" | DMARC for mail.example.com |

**Why two MX records?**  
- `@` (the apex `example.com`) handles mail to `user@example.com` (via `MAIL_EXTRA_DOMAINS`)  
- `mail` handles mail to `user@mail.example.com` (via `MAIL_DOMAIN`)

Both point to `mx.example.com`, which is the actual server host.

---

### Simpler variant: single domain

If you only want one domain for everything (web, mail, API), just use:

```
MAIL_DOMAIN=example.com
MAIL_HOSTNAME=mx.example.com
MAIL_EXTRA_DOMAINS=
```

DNS:
| Type | Name | Value |
|------|------|-------|
| A | mx | <your-server-IP> |
| A | api | <your-server-IP> |
| MX | @ | mx.example.com |
| TXT | @ | "v=spf1 mx ~all" |
| TXT | default._domainkey | "v=DKIM1; k=rsa; p=<public-key>" |
| TXT | _dmarc | "v=DMARC1; p=none; rua=mailto:dmarc@example.com" |

## 9. Monitoring

The service logs to stdout as `[YYYY-MM-DD HH:MM:SS] [LEVEL] message key=value`
(with ANSI colors). Ship logs to your aggregator (Loki, Elasticsearch, etc.):

```bash
# Follow the service logs
journalctl -u astraccounts -f

# Or as journald JSON, if your pipeline wants it
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

Data is written relative to `WorkingDirectory` (section 5), so it lives under
`/var/lib/astraccounts/data/`:

- `data/user/<UID>/user.json` — accounts and profiles
- `data/user/<UID>/mail/` — mailboxes and indexes
- `data/queue/` — outbound mail queue (transient)

## 11. Upgrading

```bash
sudo systemctl stop astraccounts
cp new-astraccounts /usr/local/bin/astraccounts
sudo systemctl start astraccounts
```

No migrations; the on-disk format is forward-compatible. Replacing the binary
drops any file capabilities, so if you bound privileged ports with `setcap`
(section 7) re-apply it: `sudo setcap 'cap_net_bind_service=+ep' /usr/local/bin/astraccounts`.

## 12. Troubleshooting

| Symptom | Check |
|---------|-------|
| Service exits immediately | `journalctl -u astraccounts` — usually bad `.env` (invalid domain, missing TLS files) |
| Listener address includes a `#comment` | systemd `EnvironmentFile=` keeps inline comments; put comments on their own lines |
| `502` / "TLS is required" on submission | Client must send EHLO before MAIL FROM. Do not terminate TLS in nginx; Astraccounts must see the TLS session or AUTH is refused |
| Mail not delivered externally | `MAIL_RELAY=true`, port 25 outbound open, valid DKIM, SPF/DMARC in DNS |
| IMAP/POP3 connection refused | Listener addresses in `.env` match nginx `proxy_pass` |
| "Invalid GIN_TRUSTED_PROXIES" | Must be valid CIDR/IP; empty = no proxies trusted |

## 13. Running without mail

Simply omit `MAIL_DOMAIN` from `/etc/astraccounts.env` (or set it empty). The service runs as a pure HTTP account server on port 8080.