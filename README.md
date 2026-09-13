# Astraccounts

Astraccounts is an account service providing user registration, login, login tokens, user profile editing, and profile viewing endpoints.

The project uses Go, Gin, and local JSON files to store user data.

## Features

- `GET /api/health` Health check
- `POST /api/register` User registration
- `POST /api/login` Login and retrieve token
- `POST /api/profile/edit` Modify own profile using a token
- `POST /api/profile/view` View public profile (users can view their own private fields)
- Bcrypt password hashing
- HMAC-SHA256 login tokens
- Gin request logging integrated with a unified colored logger
- `.env` support for configuring Gin mode, trusted proxies, token expiration, and profile fields
- **Built-in mail server (optional):** SMTP (MX + submission), POP3, IMAP with per-user mailboxes stored on disk. Every registered user automatically owns a mailbox at `<user-id>@MAIL_DOMAIN`. Supports STARTTLS, implicit TLS, DKIM signing, and smarthost relay.

For complete API specifications, see [APIS.md](APIS.md).

## Requirements

- Go `1.25.3` or compatible version
- Python `3.10+` (optional, only used for running interactive test scripts)

## Quick Start

Copy the environment variable template:

```bash
cp .env.example .env
```

Modify `.env` as needed, then start the service:

```bash
go run main.go
```

Default listening address:

```text
[http://127.0.0.1:8080](http://127.0.0.1:8080)
```

Check service status:

```bash
curl -s [http://127.0.0.1:8080/api/health](http://127.0.0.1:8080/api/health)
```

Expected response:

```json
{"status":200}
```

You can also build and run:

```bash
go build -o Astraccounts
./Astraccounts
```

## Environment Variables

`.env` is loaded on startup, but will not overwrite pre-existing system environment variables.

### `GIN_MODE`

Gin running mode. Options:

- `debug`
- `release`
- `test`

Default is `debug`. Invalid values log a `WARN` message and fall back to `debug`.

### `GIN_TRUSTED_PROXIES`

Comma-separated IP addresses or CIDR subnets used to configure Gin's trusted proxies:

```env
GIN_TRUSTED_PROXIES=127.0.0.1,::1,10.0.0.0/8
```

If unconfigured, no proxies are trusted. Invalid configurations log an error and stop execution.

### `TOKEN_VALID_SECS`

Token validity duration in seconds:

```env
TOKEN_VALID_SECS=3600
```

Default is `3600`. Must be a positive integer.

### `TOKEN_SECRET`

Secret key used for HMAC-SHA256 token signing:

```env
TOKEN_SECRET=replace-with-a-long-random-secret
```

If left empty, a random secret is generated on startup. This causes all previously issued tokens to become invalid after a service restart. A fixed random secret should be used in production environments.

### `ALLOWED_PROFILE_KEY`

Configures client-editable profile keys using the format:

```text
name:type[:visibility]
```

Multiple fields are separated by commas:

```env
ALLOWED_PROFILE_KEY=publicKey:string,publicBool:bool,publicNum:number,superSecretKey:string:private
```

Supported types:

- `string`
- `number`
- `bool`

Visibility options:

- `public`: Viewable by anonymous users (default)
- `private`: Viewable only by requests containing a valid token for the target user

`username` and `register` are built-in fields and cannot be configured or redeclared in `.env`:

- `profile.username`: Set by the system during registration; editable by the client afterwards
- `profile.register`: Set by the system during registration (Unix timestamp in seconds); not editable by the client

### Mail Server (`MAIL_*`)

The built-in mail server is opt-in. Set `MAIL_DOMAIN` to enable it. Every
registered user automatically owns a mailbox at `<user-id>@MAIL_DOMAIN`.

```env
# Required to enable the mail server
MAIL_DOMAIN=example.test

# Hostname advertised in SMTP banners (defaults to MAIL_DOMAIN)
MAIL_HOSTNAME=mx.example.test

# Listener addresses. Defaults are standard ports. Set to "off" to disable.
MAIL_SMTP_ADDR=:25
MAIL_SUBMISSION_ADDR=:587
MAIL_SUBMISSION_TLS_ADDR=:465
MAIL_POP3_ADDR=:110
MAIL_POP3_TLS_ADDR=:995
MAIL_IMAP_ADDR=:143
MAIL_IMAP_TLS_ADDR=:993

# TLS certificate for STARTTLS and implicit-TLS ports. Both required together.
MAIL_TLS_CERT_FILE=/path/to/cert.pem
MAIL_TLS_KEY_FILE=/path/to/key.pem

# Maximum message size in bytes (default 25 MB)
MAIL_MAX_MESSAGE_BYTES=26214400

# Allow relaying to external domains (default true)
MAIL_RELAY=true

# Smarthost for outbound delivery when port 25 is blocked
MAIL_SMARTHOST_ADDR=mail.provider.example:587
MAIL_SMARTHOST_USER=user
MAIL_SMARTHOST_PASSWORD=pass

# DKIM signing for outgoing mail
MAIL_DKIM_DOMAIN=example.test
MAIL_DKIM_SELECTOR=default
MAIL_DKIM_KEY_FILE=/path/to/dkim.key
```

See `.env.example` for the complete list with comments.

User data is stored at:

```text
data/user/[UID]/user.json
```

Mailboxes (when `MAIL_DOMAIN` is configured) are stored at:

```text
data/user/[UID]/mail/INBOX/index.json
data/user/[UID]/mail/INBOX/00000001.eml
...
```

Example user.json:

```json
{
  "id": "ExampleUser",
  "email": "user@example.com",
  "password": "$2a$10$...",
  "UID": 1,
  "profile": {
    "username": "Example",
    "register": 1788665697,
    "publicKey": "bruh"
  }
}
```

Passwords are stored as bcrypt hashes; plaintext passwords are never saved. `data/` is added to `.gitignore`.

## Python Test Script

The project includes an interactive Python test script with zero external dependencies:

```bash
python3 scripts/test.py
```

Features:

- Health check
- Registration
- Login with automatic token persistence
- Profile editing
- Viewing profile anonymously or with a token
- Modifying the target API URL

You can also specify the URL directly:

```bash
python3 scripts/test.py [http://127.0.0.1:8080](http://127.0.0.1:8080)
```

## Testing and Building

Run Go tests:

```bash
go test ./...
```

Run static analysis:

```bash
golangci-lint run
```

Build:

```bash
go build -o Astraccounts
```

## Logging

Log format:

```text
[YYYY-MM-DD HH:MM:SS] [LEVEL] message key=value
```

Log level colors:

- `INFO`: Blue
- `WARN`: Yellow
- `ERROR`: Red
- `DEBUG`: Gray

Gin request logs include HTTP method, path, status code, latency, and client IP, output using the same logger system.

## License

This project is licensed under the [Apache License 2.0](LICENSE).