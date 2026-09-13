# AGENTS.md

Astraccounts: a single-binary Go/Gin account service. Users are stored as one JSON
file per user on local disk. No database, no CI, no migrations.

## Verification loop

```powershell
go vet ./...
go test ./...
```

- Only `auth` has tests (`auth/totp_test.go`); `main` and `logger` have none.
- Single test: `go test ./auth -run TestRecoveryCodeConsume -v`
- Tests are hermetic — `NewUserStore(t.TempDir())`, no server or network needed.
  `go test ./auth` takes ~2.5s because bcrypt hashing dominates; that is normal,
  not a hang.
- The existing tests drive `UserStore` directly and re-implement the handler logic
  rather than calling the `gin.HandlerFunc`s. A green suite says nothing about
  handler behaviour — exercise changed endpoints with `scripts/test.py` or curl.
- `golangci-lint` is **not** configured (no `.golangci.yml`) and is not installed.
  Ignore the README's `golangci-lint run` instruction; `go vet` + `go test` is the
  real gate.

## Do not run `gofmt -w` or `go mod tidy` blindly

`core.autocrlf=true` is set globally, so the index is LF while the working tree is
CRLF for `main.go`, `auth/auth.go`, `go.mod`, `go.sum`, `.env.example`,
`scripts/test.py`, and `LICENSE`.

Consequences that will waste your time:

- `gofmt -l .` reports `main.go` and `auth/auth.go`. **They are already correctly
  formatted.** The only diff is CRLF. Running `gofmt -w` rewrites the whole file
  to LF and produces a several-hundred-line spurious diff.
- `go mod tidy -diff` prints a full-file diff of `go.sum`. Verified: tidy output is
  byte-identical to the committed files apart from line endings. `go.mod`/`go.sum`
  are already tidy — leave them alone.
- Before claiming a formatting or dependency problem, compare content ignoring
  line endings, or check `git status --short` (clean == nothing to fix).

The unused-looking indirect deps in `go.mod` (`go.mongodb.org/mongo-driver/v2`,
`quic-go`, `qpack`) are what `go mod tidy` itself produces. Do not remove them.

## Running it

```powershell
Copy-Item .env.example .env   # .env is gitignored
go run .
```

- The listen address `:8080` is **hardcoded** in `main.go:64-65`. There is no
  `PORT` env var; adding one means editing `main.go`.
- Data lands in `data/user/<UID>/user.json`, relative to the process CWD
  (`main.go:30`), created on first write. `data/` does not exist in a fresh clone.
- Misconfigured `GIN_TRUSTED_PROXIES` or `ALLOWED_PROFILE_KEY` makes `main` log an
  error and `return` (exit 0) instead of serving. A silent immediate exit means bad
  `.env`, not a crash.
- `TOKEN_SECRET` empty => random secret per start => every previously issued token
  breaks on restart.

### Windows build gotcha

`.gitignore` only ignores `Astraccounts.exe`.

- `go build` -> `Astraccounts.exe` (ignored, correct)
- `go build -o Astraccounts` (what the README says) -> extension-less
  `Astraccounts`, a 30 MB **untracked** binary. Don't use the README form here.

## Manual API testing

`python scripts/test.py [base_url]` is an interactive menu-driven client, stdlib
only, no pytest, not part of `go test`. It remembers the token from the last login
for the profile calls. Override the URL with `ASTRACCOUNTS_BASE_URL`. It requires a
TTY and a running server — never invoke it as an automated check.

## Layout and conventions

- `main.go` — env parsing, Gin setup, and the route table. Every route is
  registered here; a new endpoint needs a line in `main.go` plus a handler in
  `auth`.
- `auth/` — one package. `auth.go` (store + register/login), `token.go` (HMAC
  tokens), `profile.go` (`ALLOWED_PROFILE_KEY` schema), `totp.go` (TOTP + recovery
  codes). `UserStore` is the only disk gateway.
- `mail/` — one package. `config.go` (env parsing), `store.go` (per-user mailboxes
  on disk), `smtp.go` (MX + submission), `pop3.go` (RFC 1939), `imap.go` (go-imap
  v1 backend), `relay.go` (outbound queue, MX lookup, DKIM). `Store` is the only
  disk gateway. Every mutation serialises through a mutex; message bodies are
  immutable files.
- `logger/` — slog handler with ANSI colors plus `GinLogger`/`GinRecovery`. Use
  `logger.Info/Warn/Error`, never `log` or `fmt.Print`.

Repo-specific API conventions (deviate from these and you break clients):

- Every response body carries a `status` field mirroring the HTTP status, e.g.
  `c.JSON(400, gin.H{"status": 400})`. Handlers use bare ints, not
  `http.StatusBadRequest`.
- Auth/validation failures are always `400`, never `401`/`403`/`404`. Unknown user
  and wrong password return the identical body to prevent account enumeration.
- Only `/api/register` returns `201`; only read/write failures return `500`.
- Numeric `err` codes are part of the public contract and are documented per
  endpoint in `APIS.md` and mirrored in `scripts/test.py`'s `REGISTER_ERRORS` /
  `TOTP_ERRORS` maps. Changing or adding one means updating both.

Implementation traps:

- JSON numbers decode to `float64`, so `profileTypeNumber` asserts `float64`
  (`auth/profile.go:139`). Asserting `int` silently rejects valid input.
- `profile.username` and `profile.register` are built-in (`builtinFields`) and
  always present; declaring either in `ALLOWED_PROFILE_KEY` is a startup error.
  `register` is immutable.
- `/api/profile/edit` validates every entry before writing anything — one bad key
  rejects the whole request with an `invalid` array. Keep it all-or-nothing.
- `UserStore.mu` is only held by `register`/`login`/`updateProfile`/
  `verifyPassword`. The TOTP handlers and `ProfileViewHandler` call
  `readUser`/`writeUser` with no lock held, and every write rewrites the whole
  `user.json`. Take `mu` in new write paths.
- `loadUsers()` rescans the entire directory on every register/login/TOTP lookup,
  so UID allocation is O(users). Fine at this scale; don't "optimize" it into a
  race.
- `TokenIssuer.Verify` splits from the right (`cutLast`) because a user ID may
  contain `_`. Don't switch to `strings.Split`.
- TOTP setup is two-phase: `/api/totp/sign` stores an unverified secret,
  `/api/totp/verify` activates it and issues 10 one-time recovery codes. A failed
  verify wipes the secret entirely. `/api/login/totp` rejects unverified secrets.
  Recovery codes are stored in plaintext in `user.json` (passwords are bcrypt).

Mail implementation traps:

- Mail is opt-in: with no `MAIL_DOMAIN` the service runs exactly as before.
  A silent immediate exit on startup means bad `.env`, not a crash.
- The MX listener (port 25) and submission listener (587) are separate and have
  different policies: MX never relays, submission only relays for authenticated
  users. This is what prevents an open relay.
- Submission requires EHLO before MAIL FROM. Clients that skip it get 502.
- IMAP backend uses go-imap v1 (stable); v2 is still beta and not used here.
- `Store.Append` materialises INBOX on demand — a user can be registered and
  immediately receive mail without any explicit provisioning step.
- UIDs are never reused: `UIDNext` only increments. EXPUNGE deletes the file and
  leaves a gap, which IMAP clients expect.
- The outbound queue serialises every retry through a single goroutine; the
  retry ladder is ~2 days (5m, 10m, 20m... capped at 6h). `MAIL_RELAY=false`
  disables it entirely.
- DKIM signing is additive: a signing failure logs a warning but the message is
  still sent unsigned, because an unsigned message is better than a bounced one.
- TLS cert is shared by all mail listeners. Without it, plaintext listeners run,
  STLS is offered on 25/587/110/143, and implicit-TLS ports (465/995/993) stay
  closed. A `WARN` is logged but it is not a startup error.
- `Received` headers use RFC 5321 address literal format `[IP]`, not `IP:port`.

## Docs and workflow

- `APIS.md` is the endpoint contract; `README.md` covers env vars. Update both when
  changing request/response shapes or configuration.
- Markdown in `README.md`/`APIS.md` has pre-existing `[url](url)`-mangled bare
  links. Leave them unless asked; don't bundle a cleanup into a feature change.
- Commits go straight to `main` (`git@github.com:TheAstrasTeam/Astraccounts.git`);
  no PR flow, no hooks. Messages follow Conventional Commits with a subsystem
  scope, e.g. `feat(totp): ...`, `fix(auth): ...`, `chore(auth): ...`.
- `opencode.json` is gitignored — it is local config, not a shared repo setting.
