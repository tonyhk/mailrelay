# mailrelay: Go rewrite plan

Status (2026-11-23): first port done and tested (Go sources at the repo root, `relay_test.go` integration tests,
Dockerfile now builds the Go image, 24.6 MB). Not yet committed. The Python sources are still in the repo for comparison;
delete them (`*.py`, `requirements.txt`) once the Go build has run in production for a while.
Differences: LOGIN/PLAIN only for upstream AUTH (no CRAM-MD5); TLS 1.0/1.1 clients get ECDHE-CBC suites only
(Go 1.27 removed RSA key exchange); generic error texts differ from Python exception names.

Repo: https://github.com/tonyhk/mailrelay, local at `C:\code\mailrelay`. The Python sources sit at the repo root
(flat layout); the Dockerfile copies `*.py dashboard.html` into `/app/mailrelay/`.

## Goal
Port the Python app to Go as a drop-in replacement, for lower memory use, a small static image and stability.

## Must stay compatible
- Env vars `MAILRELAY_*` and `SMTP_<n>_*` (incl. `_FILE` secrets) and `config.toml` (`[app]` + `[[upstream]]`).
- SQLite `mailrelay.db`: tables `smtp_log`, `messages`, `settings` (key -> JSON value), `relay_users`
  (password hash `pbkdf2_sha256$<iter>$<salthex>$<dkhex>`). Add missing columns like the Python `_ensure`.
- Queue dir: `<relay_id>.eml` + `<relay_id>.json` {mail_from, rcpts, meta, attempt, first_seen, next_try, upstream}.
- JSONL attempt log + stdout JSON lines (`{"event":"smtp_attempt", ...}`).
- Web/API: `/health`, `/api/overview`, `/api/messages[/<id>]`, `/api/attempts`, `/api/queue/retry`, `/api/send`,
  `/api/reply`, `/api/settings` (GET/PUT), `/api/settings/reset`, `/api/users` (POST), `/api/users/<name>` (DELETE).
  Basic auth (admin) or Bearer token; settings endpoints require `Content-Type: application/json`.
- Same `dashboard.html` (embedded).
- CLI: `serve`, `messages`, `attempts`, `show <id>`, `queue` with the same flags.
- Runtime settings (UI overrides env): allowed_networks, require_auth, allowed_sender_domains, max_recipients,
  rewrite_from, from_address, from_name, retry_minutes, queue_max_age_hours. Guards: no /0 networks; no
  require_auth without an enabled user.
- TLS: own cert, or self-signed RSA 2048 in `<data>/tls/` (renew <30 days or names changed), TLS_SANS,
  TLS_MIN_VERSION, AUTH_REQUIRE_TLS. SMTP AUTH always offered; "require login" enforced at MAIL.
- Upstream delivery: failover in order; 5xx at RCPT/DATA = permanent (bounce), else next upstream / queue with
  retry schedule; record banner, upstream IP, TLS version, stage of failure, duration.

## Planned libraries
github.com/emersion/go-smtp (server), own small textproto client for upstream (needs banner/stage capture),
modernc.org/sqlite (pure Go, no CGO), github.com/BurntSushi/toml; stdlib for HTTP, x509, crypto/pbkdf2 (Go 1.24).

## Image
Multi-stage build -> static binary in distroless/static (has CA certs); run as UID 1000 so existing volumes work;
`mailrelay healthcheck` subcommand replaces the Python healthcheck. Keep the GitHub Actions workflow + smoke test.

## Testing before touching the repo
Re-run the earlier checks (relay allow/deny, AUTH, require_auth, settings API, persistence across restart,
self-signed STARTTLS, TLS 1.0 option) and open a database created by the Python version.
