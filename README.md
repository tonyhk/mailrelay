# mailrelay

An SMTP **mail relay**: your internal apps, servers, printers and NAS send mail to it on port 25
without needing provider credentials, and it forwards each message unchanged to your
**external SMTP server using authentication**. Every message is logged with the client it came
from, **which upstream server relayed it, the IP and banner of that server, and timestamps**,
and there is a **web overview** dashboard.

```
 apps / printers / NAS ──SMTP:25──▶ mailrelay ──SMTP AUTH (587 STARTTLS / 465 SSL)──▶ smtp.provider.com ──▶ recipients
                                       │
                                       ├─ disk queue + retries when the upstream is down
                                       └─ log (SQLite + JSONL + docker logs)  ─▶  web overview :8080
```

## How a message flows
1. A client connects to the relay. It is allowed if its IP is in `MAILRELAY_ALLOWED_NETWORKS`
   **or** it logs in with SMTP AUTH (`MAILRELAY_RELAY_USERS`). Anything else gets `554 Relay access denied`.
2. The relay adds a `Received:` header (with a relay ID) and, if `MAILRELAY_REWRITE_FROM=true`, rewrites the
   sender to your provider account. Otherwise the message is passed through byte for byte.
3. It immediately logs in to upstream `SMTP_1` and delivers. If that server is unreachable or fails
   (connect, TLS, auth, 4xx) it tries `SMTP_2`, and so on.
4. Result back to the client:
   - delivered: `250 Ok: queued as <relay-id>`
   - upstream rejects the message itself (5xx on recipient/data, e.g. unknown user): the client gets that `554` right away (status **bounced**)
   - all upstreams temporarily unavailable: `250` and the message waits in the disk queue (status **queued**), retried
     on `MAILRELAY_RETRY_MINUTES`, given up after `MAILRELAY_QUEUE_MAX_AGE_HOURS` (status **expired**).
     The queue is in the data volume, so it survives restarts.

## What is logged
**Per message**: relay ID, received time, client IP / HELO / SMTP user / TLS, envelope sender (and original if
rewritten), recipients, subject, Message-ID, size, final status, which upstream delivered it, upstream IP,
upstream reply (usually contains the provider's queue ID), number of attempts, next retry.

**Per delivery attempt**: timestamp (UTC, ms), upstream name/host/port, **connected IP**, **server greeting banner**,
TLS version, login user, SMTP code + reply or error (with the stage it failed at: connect/starttls/auth/mail/rcpt/data),
duration.

Stored in SQLite (`/app/data/mailrelay.db`), appended to `/app/data/smtp_log.jsonl`, and printed to
`docker logs` as one JSON line per attempt (ready for Loki/ELK). Passwords are never logged.

## Web overview (port 8080)
Log in with `MAILRELAY_ADMIN_USER` / `MAILRELAY_ADMIN_PASSWORD`. It shows:
- **Last 24 h:** received, relayed (with success rate), queued now, bounced and expired.
- **Each upstream server:** sent and failed counts, average delivery time, last IP and banner, last success and last error.
- **Top clients:** by IP and SMTP user.
- **Message list:** searchable and filterable; click a message to see its path (client → relay → upstream → recipients) and every attempt.
- **Retry queue now** button.
- **Settings** button: change relay settings at runtime (see below).

Refreshes every 10 s.

### Changing settings without a restart
The **Settings** dialog (or the `/api/settings` and `/api/users` API) changes these live; the next SMTP command
uses the new value:

| setting | env default |
|---|---|
| Allowed networks | `MAILRELAY_ALLOWED_NETWORKS` ⚙ |
| Require login | `MAILRELAY_REQUIRE_AUTH` ⚙ |
| Relay users (add, change password, disable, delete) | `MAILRELAY_RELAY_USERS` accounts are shown read-only |
| Allowed sender domains | `MAILRELAY_ALLOWED_SENDER_DOMAINS` ⚙ |
| Max recipients | `MAILRELAY_MAX_RECIPIENTS` |
| Rewrite From / From address / From name | `MAILRELAY_REWRITE_FROM`, `MAILRELAY_FROM_ADDRESS`, `MAILRELAY_FROM_NAME` |
| Retry schedule / queue max age | `MAILRELAY_RETRY_MINUTES`, `MAILRELAY_QUEUE_MAX_AGE_HOURS` |

The env value is only the default. Once a setting is saved in the UI it is stored in the database
(`data/mailrelay.db`, table `settings`) and overrides the env value, also after restarts, until you click
**reset to default**. The startup log lists which settings are overridden. Users created in the UI are
stored with a salted PBKDF2 hash. Every change is logged as `[settings] <who> set ...`.

Guards: `0.0.0.0/0` / `::/0` are refused (open relay), and "require login" cannot be turned on, nor the
last enabled user disabled/deleted, while that would lock every client out.

Ports, TLS certificates, upstream servers, max message size, storage paths and the admin login still come
from env / config.toml only and need a restart.

```bash
curl -u admin:$PW http://host:8080/api/settings
curl -u admin:$PW -X PUT -H 'Content-Type: application/json' http://host:8080/api/settings \
     -d '{"allowed_networks": ["10.0.0.0/8", "192.168.10.0/24"]}'
curl -u admin:$PW -H 'Content-Type: application/json' http://host:8080/api/users \
     -d '{"username": "printer3f", "password": "a-long-password", "note": "3F copier"}'
curl -u admin:$PW -X DELETE -H 'Content-Type: application/json' http://host:8080/api/users/printer3f
curl -u admin:$PW -H 'Content-Type: application/json' http://host:8080/api/settings/reset \
     -d '{"keys": ["allowed_networks"]}'
```
These endpoints require `Content-Type: application/json`.

## Deploy
```bash
cp .env.example .env        # set ALLOWED_NETWORKS, SMTP_1_*, ADMIN_PASSWORD, API_TOKEN
docker compose up -d --build
docker compose ps           # wait for (healthy)
```
Then point your devices at `<docker-host>:25`, no authentication (or with a relay user created in **Settings**).

Dashboard behind Traefik with Let's Encrypt (SMTP still published directly on the host):
```bash
docker compose -f docker-compose.yml -f docker-compose.traefik.yml up -d --build
```

Useful commands:
```bash
docker compose logs -f
docker compose exec mailrelay python -m mailrelay messages            # recent messages
docker compose exec mailrelay python -m mailrelay messages --status failed -q customer.com
docker compose exec mailrelay python -m mailrelay attempts --upstream primary
docker compose exec mailrelay python -m mailrelay queue               # waiting for retry
docker compose exec mailrelay python -m mailrelay show <relay-id>     # full detail as JSON
```

### Quick test from another machine
```bash
swaks --server <docker-host> --port 25 --from app@yourdomain.com --to you@example.com --header "Subject: relay test"
```

## Settings (.env)
Variables marked ⚙ are only defaults: they can be changed in the web UI without a restart (see above).

| variable | default | |
|---|---|---|
| `MAILRELAY_ALLOWED_NETWORKS` | all private ranges | CIDRs allowed to relay without login. **Never** add public ranges |
| `MAILRELAY_RELAY_USERS` ⚙ | | `user:pass,user2:pass2` SMTP AUTH accounts for clients (or `_FILE`, one per line) |
| `MAILRELAY_REQUIRE_AUTH` | `false` | everyone must log in, even from allowed networks |
| `MAILRELAY_TLS_SELF_SIGNED` | `false` | no cert given: generate a self-signed one in `data/tls/` and offer STARTTLS (see below) |
| `MAILRELAY_TLS_SANS` | | extra DNS names / IPs for the generated cert (`MAILRELAY_HOSTNAME` is always in it) |
| `MAILRELAY_TLS_SELF_SIGNED_DAYS` | `3650` | validity of the generated cert |
| `MAILRELAY_TLS_CERT` / `_KEY` | | your own certificate for STARTTLS; wins over self-signed |
| `MAILRELAY_TLS_MIN_VERSION` | `1.2` | `1.0`/`1.1` only for old devices that fail the handshake |
| `MAILRELAY_AUTH_REQUIRE_TLS` | `true` | with TLS on, AUTH is only offered after STARTTLS; `false` also allows plain-text login |
| `MAILRELAY_REWRITE_FROM` ⚙ | `false` | rewrite sender + From: to `MAILRELAY_FROM_ADDRESS` (original From → Reply-To). Needed for Microsoft 365 / Gmail / most providers that only accept your own address |
| `MAILRELAY_ALLOWED_SENDER_DOMAINS` | any | restrict envelope sender domains |
| `MAILRELAY_MAX_MESSAGE_MB` | `25` | |
| `MAILRELAY_MAX_RECIPIENTS` ⚙ | `100` | per message |
| `MAILRELAY_FROM_ADDRESS` / `_NAME` ⚙ | | sender for From rewriting and `/api/send`, `/api/reply` |
| `MAILRELAY_RETRY_MINUTES` ⚙ | `1,5,15,30,60` | retry schedule, last value repeats |
| `MAILRELAY_QUEUE_MAX_AGE_HOURS` ⚙ | `24` | then the message is marked expired |
| `MAILRELAY_HOSTNAME` | `mailrelay` | banner / Received: name; also used in EHLO to the upstream |
| `MAILRELAY_ADMIN_USER` / `_PASSWORD` | `admin` / | dashboard login |
| `MAILRELAY_API_TOKEN` | | bearer token for the JSON API |
| `SMTP_n_NAME/HOST/PORT/SECURITY/USERNAME/PASSWORD/TIMEOUT/VERIFY_TLS` | | upstream servers, tried in order n = 1, 2, … `SECURITY` = `starttls`, `ssl` or `none` |

Every secret also works as a Docker secret file by adding `_FILE` (e.g. `SMTP_1_PASSWORD_FILE=/run/secrets/smtp1`).

## STARTTLS on an internal network (self-signed)
With `MAILRELAY_TLS_SELF_SIGNED=true` and no `MAILRELAY_TLS_CERT`, the first start generates an RSA 2048
certificate (RSA because many printers/copiers can't do ECDSA) for `MAILRELAY_HOSTNAME` + `MAILRELAY_TLS_SANS`
into `data/tls/selfsigned-cert.pem` / `selfsigned-key.pem` (key 0600). It is reused on every start and
regenerated automatically when it expires within 30 days, can't be read, or doesn't cover a configured name.
To force a new one, delete the two files and restart.

The startup log and the dashboard header (hover "STARTTLS") show the names, expiry and SHA-256 fingerprint.
Most devices accept a self-signed cert as-is. Clients that verify certificates need the cert imported as trusted:
```bash
docker compose cp mailrelay:/app/data/tls/selfsigned-cert.pem ./mailrelay.crt
```
STARTTLS stays optional, so devices without TLS keep working in plain text. If a device fails *after*
STARTTLS, it usually only speaks TLS 1.0/1.1: set `MAILRELAY_TLS_MIN_VERSION=1.0`. If a device logs in
(SMTP AUTH) without STARTTLS, set `MAILRELAY_AUTH_REQUIRE_TLS=false`.

## Notes
- **Open relay protection:** only private networks are allowed by default. Don't expose port 25 to the
  internet. If you must accept from outside, set `MAILRELAY_REQUIRE_AUTH=true` with STARTTLS.
- **Client IPs:** Docker keeps the real source IP for connections from other machines. Connections from the
  Docker host itself show the bridge gateway (172.x), which is inside the default allowed ranges.
- **Provider limits:** the upstream's own sending limits and From-address rules still apply. Check the dashboard's
  "Last error" column if messages bounce (e.g. `554 5.7.1 Sender not allowed` → enable `MAILRELAY_REWRITE_FROM`).

## JSON API
Bearer token or the admin Basic login:
`GET /api/overview`, `GET /api/messages?status=&q=&since=`, `GET /api/messages/<id>`, `GET /api/attempts`,
`POST /api/queue/retry`, plus `POST /api/send` and `POST /api/reply` (compose a new mail or a threaded reply
to a pasted `.eml`, sent through the same relay path).

## Prebuilt image / GitHub Actions
`.github/workflows/docker.yml` builds the image, starts it and checks `/health`, the SMTP banner and
self-signed STARTTLS, then publishes it to GitHub Container Registry for `linux/amd64` and `linux/arm64`:

| event | published tags |
|---|---|
| pull request | nothing (build + smoke test only) |
| push to `main` | `latest`, `sha-<short>` |
| tag `v1.2.3` | `1.2.3`, `1.2`, `1`, `latest` |

No secrets are needed (it uses the built-in `GITHUB_TOKEN`). After the first run, make the package public
once under *Packages → mailrelay → Package settings → Change visibility*.

To run the prebuilt image instead of building locally, set in `.env`:
```bash
MAILRELAY_IMAGE=ghcr.io/<owner>/mailrelay:latest
```
then `docker compose pull && docker compose up -d`.

Release a version:
```bash
git tag v1.0.0 && git push origin v1.0.0
```
