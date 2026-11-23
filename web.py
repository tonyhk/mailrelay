"""Web overview + JSON API (stdlib only).

Auth: browser -> HTTP Basic (MAILRELAY_ADMIN_USER / MAILRELAY_ADMIN_PASSWORD),
      scripts -> Authorization: Bearer $MAILRELAY_API_TOKEN.

GET  /                      overview dashboard
GET  /health                no auth
GET  /api/overview          24h counters, per-upstream and per-client stats
GET  /api/messages          ?limit=&status=sent|queued|bounced|expired|failed&q=&since=
GET  /api/messages/<id>     one message with every delivery attempt
GET  /api/attempts          ?limit=&upstream=&status=&since=
POST /api/queue/retry       {"relay_id": optional}  retry queued mail now
POST /api/send              {"to": [...], "subject": "...", "body": "...", "cc": [], "html": null, "upstream": null}
POST /api/reply             {"original_eml": "...", "body": "...", "reply_all": false, "quote": true}

Runtime settings (apply immediately, stored in the database, override env defaults).
These need "Content-Type: application/json" (blocks cross-site form posts against a logged-in browser):
GET    /api/settings               live values, env defaults, relay users
PUT    /api/settings               {"allowed_networks": [...], "require_auth": true, ...}  partial update
POST   /api/settings/reset         {"keys": ["allowed_networks", ...]}  back to env default
POST   /api/users                  {"username": "...", "password": "...", "enabled": true, "note": ""}
                                   create, or update (omit password to keep it)
DELETE /api/users/<username>
"""
from __future__ import annotations

import base64
import hmac
import json
import threading
from email import policy
from email.utils import getaddresses
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
from urllib.parse import parse_qs, unquote, urlparse

from .config import AppConfig, read_secret
from .relay import RelayEngine
from .settings import RuntimeSettings
from .reply import build_message, build_reply, parse_original
from .store import Store

MAX_BODY = 30 * 1024 * 1024


def _eq(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


def make_handler(cfg: AppConfig, store: Store, engine: RelayEngine, settings: RuntimeSettings,
                 token: str | None, admin_pw: str):
    dashboard = files("mailrelay").joinpath("dashboard.html").read_bytes()

    def config_summary() -> dict:
        return {
            "hostname": cfg.hostname, "smtp_port": cfg.smtp_listen_port,
            "allowed_networks": cfg.allowed_networks, "auth_users": settings.user_count(),
            "require_auth": cfg.require_auth, "starttls": bool(cfg.tls_cert),
            "tls": cfg.tls_info,
            "rewrite_from": cfg.from_address if cfg.rewrite_from else None,
            "max_message_mb": cfg.max_message_mb, "retry_minutes": cfg.retry_minutes,
            "queue_max_age_hours": cfg.queue_max_age_hours,
            "upstreams": [{"order": i + 1, "name": u.name, "host": u.host, "port": u.port,
                           "security": u.security, "username": u.username}
                          for i, u in enumerate(cfg.upstreams)],
        }

    class Handler(BaseHTTPRequestHandler):
        server_version = "mailrelay/2.0"

        def _send(self, code: int, body: bytes, ctype: str, extra: dict | None = None) -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def _json(self, code: int, payload) -> None:
            self._send(code, json.dumps(payload, ensure_ascii=False, default=str).encode(), "application/json")

        def _authorized(self) -> bool:
            h = self.headers.get("Authorization", "")
            if h.startswith("Bearer ") and token and _eq(h[7:], token):
                self.who = "api-token"
                return True
            if h.startswith("Basic "):
                try:
                    user, _, pw = base64.b64decode(h[6:]).decode().partition(":")
                    if _eq(user, cfg.admin_user) and _eq(pw, admin_pw):
                        self.who = user
                        return True
                except ValueError:
                    pass
            self._send(401, b'{"error":"unauthorized"}', "application/json",
                       {"WWW-Authenticate": 'Basic realm="mailrelay", charset="UTF-8"'})
            return False

        def _body(self) -> dict:
            n = int(self.headers.get("Content-Length", 0))
            if n > MAX_BODY:
                raise ValueError("request too large")
            return json.loads(self.rfile.read(n) or b"{}")

        def do_GET(self):
            url = urlparse(self.path)
            q = {k: v[0] for k, v in parse_qs(url.query).items()}
            if url.path == "/health":
                return self._json(200, {"ok": True})
            if not self._authorized():
                return
            if url.path in ("/", "/index.html"):
                return self._send(200, dashboard, "text/html; charset=utf-8")
            if url.path == "/api/overview":
                ov = store.overview(int(q.get("hours", 24)))
                return self._json(200, {**ov, "config": config_summary()})
            if url.path == "/api/messages":
                return self._json(200, store.messages(min(int(q.get("limit", 100)), 1000), q.get("status"),
                                                      q.get("q"), q.get("since")))
            if url.path.startswith("/api/messages/"):
                m = store.get_message(unquote(url.path.rsplit("/", 1)[1]))
                return self._json(200, m) if m else self._json(404, {"error": "not found"})
            if url.path == "/api/settings":
                return self._settings_payload()
            if url.path == "/api/attempts":
                return self._json(200, store.attempts(min(int(q.get("limit", 100)), 1000), q.get("upstream"),
                                                      q.get("status"), q.get("since")))
            self._json(404, {"error": "not found"})

        def _settings_payload(self, code: int = 200):
            return self._json(code, {"settings": settings.view(), "users": settings.users()})

        def _settings_write(self, method: str) -> bool:
            """Settings/user endpoints. Returns False if the path is not one of them."""
            path = urlparse(self.path).path
            if not (path.startswith("/api/settings") or path.startswith("/api/users")):
                return False
            if not self._authorized():
                return True
            if self.headers.get("Content-Type", "").split(";")[0].strip() != "application/json":
                self._json(415, {"error": "Content-Type must be application/json"})
                return True
            by = getattr(self, "who", "?")
            try:
                req = self._body()
                if method == "PUT" and path == "/api/settings":
                    settings.update(req, by)
                elif method == "POST" and path == "/api/settings/reset":
                    settings.reset(list(req.get("keys") or []), by)
                elif method == "POST" and path == "/api/users":
                    settings.save_user(req.get("username", ""), req.get("password"), req.get("enabled", True),
                                       req.get("note", ""), by)
                elif method == "DELETE" and path.startswith("/api/users/"):
                    settings.delete_user(unquote(path.split("/api/users/", 1)[1]), by)
                else:
                    self._json(404, {"error": "not found"})
                    return True
                self._settings_payload()
            except KeyError as e:
                self._json(404, {"error": f"not found: {e}"})
            except (ValueError, TypeError) as e:
                self._json(400, {"error": str(e)})
            return True

        def do_PUT(self):
            if not self._settings_write("PUT"):
                self._json(404, {"error": "not found"})

        def do_DELETE(self):
            if not self._settings_write("DELETE"):
                self._json(404, {"error": "not found"})

        def do_POST(self):
            if self._settings_write("POST"):
                return
            path = urlparse(self.path).path
            if not self._authorized():
                return
            try:
                req = self._body()
                if path == "/api/queue/retry":
                    rid = req.get("relay_id")
                    threading.Thread(target=engine.process_queue, kwargs={"force": True, "only": rid},
                                     daemon=True).start()
                    return self._json(202, {"retrying": rid or "all", "queued": len(engine.queued())})
                if path in ("/api/send", "/api/reply"):
                    if not cfg.from_address:
                        return self._json(400, {"error": "MAILRELAY_FROM_ADDRESS is not set"})
                    if path == "/api/reply":
                        msg = build_reply(parse_original(req["original_eml"].encode()), cfg.from_address,
                                          cfg.from_name, req["body"], reply_all=req.get("reply_all", False),
                                          quote=req.get("quote", True), html=req.get("html"))
                    else:
                        msg = build_message(cfg.from_address, cfg.from_name, req["to"], req["subject"],
                                            req["body"], cc=req.get("cc"), html=req.get("html"),
                                            in_reply_to=req.get("in_reply_to"), references=req.get("references"))
                    rcpts = [a for _, a in getaddresses(msg.get_all("To", []) + msg.get_all("Cc", [])) if a]
                    raw = msg.as_bytes(policy=policy.SMTP)
                    code, text, rid = engine.accept(raw, cfg.from_address, rcpts,
                                                    {"source": "api", "client_ip": self.client_address[0]},
                                                    upstream=req.get("upstream"))
                    return self._json(200 if code == 250 else 502,
                                      {"smtp_code": code, "smtp_text": text, "message": store.get_message(rid)})
                self._json(404, {"error": "not found"})
            except (KeyError, ValueError, TypeError) as e:
                self._json(400, {"error": f"{type(e).__name__}: {e}"})

        def log_message(self, fmt, *args):
            if not self.path.startswith(("/health", "/api/overview", "/api/messages")):
                print(f"[web] {self.address_string()} {fmt % args}", flush=True)

    return Handler


def build_web(cfg: AppConfig, store: Store, engine: RelayEngine, settings: RuntimeSettings) -> ThreadingHTTPServer:
    token = read_secret(cfg.api_token_env)
    admin_pw = read_secret(cfg.admin_password_env) or token
    if not admin_pw:
        raise SystemExit(f"Set {cfg.admin_password_env} (dashboard) and/or {cfg.api_token_env} (API)")
    return ThreadingHTTPServer((cfg.web_listen_host, cfg.web_listen_port),
                               make_handler(cfg, store, engine, settings, token, admin_pw))
