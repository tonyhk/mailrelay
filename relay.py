"""The relay: inbound SMTP listener -> immediate delivery to upstream -> disk queue with retries."""
from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import re
import secrets
import ssl
import threading
import time
from datetime import datetime, timezone
from email import policy
from email.parser import BytesHeaderParser
from email.utils import formataddr, formatdate
from pathlib import Path

from aiosmtpd.controller import Controller
from aiosmtpd.smtp import AuthResult, LoginPassword

from .config import AppConfig
from .sender import Sender
from .settings import RuntimeSettings
from .store import Store, now_iso


# ---------------------------------------------------------------- message helpers
def new_relay_id() -> str:
    return datetime.now(timezone.utc).strftime("%y%m%d%H%M%S") + secrets.token_hex(3).upper()


def normalize_crlf(raw: bytes) -> bytes:
    return re.sub(rb"\r?\n", b"\r\n", raw)


def _split(raw: bytes) -> tuple[bytes, bytes]:
    i = raw.find(b"\r\n\r\n")
    return (raw, b"") if i < 0 else (raw[: i + 2], raw[i + 2:])


def rewrite_from(raw: bytes, from_addr: str, from_name: str) -> bytes:
    """Replace the From: header (keeps the original as Reply-To if there is none). Body untouched."""
    head, body = _split(raw)
    out, from_lines, in_from = [], [], False
    for line in head.split(b"\r\n"):
        if not line:
            continue
        if line[:1] in (b" ", b"\t"):
            (from_lines if in_from else out).append(line)
            continue
        in_from = line.split(b":", 1)[0].strip().lower() == b"from"
        (from_lines if in_from else out).append(line)
    new = [f"From: {formataddr((from_name, from_addr))}".encode()]
    if from_lines and not any(l.lower().startswith(b"reply-to:") for l in out):
        new.append(b"Reply-To:" + b"\r\n".join(from_lines).split(b":", 1)[1])
    return b"\r\n".join(new + out) + b"\r\n" + body


def ip_allowed(ip: str, networks: list[str]) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if getattr(addr, "ipv4_mapped", None):
        addr = addr.ipv4_mapped
    return any(addr in ipaddress.ip_network(n, strict=False) for n in networks)


# ---------------------------------------------------------------- engine
class RelayEngine:
    def __init__(self, cfg: AppConfig, store: Store, sender: Sender):
        self.cfg, self.store, self.sender = cfg, store, sender
        self.qdir = Path(cfg.queue_dir)
        self.qdir.mkdir(parents=True, exist_ok=True)
        self._qlock = threading.Lock()

    def accept(self, raw: bytes, mail_from: str, rcpts: list[str], client: dict,
               upstream: str | None = None) -> tuple[int, str, str]:
        """Take a message in, try to deliver it now, queue it if upstream is temporarily unavailable.
        Returns (smtp_code, smtp_text, relay_id) to answer the client with."""
        relay_id = new_relay_id()
        raw = normalize_crlf(raw)
        client_mail_from = mail_from
        if self.cfg.rewrite_from and client.get("source") == "relay":
            raw = rewrite_from(raw, self.cfg.from_address, self.cfg.from_name)
            mail_from = self.cfg.from_address
        proto = "ESMTP" + ("S" if client.get("client_tls") else "") + ("A" if client.get("client_user") else "")
        helo = client.get("client_helo") or "unknown"
        received = (f"Received: from {helo} ({client.get('client_ip') or 'api'})\r\n"
                    f"\tby {self.cfg.hostname} (mailrelay) with {proto} id {relay_id};\r\n"
                    f"\t{formatdate(usegmt=True)}\r\n").encode()
        raw = received + raw
        hdr = BytesHeaderParser(policy=policy.default).parsebytes(raw)
        meta = {
            "source": client.get("source", "relay"), "relay_id": relay_id,
            "client_ip": client.get("client_ip"), "client_helo": client.get("client_helo"),
            "client_user": client.get("client_user"),
            "subject": str(hdr.get("Subject", ""))[:500], "message_id": str(hdr.get("Message-ID", "")) or None,
            "in_reply_to": str(hdr.get("In-Reply-To", "")) or None,
        }
        self.store.create_message(
            relay_id=relay_id, received_utc=now_iso(), source=meta["source"], status="sending",
            client_ip=meta["client_ip"], client_helo=meta["client_helo"], client_user=meta["client_user"],
            client_tls=int(bool(client.get("client_tls"))), client_mail_from=client_mail_from,
            mail_from=mail_from, rcpt_to=", ".join(rcpts), subject=meta["subject"],
            message_id=meta["message_id"], size_bytes=len(raw), attempts=0,
        )
        return self._try(relay_id, raw, mail_from, rcpts, meta, 1, time.time(), upstream)

    def _try(self, relay_id, raw, mail_from, rcpts, meta, attempt, first_seen, upstream=None):
        d = self.sender.deliver(raw, mail_from, rcpts, {**meta, "attempt": attempt}, upstream)
        f = d.final
        common = dict(attempts=attempt, upstream_name=f.upstream_name, upstream_host=f.upstream_host,
                      upstream_ip=f.upstream_ip, smtp_code=f.smtp_code, smtp_response=f.smtp_response,
                      last_error=f.error, next_retry_utc=None)
        if d.ok:
            self._unspool(relay_id)
            self.store.update_message(relay_id, status="sent", **common)
            return 250, f"2.0.0 Ok: queued as {relay_id}", relay_id
        if d.permanent:
            self._unspool(relay_id)
            self.store.update_message(relay_id, status="bounced", **common)
            return 554, f"5.0.0 Rejected by upstream {f.upstream_name}: {f.smtp_code} {f.smtp_response}"[:400], relay_id
        if time.time() - first_seen >= self.cfg.queue_max_age_hours * 3600:
            self._unspool(relay_id)
            self.store.update_message(relay_id, status="expired", **common)
            return 451, "4.4.7 Message expired in queue", relay_id
        delay = self.cfg.retry_minutes[min(attempt - 1, len(self.cfg.retry_minutes) - 1)] * 60
        nxt = time.time() + delay
        self._spool(relay_id, raw, dict(mail_from=mail_from, rcpts=rcpts, meta=meta, attempt=attempt,
                                        first_seen=first_seen, next_try=nxt, upstream=upstream))
        common["next_retry_utc"] = datetime.fromtimestamp(nxt, timezone.utc).isoformat(timespec="milliseconds")
        self.store.update_message(relay_id, status="queued", **common)
        return 250, f"2.0.0 Ok: queued as {relay_id} (upstream unavailable, will retry)", relay_id

    # ---- disk queue (survives restarts; lives in the data volume) ----
    def _spool(self, relay_id: str, raw: bytes, item: dict) -> None:
        eml = self.qdir / f"{relay_id}.eml"
        if not eml.exists():
            eml.write_bytes(raw)
        tmp = self.qdir / f".{relay_id}.json.tmp"
        tmp.write_text(json.dumps(item))
        os.replace(tmp, self.qdir / f"{relay_id}.json")

    def _unspool(self, relay_id: str) -> None:
        for ext in (".json", ".eml"):
            (self.qdir / f"{relay_id}{ext}").unlink(missing_ok=True)

    def queued(self) -> list[dict]:
        out = []
        for j in sorted(self.qdir.glob("*.json")):
            try:
                out.append({"relay_id": j.stem, **json.loads(j.read_text())})
            except (OSError, ValueError):
                pass
        return out

    def process_queue(self, force: bool = False, only: str | None = None) -> int:
        if not self._qlock.acquire(blocking=False):
            return 0
        n = 0
        try:
            for item in self.queued():
                rid = item["relay_id"]
                if (only and rid != only) or (not force and item["next_try"] > time.time()):
                    continue
                try:
                    raw = (self.qdir / f"{rid}.eml").read_bytes()
                except OSError:
                    self._unspool(rid)
                    continue
                self._try(rid, raw, item["mail_from"], item["rcpts"], item["meta"],
                          item["attempt"] + 1, item["first_seen"], item.get("upstream"))
                n += 1
        finally:
            self._qlock.release()
        return n

    def run_queue(self, stop: threading.Event, interval: int = 15) -> None:
        while not stop.wait(interval):
            try:
                self.process_queue()
            except Exception as e:
                print(f"[queue] error: {type(e).__name__}: {e}", flush=True)


# ---------------------------------------------------------------- inbound SMTP
class RelayHandler:
    """Reads cfg on every command, so changes made in the web UI apply to the next client command."""

    def __init__(self, cfg: AppConfig, engine: RelayEngine, settings: RuntimeSettings):
        self.cfg, self.engine, self.settings = cfg, engine, settings

    @staticmethod
    def _ip(session) -> str:
        return session.peer[0] if isinstance(session.peer, tuple) else str(session.peer)

    async def handle_MAIL(self, server, session, envelope, address, mail_options):
        ip = self._ip(session)
        if not session.authenticated:
            if self.cfg.require_auth:
                return "530 5.7.0 Authentication required"
            if not ip_allowed(ip, self.cfg.allowed_networks):
                hint = " - authenticate first" if self.settings.user_count() else ""
                print(f"[smtp] relay denied for {ip} (MAIL FROM {address})", flush=True)
                return f"554 5.7.1 Relay access denied for {ip}{hint}"
        if self.cfg.allowed_sender_domains and address:
            if address.rsplit("@", 1)[-1].lower() not in self.cfg.allowed_sender_domains:
                return "553 5.7.1 Sender domain not allowed"
        envelope.mail_from = address
        envelope.mail_options.extend(mail_options)
        return "250 2.1.0 OK"

    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
        if len(envelope.rcpt_tos) >= self.cfg.max_recipients:
            return "452 4.5.3 Too many recipients"
        envelope.rcpt_tos.append(address)
        envelope.rcpt_options.extend(rcpt_options)
        return "250 2.1.5 OK"

    async def handle_DATA(self, server, session, envelope):
        user = session.auth_data
        if isinstance(user, bytes):
            user = user.decode(errors="replace")
        client = {"source": "relay", "client_ip": self._ip(session), "client_helo": session.host_name,
                  "client_user": user if isinstance(user, str) else None, "client_tls": bool(session.ssl)}
        raw = envelope.original_content or envelope.content
        if isinstance(raw, str):
            raw = raw.encode("utf-8", "surrogateescape")
        try:
            code, text, _ = await asyncio.get_running_loop().run_in_executor(
                None, self.engine.accept, raw, envelope.mail_from, list(envelope.rcpt_tos), client)
        except Exception as e:
            print(f"[smtp] relay error: {type(e).__name__}: {e}", flush=True)
            return "451 4.3.0 Temporary relay error, try again later"
        return f"{code} {text}"


def make_authenticator(settings: RuntimeSettings):
    def authenticator(server, session, envelope, mechanism, auth_data):
        if not isinstance(auth_data, LoginPassword):
            return AuthResult(success=False, handled=False)
        login = auth_data.login.decode(errors="replace")
        ok = settings.verify(login, auth_data.password)
        if not ok:
            print(f"[smtp] AUTH failed for '{login}' from {session.peer[0] if session.peer else '?'}", flush=True)
        return AuthResult(success=ok, handled=False, auth_data=login if ok else None)
    return authenticator


def build_controller(cfg: AppConfig, engine: RelayEngine, settings: RuntimeSettings) -> Controller:
    tls = None
    if cfg.tls_cert:
        tls = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        tls.load_cert_chain(cfg.tls_cert, cfg.tls_key)
        tls.minimum_version = {"1.0": ssl.TLSVersion.TLSv1, "1.1": ssl.TLSVersion.TLSv1_1,
                               "1.2": ssl.TLSVersion.TLSv1_2, "1.3": ssl.TLSVersion.TLSv1_3}[cfg.tls_min_version]
        if cfg.tls_min_version in ("1.0", "1.1"):
            tls.set_ciphers("DEFAULT:@SECLEVEL=0")   # OpenSSL 3 refuses TLS 1.0/1.1 at the default level
    kwargs = dict(
        hostname=cfg.smtp_listen_host, port=cfg.smtp_listen_port, server_hostname=cfg.hostname,
        ident="mailrelay ESMTP", data_size_limit=cfg.max_message_mb * 1024 * 1024,
        tls_context=tls, require_starttls=False, decode_data=False,
        # AUTH is always offered because users can be added at runtime. "Login required" is enforced
        # in handle_MAIL from the live setting, not by aiosmtpd's static auth_required flag.
        authenticator=make_authenticator(settings), auth_required=False,
        auth_require_tls=tls is not None and cfg.auth_require_tls,
    )
    return Controller(RelayHandler(cfg, engine, settings), **kwargs)
