"""Deliver a raw message to the authenticated upstream SMTP servers, failing over in order.

Every attempt is written to the store. A 5xx on RCPT/DATA means the upstream rejected the
message itself (permanent); anything else (connect, TLS, auth, 4xx) moves on to the next upstream.
"""
from __future__ import annotations

import smtplib
import ssl
import time
from dataclasses import dataclass, field

from .config import AppConfig, Upstream
from .store import SendRecord, Store, now_iso


@dataclass
class Delivery:
    ok: bool
    permanent: bool
    final: SendRecord
    attempts: list[SendRecord] = field(default_factory=list)


class _CapturingSMTP(smtplib.SMTP):
    """Keeps the 220 greeting banner so the log shows which server actually answered."""
    banner = ""

    def getreply(self):
        code, msg = super().getreply()
        if not self.banner and code == 220:
            self.banner = msg.decode(errors="replace")
        return code, msg


class _CapturingSMTP_SSL(smtplib.SMTP_SSL, _CapturingSMTP):
    pass


def _text(resp) -> str:
    s = resp.decode(errors="replace") if isinstance(resp, bytes) else str(resp)
    return " ".join(s.split())


class Sender:
    def __init__(self, cfg: AppConfig, store: Store):
        self.cfg = cfg
        self.store = store

    @staticmethod
    def _tls_context(up: Upstream) -> ssl.SSLContext:
        ctx = ssl.create_default_context()
        if not up.verify_tls:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def _attempt(self, up: Upstream, raw: bytes, mail_from: str, rcpts: list[str], meta: dict) -> SendRecord:
        rec = SendRecord(
            timestamp_utc=now_iso(), upstream_name=up.name, upstream_host=up.host, upstream_port=up.port,
            status="failed", security=up.security, auth_user=up.username or None,
            mail_from=mail_from, rcpt_to=", ".join(rcpts), size_bytes=len(raw), **meta,
        )
        start = time.monotonic()
        stage = "connect"
        smtp = None
        try:
            if up.security == "ssl":
                smtp = _CapturingSMTP_SSL(up.host, up.port, timeout=up.timeout, context=self._tls_context(up))
            else:
                smtp = _CapturingSMTP(up.host, up.port, timeout=up.timeout)
            rec.server_banner = smtp.banner
            try:
                rec.upstream_ip = smtp.sock.getpeername()[0]
            except OSError:
                pass
            smtp.ehlo(self.cfg.hostname)
            if up.security == "starttls":
                stage = "starttls"
                smtp.starttls(context=self._tls_context(up))
                smtp.ehlo(self.cfg.hostname)
            if hasattr(smtp.sock, "version"):
                rec.tls_version = smtp.sock.version()
            if up.username:
                stage = "auth"
                smtp.login(up.username, up.password)

            stage = "mail"
            opts = []
            if smtp.has_extn("size"):
                opts.append(f"SIZE={len(raw)}")
            if smtp.has_extn("8bitmime") and any(b > 127 for b in raw):
                opts.append("BODY=8BITMIME")
            if smtp.has_extn("smtputf8") and not (mail_from + "".join(rcpts)).isascii():
                opts.append("SMTPUTF8")
            code, resp = smtp.mail(mail_from, opts)
            if code != 250:
                raise smtplib.SMTPSenderRefused(code, resp, mail_from)

            stage = "rcpt"
            refused = {}
            for r in rcpts:
                c, m = smtp.rcpt(r)
                if c not in (250, 251):
                    refused[r] = f"{c} {_text(m)}"
                    last = (c, m)
            if len(refused) == len(rcpts):
                raise smtplib.SMTPResponseException(*last)

            stage = "data"
            code, resp = smtp.data(raw)
            rec.smtp_code, rec.smtp_response = code, _text(resp)
            if code != 250:
                raise smtplib.SMTPDataError(code, resp)
            rec.status = "sent"
            if refused:
                rec.error = f"recipients refused by upstream: {refused}"
        except smtplib.SMTPResponseException as e:
            rec.smtp_code, rec.smtp_response = e.smtp_code, _text(e.smtp_error)
            rec.error = f"{stage}: {e.smtp_code} {rec.smtp_response}"
            rec.permanent = int(e.smtp_code >= 500 and stage in ("rcpt", "data"))
        except Exception as e:  # DNS, refused, timeout, TLS, missing password ...
            rec.error = f"{stage}: {type(e).__name__}: {e}"
        finally:
            rec.duration_ms = int((time.monotonic() - start) * 1000)
            if smtp is not None:
                try:
                    smtp.quit()
                except Exception:
                    smtp.close()
        return rec

    def deliver(self, raw: bytes, mail_from: str, rcpts: list[str], meta: dict,
                upstream: str | None = None) -> Delivery:
        ups = [u for u in self.cfg.upstreams if upstream in (None, u.name)] or self.cfg.upstreams
        attempts = []
        for up in ups:
            rec = self._attempt(up, raw, mail_from, rcpts, meta)
            self.store.write_attempt(rec)
            attempts.append(rec)
            if rec.status == "sent":
                return Delivery(True, False, rec, attempts)
            if rec.permanent:
                return Delivery(False, True, rec, attempts)
        return Delivery(False, False, attempts[-1], attempts)
