"""SQLite store: one row per relayed message, one row per upstream delivery attempt.

Attempts are also appended to a JSON-lines file and (optionally) printed to stdout for `docker logs`.
"""
from __future__ import annotations

import json
import sqlite3
import sys
import threading
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


@dataclass
class SendRecord:
    """One delivery attempt to one upstream server."""
    timestamp_utc: str
    upstream_name: str
    upstream_host: str
    upstream_port: int
    status: str                         # sent | failed
    source: str = "relay"               # relay | api
    relay_id: str | None = None
    attempt: int = 1
    client_ip: str | None = None
    client_helo: str | None = None
    client_user: str | None = None
    upstream_ip: str | None = None
    security: str | None = None
    tls_version: str | None = None
    server_banner: str | None = None
    auth_user: str | None = None
    mail_from: str | None = None
    rcpt_to: str | None = None
    subject: str | None = None
    message_id: str | None = None
    in_reply_to: str | None = None
    size_bytes: int | None = None
    smtp_code: int | None = None
    smtp_response: str | None = None
    error: str | None = None
    permanent: int = 0                  # 1 = upstream rejected the message itself (5xx on RCPT/DATA)
    duration_ms: int | None = None


ATTEMPT_COLS = {
    "timestamp_utc": "TEXT NOT NULL", "upstream_name": "TEXT NOT NULL", "upstream_host": "TEXT NOT NULL",
    "upstream_port": "INTEGER NOT NULL", "status": "TEXT NOT NULL", "source": "TEXT", "relay_id": "TEXT",
    "attempt": "INTEGER", "client_ip": "TEXT", "client_helo": "TEXT", "client_user": "TEXT",
    "upstream_ip": "TEXT", "security": "TEXT", "tls_version": "TEXT", "server_banner": "TEXT",
    "auth_user": "TEXT", "mail_from": "TEXT", "rcpt_to": "TEXT", "subject": "TEXT", "message_id": "TEXT",
    "in_reply_to": "TEXT", "size_bytes": "INTEGER", "smtp_code": "INTEGER", "smtp_response": "TEXT",
    "error": "TEXT", "permanent": "INTEGER", "duration_ms": "INTEGER",
}

MESSAGE_COLS = {
    "relay_id": "TEXT PRIMARY KEY", "received_utc": "TEXT NOT NULL", "updated_utc": "TEXT",
    "source": "TEXT", "status": "TEXT NOT NULL",   # sending | sent | queued | bounced | expired
    "client_ip": "TEXT", "client_helo": "TEXT", "client_user": "TEXT", "client_tls": "INTEGER",
    "client_mail_from": "TEXT", "mail_from": "TEXT", "rcpt_to": "TEXT", "subject": "TEXT",
    "message_id": "TEXT", "size_bytes": "INTEGER", "attempts": "INTEGER DEFAULT 0",
    "upstream_name": "TEXT", "upstream_host": "TEXT", "upstream_ip": "TEXT", "smtp_code": "INTEGER",
    "smtp_response": "TEXT", "last_error": "TEXT", "next_retry_utc": "TEXT",
}

SETTINGS_COLS = {"key": "TEXT PRIMARY KEY", "value": "TEXT NOT NULL", "updated_utc": "TEXT", "updated_by": "TEXT"}

USER_COLS = {
    "username": "TEXT PRIMARY KEY", "password_hash": "TEXT NOT NULL", "enabled": "INTEGER DEFAULT 1",
    "note": "TEXT", "created_utc": "TEXT", "updated_utc": "TEXT", "last_login_utc": "TEXT",
}


class Store:
    def __init__(self, db_path: str, jsonl_path: str | None = None, stdout: bool = False):
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._stdout = stdout
        self._db = sqlite3.connect(db_path, check_same_thread=False, timeout=30)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA journal_mode=WAL")
        self._ensure("smtp_log", {"id": "INTEGER PRIMARY KEY AUTOINCREMENT", **ATTEMPT_COLS})
        self._ensure("messages", MESSAGE_COLS)
        self._ensure("settings", SETTINGS_COLS)
        self._ensure("relay_users", USER_COLS)
        self._db.executescript("""
            CREATE INDEX IF NOT EXISTS idx_log_time ON smtp_log(timestamp_utc);
            CREATE INDEX IF NOT EXISTS idx_log_upstream ON smtp_log(upstream_name);
            CREATE INDEX IF NOT EXISTS idx_log_relay ON smtp_log(relay_id);
            CREATE INDEX IF NOT EXISTS idx_msg_time ON messages(received_utc);
            CREATE INDEX IF NOT EXISTS idx_msg_status ON messages(status);
        """)
        self._db.commit()
        self._jsonl = Path(jsonl_path) if jsonl_path else None
        if self._jsonl:
            self._jsonl.parent.mkdir(parents=True, exist_ok=True)

    def _ensure(self, table: str, cols: dict[str, str]) -> None:
        """Create the table, or add any columns missing from an older version."""
        self._db.execute(f"CREATE TABLE IF NOT EXISTS {table} ({', '.join(f'{k} {v}' for k, v in cols.items())})")
        have = {r[1] for r in self._db.execute(f"PRAGMA table_info({table})")}
        for k, v in cols.items():
            if k not in have:
                self._db.execute(f"ALTER TABLE {table} ADD COLUMN {k} {v.replace('NOT NULL', '').replace('PRIMARY KEY', '')}")

    # ---- attempts ----
    def write_attempt(self, rec: SendRecord) -> int:
        row = asdict(rec)
        with self._lock:
            cur = self._db.execute(f"INSERT INTO smtp_log ({', '.join(row)}) VALUES ({', '.join('?' * len(row))})",
                                   list(row.values()))
            self._db.commit()
            row_id = cur.lastrowid
            line = json.dumps({"event": "smtp_attempt", "id": row_id, **row}, ensure_ascii=False)
            if self._jsonl:
                with self._jsonl.open("a", encoding="utf-8") as f:
                    f.write(line + "\n")
            if self._stdout:
                print(line, file=sys.stdout, flush=True)
        return row_id

    def attempts(self, limit=50, upstream=None, status=None, since=None, relay_id=None) -> list[dict]:
        sql, args = "SELECT * FROM smtp_log WHERE 1=1", []
        for col, val in (("upstream_name", upstream), ("status", status), ("relay_id", relay_id)):
            if val:
                sql += f" AND {col} = ?"; args.append(val)
        if since:
            sql += " AND timestamp_utc >= ?"; args.append(since)
        sql += " ORDER BY id DESC LIMIT ?"; args.append(limit)
        with self._lock:
            return [dict(r) for r in self._db.execute(sql, args)]

    # ---- messages ----
    def create_message(self, **fields) -> None:
        with self._lock:
            self._db.execute(f"INSERT INTO messages ({', '.join(fields)}) VALUES ({', '.join('?' * len(fields))})",
                             list(fields.values()))
            self._db.commit()

    def update_message(self, relay_id: str, **fields) -> None:
        fields["updated_utc"] = now_iso()
        with self._lock:
            self._db.execute(f"UPDATE messages SET {', '.join(f'{k} = ?' for k in fields)} WHERE relay_id = ?",
                             [*fields.values(), relay_id])
            self._db.commit()

    def get_message(self, relay_id: str) -> dict | None:
        with self._lock:
            r = self._db.execute("SELECT * FROM messages WHERE relay_id = ?", (relay_id,)).fetchone()
            if not r:
                return None
            att = [dict(a) for a in self._db.execute(
                "SELECT * FROM smtp_log WHERE relay_id = ? ORDER BY id", (relay_id,))]
        return {**dict(r), "attempt_log": att}

    def messages(self, limit=100, status=None, q=None, since=None) -> list[dict]:
        sql, args = "SELECT * FROM messages WHERE 1=1", []
        if status == "failed":
            sql += " AND status IN ('bounced','expired')"
        elif status:
            sql += " AND status = ?"; args.append(status)
        if since:
            sql += " AND received_utc >= ?"; args.append(since)
        if q:
            like = f"%{q}%"
            sql += (" AND (relay_id LIKE ? OR mail_from LIKE ? OR client_mail_from LIKE ? OR rcpt_to LIKE ?"
                    " OR subject LIKE ? OR client_ip LIKE ? OR client_user LIKE ? OR message_id LIKE ?)")
            args += [like] * 8
        sql += " ORDER BY received_utc DESC LIMIT ?"; args.append(limit)
        with self._lock:
            return [dict(r) for r in self._db.execute(sql, args)]

    def overview(self, hours: int = 24) -> dict:
        since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat(timespec="milliseconds")
        with self._lock:
            counts = {r[0]: r[1] for r in self._db.execute(
                "SELECT status, COUNT(*) FROM messages WHERE received_utc >= ? GROUP BY status", (since,))}
            queued = self._db.execute("SELECT COUNT(*) FROM messages WHERE status = 'queued'").fetchone()[0]
            bytes_ = self._db.execute("SELECT COALESCE(SUM(size_bytes),0) FROM messages WHERE received_utc >= ?",
                                      (since,)).fetchone()[0]
            ups = {}
            for r in self._db.execute("""
                SELECT upstream_name, SUM(status='sent') sent, SUM(status='failed') failed,
                       MAX(CASE WHEN status='sent' THEN timestamp_utc END) last_ok,
                       CAST(AVG(CASE WHEN status='sent' THEN duration_ms END) AS INTEGER) avg_ms
                FROM smtp_log WHERE timestamp_utc >= ? GROUP BY upstream_name""", (since,)):
                ups[r["upstream_name"]] = dict(r)
            for name in ups:
                e = self._db.execute("SELECT timestamp_utc, error, upstream_ip FROM smtp_log WHERE upstream_name = ?"
                                     " AND status='failed' ORDER BY id DESC LIMIT 1", (name,)).fetchone()
                ups[name]["last_error"] = dict(e) if e else None
                ip = self._db.execute("SELECT upstream_ip, server_banner FROM smtp_log WHERE upstream_name = ?"
                                      " AND upstream_ip IS NOT NULL ORDER BY id DESC LIMIT 1", (name,)).fetchone()
                ups[name]["last_ip"] = ip["upstream_ip"] if ip else None
                ups[name]["last_banner"] = ip["server_banner"] if ip else None
            clients = [dict(r) for r in self._db.execute("""
                SELECT client_ip, COALESCE(client_user,'') client_user, COUNT(*) messages,
                       SUM(status='sent') sent, MAX(received_utc) last_seen
                FROM messages WHERE received_utc >= ? GROUP BY client_ip, client_user
                ORDER BY messages DESC LIMIT 10""", (since,))]
        return {
            "window_hours": hours,
            "received": sum(counts.values()),
            "sent": counts.get("sent", 0),
            "queued_now": queued,
            "bounced": counts.get("bounced", 0),
            "expired": counts.get("expired", 0),
            "bytes": bytes_,
            "upstreams": ups,
            "clients": clients,
        }

    # ---- runtime settings (changed from the web UI) ----
    def get_settings(self, meta: bool = False) -> dict:
        with self._lock:
            rows = [dict(r) for r in self._db.execute("SELECT * FROM settings")]
        if meta:
            return {r["key"]: {"value": json.loads(r["value"]), "updated_utc": r["updated_utc"],
                               "updated_by": r["updated_by"]} for r in rows}
        return {r["key"]: json.loads(r["value"]) for r in rows}

    def set_settings(self, values: dict, by: str) -> None:
        ts = now_iso()
        with self._lock:
            self._db.executemany(
                "INSERT INTO settings (key, value, updated_utc, updated_by) VALUES (?, ?, ?, ?)"
                " ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_utc=excluded.updated_utc,"
                " updated_by=excluded.updated_by",
                [(k, json.dumps(v), ts, by) for k, v in values.items()])
            self._db.commit()

    def delete_settings(self, keys: list[str]) -> None:
        with self._lock:
            self._db.executemany("DELETE FROM settings WHERE key = ?", [(k,) for k in keys])
            self._db.commit()

    # ---- relay users (SMTP AUTH accounts managed in the web UI) ----
    def list_relay_users(self, with_hash: bool = False) -> list[dict]:
        with self._lock:
            rows = [dict(r) for r in self._db.execute("SELECT * FROM relay_users ORDER BY username")]
        for r in rows:
            r["enabled"] = bool(r["enabled"])
            if not with_hash:
                r.pop("password_hash", None)
        return rows

    def upsert_relay_user(self, username: str, password_hash: str | None, enabled: bool, note: str) -> None:
        ts = now_iso()
        with self._lock:
            exists = self._db.execute("SELECT 1 FROM relay_users WHERE username = ?", (username,)).fetchone()
            if exists:
                sql = "UPDATE relay_users SET enabled = ?, note = ?, updated_utc = ?"
                args = [int(enabled), note, ts]
                if password_hash:
                    sql += ", password_hash = ?"; args.append(password_hash)
                self._db.execute(sql + " WHERE username = ?", [*args, username])
            else:
                self._db.execute("INSERT INTO relay_users (username, password_hash, enabled, note, created_utc,"
                                 " updated_utc) VALUES (?, ?, ?, ?, ?, ?)",
                                 (username, password_hash, int(enabled), note, ts, ts))
            self._db.commit()

    def delete_relay_user(self, username: str) -> None:
        with self._lock:
            self._db.execute("DELETE FROM relay_users WHERE username = ?", (username,))
            self._db.commit()

    def touch_relay_user(self, username: str) -> str:
        ts = now_iso()
        with self._lock:
            self._db.execute("UPDATE relay_users SET last_login_utc = ? WHERE username = ?", (ts, username))
            self._db.commit()
        return ts
