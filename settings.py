"""Runtime settings: values that can be changed from the web overview without restarting.

Environment variables / config.toml give the defaults. A value saved in the web UI (or via the API) is stored
in the SQLite database and wins over the default until it is reset. Changes apply to the next SMTP command.

Relay users: accounts from MAILRELAY_RELAY_USERS(_FILE) are read-only; accounts created in the web UI are
stored in the database with a salted PBKDF2 hash.
"""
from __future__ import annotations

import copy
import hashlib
import hmac
import ipaddress
import re
import secrets
import threading

from .config import AppConfig
from .store import Store, now_iso

# key -> (type, label)
RUNTIME_KEYS: dict[str, tuple[str, str]] = {
    "allowed_networks": ("cidrs", "Networks allowed to relay without login"),
    "require_auth": ("bool", "Every client must log in, even from allowed networks"),
    "allowed_sender_domains": ("domains", "Allowed sender domains (empty = any)"),
    "max_recipients": ("int", "Max recipients per message"),
    "rewrite_from": ("bool", "Rewrite envelope sender + From: to the relay address"),
    "from_address": ("email", "Relay From address"),
    "from_name": ("str", "Relay From name"),
    "retry_minutes": ("ints", "Retry schedule in minutes (last value repeats)"),
    "queue_max_age_hours": ("float", "Give up on queued mail after (hours)"),
}

USERNAME_RE = re.compile(r"^[A-Za-z0-9._@+-]{1,64}$")
PBKDF2_ITER = 200_000


def hash_password(pw: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, PBKDF2_ITER)
    return f"pbkdf2_sha256${PBKDF2_ITER}${salt.hex()}${dk.hex()}"


def check_password(pw: str | bytes, stored: str) -> bool:
    try:
        algo, it, salt, dk = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        pw_b = pw if isinstance(pw, bytes) else pw.encode()
        got = hashlib.pbkdf2_hmac("sha256", pw_b, bytes.fromhex(salt), int(it))
        return hmac.compare_digest(got.hex(), dk)
    except (ValueError, TypeError):
        return False


def _items(v) -> list[str]:
    if v is None:
        return []
    if isinstance(v, str):
        v = re.split(r"[,\s]+", v)
    return [str(x).strip() for x in v if str(x).strip()]


def _bool(v) -> bool:
    if isinstance(v, bool):
        return v
    if isinstance(v, str) and v.lower() in ("1", "true", "yes", "on", "0", "false", "no", "off", ""):
        return v.lower() in ("1", "true", "yes", "on")
    if isinstance(v, int):
        return bool(v)
    raise ValueError("must be true or false")


def normalize(key: str, value):
    """Validate one runtime setting and return it in canonical form. Raises ValueError."""
    kind = RUNTIME_KEYS[key][0]
    if kind == "cidrs":
        out = []
        for n in _items(value):
            try:
                net = ipaddress.ip_network(n, strict=False)
            except ValueError:
                raise ValueError(f"'{n}' is not a valid IP network")
            if net.prefixlen == 0:
                raise ValueError(f"'{n}' would make this an open relay")
            if str(net) not in out:
                out.append(str(net))
        return out
    if kind == "domains":
        out = []
        for d in _items(value):
            d = d.lower().lstrip("@")
            if not re.fullmatch(r"[a-z0-9.-]+\.[a-z0-9-]+", d):
                raise ValueError(f"'{d}' is not a valid domain")
            if d not in out:
                out.append(d)
        return out
    if kind == "bool":
        return _bool(value)
    if kind == "int":
        v = int(value)
        if not 1 <= v <= 10000:
            raise ValueError("must be between 1 and 10000")
        return v
    if kind == "float":
        v = float(value)
        if not 0 < v <= 24 * 30:
            raise ValueError("must be between 0 and 720")
        return v
    if kind == "ints":
        v = [int(x) for x in _items(value)]
        if not v or any(x < 1 or x > 24 * 60 for x in v):
            raise ValueError("needs at least one value, each 1..1440 minutes")
        return v
    if kind == "email":
        v = str(value or "").strip()
        if v and not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", v):
            raise ValueError("is not a valid email address")
        return v
    return str(value or "").strip()[:200]


class RuntimeSettings:
    """Owns the live values of RUNTIME_KEYS on the shared AppConfig and the relay user list."""

    def __init__(self, cfg: AppConfig, store: Store):
        self.cfg, self.store = cfg, store
        self._lock = threading.Lock()
        self.defaults = {k: copy.deepcopy(getattr(cfg, k)) for k in RUNTIME_KEYS}
        self.env_users = dict(cfg.relay_users)          # read-only, from env / file
        self._db_users: dict[str, dict] = {}
        self.warnings: list[str] = []
        self._load()

    # ---- loading / applying ----
    def _load(self) -> None:
        saved = self.store.get_settings()
        values = dict(self.defaults)
        for k, v in saved.items():
            if k not in RUNTIME_KEYS:
                continue
            try:
                values[k] = normalize(k, v)
            except (ValueError, TypeError) as e:
                self.warnings.append(f"ignoring saved setting {k}: {e}")
        self._reload_users()
        problems = self._check(values)
        if problems:
            self.warnings += problems
        self._apply(values)

    def _reload_users(self) -> None:
        self._db_users = {u["username"]: u for u in self.store.list_relay_users(with_hash=True)}

    def _apply(self, values: dict) -> None:
        for k, v in values.items():
            setattr(self.cfg, k, copy.deepcopy(v))

    def _check(self, values: dict) -> list[str]:
        p = []
        if values["rewrite_from"] and not values["from_address"]:
            p.append("rewrite From needs a From address")
        if values["require_auth"] and not self.user_count(enabled_only=True):
            p.append("requiring login needs at least one enabled relay user")
        return p

    def current(self) -> dict:
        return {k: copy.deepcopy(getattr(self.cfg, k)) for k in RUNTIME_KEYS}

    # ---- settings API ----
    def view(self) -> dict:
        saved = self.store.get_settings(meta=True)
        return {
            k: {"value": getattr(self.cfg, k), "default": self.defaults[k], "type": t, "label": label,
                "overridden": k in saved, "updated_utc": saved.get(k, {}).get("updated_utc"),
                "updated_by": saved.get(k, {}).get("updated_by")}
            for k, (t, label) in RUNTIME_KEYS.items()
        }

    def update(self, changes: dict, by: str) -> dict:
        unknown = set(changes) - set(RUNTIME_KEYS)
        if unknown:
            raise ValueError(f"not a runtime setting: {', '.join(sorted(unknown))}")
        with self._lock:
            values = self.current()
            normalized = {}
            for k, v in changes.items():
                try:
                    normalized[k] = normalize(k, v)
                except (ValueError, TypeError) as e:
                    raise ValueError(f"{k}: {e}")
            values.update(normalized)
            problems = self._check(values)
            if problems:
                raise ValueError("; ".join(problems))
            changed = {k: v for k, v in normalized.items() if v != getattr(self.cfg, k)}
            self.store.set_settings(normalized, by)
            self._apply(values)
        for k, v in changed.items():
            print(f"[settings] {by} set {k} = {v}", flush=True)
        return self.view()

    def reset(self, keys: list[str], by: str) -> dict:
        keys = [k for k in keys if k in RUNTIME_KEYS]
        with self._lock:
            values = self.current()
            for k in keys:
                values[k] = copy.deepcopy(self.defaults[k])
            problems = self._check(values)
            if problems:
                raise ValueError("; ".join(problems))
            self.store.delete_settings(keys)
            self._apply(values)
        for k in keys:
            print(f"[settings] {by} reset {k} to default {self.defaults[k]}", flush=True)
        return self.view()

    # ---- relay users ----
    def user_count(self, enabled_only: bool = True) -> int:
        db = sum(1 for u in self._db_users.values() if u["enabled"] or not enabled_only)
        return len(self.env_users) + db

    def users(self) -> list[dict]:
        out = [{"username": u, "source": "env", "enabled": True, "note": "from MAILRELAY_RELAY_USERS"}
               for u in sorted(self.env_users)]
        out += [{k: v for k, v in u.items() if k != "password_hash"} | {"source": "db"}
                for u in self._db_users.values()]
        return out

    def save_user(self, username: str, password: str | None, enabled=True, note: str = "", by: str = "") -> None:
        username = (username or "").strip()
        if not USERNAME_RE.fullmatch(username):
            raise ValueError("username: 1-64 characters, letters, digits and . _ @ + -")
        if username in self.env_users:
            raise ValueError(f"'{username}' is defined in MAILRELAY_RELAY_USERS and can only be changed there")
        enabled = _bool(enabled)
        with self._lock:
            existing = self._db_users.get(username)
            if password is not None and password != "":
                if len(password) < 8:
                    raise ValueError("password must be at least 8 characters")
                pw_hash = hash_password(password)
            elif existing:
                pw_hash = None
            else:
                raise ValueError("password is required for a new user")
            if existing and existing["enabled"] and not enabled:
                self._guard_last_user(username)
            self.store.upsert_relay_user(username, pw_hash, enabled, (note or "")[:200])
            self._reload_users()
        print(f"[settings] {by} {'updated' if existing else 'created'} relay user '{username}'"
              f"{'' if enabled else ' (disabled)'}", flush=True)

    def delete_user(self, username: str, by: str) -> None:
        if username in self.env_users:
            raise ValueError(f"'{username}' is defined in MAILRELAY_RELAY_USERS and can only be removed there")
        with self._lock:
            if username not in self._db_users:
                raise KeyError(username)
            if self._db_users[username]["enabled"]:
                self._guard_last_user(username)
            self.store.delete_relay_user(username)
            self._reload_users()
        print(f"[settings] {by} deleted relay user '{username}'", flush=True)

    def _guard_last_user(self, username: str) -> None:
        if self.cfg.require_auth and self.user_count(enabled_only=True) <= 1:
            raise ValueError(f"'{username}' is the last enabled user while login is required - turn that off first")

    def verify(self, login: str, password: bytes) -> bool:
        expected = self.env_users.get(login)
        if expected is not None:
            return hmac.compare_digest(expected.encode(), password)
        u = self._db_users.get(login)
        if u and u["enabled"] and check_password(password, u["password_hash"]):
            u["last_login_utc"] = self.store.touch_relay_user(login)
            return True
        return False
