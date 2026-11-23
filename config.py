"""Configuration: environment variables (Docker) or a TOML file.

Settings listed in settings.RUNTIME_KEYS (allowed networks, relay users, sender domains, From rewriting,
retry schedule ...) are only defaults here: they can be changed in the web overview without a restart.

Secrets can be given directly (SMTP_1_PASSWORD) or as Docker secret files (SMTP_1_PASSWORD_FILE).
"""
from __future__ import annotations

import ipaddress
import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

TRUE = {"1", "true", "yes", "on"}
PRIVATE_NETS = ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "::1/128", "fc00::/7"]


def read_secret(var: str) -> str | None:
    """Value of $VAR, or contents of the file named by $VAR_FILE (Docker secrets)."""
    if var in os.environ:
        return os.environ[var]
    path = os.environ.get(var + "_FILE")
    if path:
        return Path(path).read_text(encoding="utf-8").strip()
    return None


@dataclass
class Upstream:
    name: str
    host: str
    port: int = 587
    security: str = "starttls"          # starttls | ssl | none
    username: str = ""
    password_env: str = ""
    timeout: int = 30
    verify_tls: bool = True

    @property
    def password(self) -> str:
        if not self.password_env:
            return ""
        value = read_secret(self.password_env)
        if value is None:
            raise RuntimeError(f"Upstream '{self.name}': {self.password_env} (or {self.password_env}_FILE) is not set")
        return value


@dataclass
class AppConfig:
    # identity / rewriting
    from_address: str = ""              # used by rewrite_from and by the /api/send & /api/reply endpoints
    from_name: str = ""
    hostname: str = "mailrelay"         # name used in the SMTP banner and Received: header
    rewrite_from: bool = False          # force envelope sender + From: to from_address (original From -> Reply-To)

    # inbound SMTP listener
    smtp_listen_host: str = "0.0.0.0"
    smtp_listen_port: int = 2525
    allowed_networks: list[str] = field(default_factory=lambda: list(PRIVATE_NETS))
    relay_users: dict[str, str] = field(default_factory=dict)   # user -> password for inbound SMTP AUTH
    require_auth: bool = False          # true: every client must authenticate, even from allowed networks
    tls_cert: str = ""                  # offer STARTTLS to clients when cert+key are given
    tls_key: str = ""
    tls_self_signed: bool = False       # no cert given: generate a self-signed one in <data>/tls/
    tls_self_signed_days: int = 3650
    tls_sans: list[str] = field(default_factory=list)   # extra DNS names / IPs for the generated cert
    tls_dir: str = ""                   # default: <directory of log_db>/tls
    tls_min_version: str = "1.2"        # 1.0 | 1.1 | 1.2 | 1.3 - lower only for old printers/copiers
    auth_require_tls: bool = True       # with TLS on, only offer AUTH after STARTTLS
    tls_info: dict | None = None        # set at startup by tls.prepare_tls (not a setting)
    max_message_mb: int = 25
    max_recipients: int = 100
    allowed_sender_domains: list[str] = field(default_factory=list)  # empty = any

    # queue
    queue_dir: str = "data/queue"
    retry_minutes: list[int] = field(default_factory=lambda: [1, 5, 15, 30, 60])  # last value repeats
    queue_max_age_hours: float = 24

    # logs
    log_db: str = "data/mailrelay.db"
    log_file: str = "data/smtp_log.jsonl"
    log_stdout: bool = True

    # web overview / API
    web_listen_host: str = "0.0.0.0"
    web_listen_port: int = 8080
    api_token_env: str = "MAILRELAY_API_TOKEN"
    admin_user: str = "admin"
    admin_password_env: str = "MAILRELAY_ADMIN_PASSWORD"

    upstreams: list[Upstream] = field(default_factory=list)


def _validate(cfg: AppConfig, strict: bool = True) -> AppConfig:
    if strict and not cfg.upstreams:
        raise ValueError("config: at least one upstream is required (SMTP_1_HOST ...)")
    for u in cfg.upstreams:
        if u.security not in ("starttls", "ssl", "none"):
            raise ValueError(f"upstream '{u.name}': security must be starttls, ssl or none")
    if cfg.rewrite_from and not cfg.from_address:
        raise ValueError("config: MAILRELAY_REWRITE_FROM needs MAILRELAY_FROM_ADDRESS")
    if bool(cfg.tls_cert) != bool(cfg.tls_key):
        raise ValueError("config: set both MAILRELAY_TLS_CERT and MAILRELAY_TLS_KEY")
    if cfg.tls_min_version not in ("1.0", "1.1", "1.2", "1.3"):
        raise ValueError("config: MAILRELAY_TLS_MIN_VERSION must be 1.0, 1.1, 1.2 or 1.3")
    if not 1 <= cfg.tls_self_signed_days <= 36500:
        raise ValueError("config: MAILRELAY_TLS_SELF_SIGNED_DAYS must be 1..36500")
    for n in cfg.tls_sans:
        if not n.replace(".", "").replace("-", "").replace(":", "").isalnum():
            raise ValueError(f"config: MAILRELAY_TLS_SANS entry '{n}' is not a host name or IP")
    for n in cfg.allowed_networks:
        ipaddress.ip_network(n, strict=False)
    if not cfg.retry_minutes:
        cfg.retry_minutes = [5]
    cfg.allowed_sender_domains = [d.lower().lstrip("@") for d in cfg.allowed_sender_domains]
    return cfg


def load_file(path: str | os.PathLike, strict: bool = True) -> AppConfig:
    data = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    ups = [Upstream(**u) for u in data.get("upstream", [])]
    return _validate(AppConfig(upstreams=ups, **data.get("app", {})), strict)


def _list(v: str | None) -> list[str]:
    return [x.strip() for x in (v or "").split(",") if x.strip()]


def _users() -> dict[str, str]:
    if "MAILRELAY_RELAY_USERS" in os.environ:          # user:pass,user2:pass2
        entries = _list(os.environ["MAILRELAY_RELAY_USERS"])
    elif os.environ.get("MAILRELAY_RELAY_USERS_FILE"):  # one user:pass per line
        text = Path(os.environ["MAILRELAY_RELAY_USERS_FILE"]).read_text(encoding="utf-8")
        entries = [l.strip() for l in text.splitlines() if l.strip() and not l.startswith("#")]
    else:
        return {}
    users = {}
    for e in entries:
        user, sep, pw = e.partition(":")
        if not sep:
            raise ValueError(f"MAILRELAY_RELAY_USERS: entry '{user}' must be user:password")
        users[user] = pw
    return users


def load_env(strict: bool = True) -> AppConfig:
    """MAILRELAY_* for the relay, SMTP_<n>_* for upstream servers n = 1, 2, 3 ... (tried in order)."""
    e = os.environ.get
    b = lambda k, d: e(k, d).lower() in TRUE
    ups = []
    n = 1
    while e(f"SMTP_{n}_HOST"):
        p = f"SMTP_{n}_"
        security = e(p + "SECURITY", "starttls").lower()
        ups.append(Upstream(
            name=e(p + "NAME", f"smtp{n}"),
            host=e(p + "HOST"),
            port=int(e(p + "PORT", "465" if security == "ssl" else "587")),
            security=security,
            username=e(p + "USERNAME", ""),
            password_env=p + "PASSWORD" if (e(p + "PASSWORD") or e(p + "PASSWORD_FILE")) else "",
            timeout=int(e(p + "TIMEOUT", "30")),
            verify_tls=b(p + "VERIFY_TLS", "true"),
        ))
        n += 1
    return _validate(AppConfig(
        from_address=e("MAILRELAY_FROM_ADDRESS", ""),
        from_name=e("MAILRELAY_FROM_NAME", ""),
        hostname=e("MAILRELAY_HOSTNAME", "mailrelay"),
        rewrite_from=b("MAILRELAY_REWRITE_FROM", "false"),
        smtp_listen_port=int(e("MAILRELAY_SMTP_LISTEN_PORT", "2525")),
        allowed_networks=_list(e("MAILRELAY_ALLOWED_NETWORKS")) or list(PRIVATE_NETS),
        relay_users=_users(),
        require_auth=b("MAILRELAY_REQUIRE_AUTH", "false"),
        tls_cert=e("MAILRELAY_TLS_CERT", ""),
        tls_key=e("MAILRELAY_TLS_KEY", ""),
        tls_self_signed=b("MAILRELAY_TLS_SELF_SIGNED", "false"),
        tls_self_signed_days=int(e("MAILRELAY_TLS_SELF_SIGNED_DAYS", "3650")),
        tls_sans=_list(e("MAILRELAY_TLS_SANS")),
        tls_dir=e("MAILRELAY_TLS_DIR", ""),
        tls_min_version=e("MAILRELAY_TLS_MIN_VERSION", "1.2"),
        auth_require_tls=b("MAILRELAY_AUTH_REQUIRE_TLS", "true"),
        max_message_mb=int(e("MAILRELAY_MAX_MESSAGE_MB", "25")),
        max_recipients=int(e("MAILRELAY_MAX_RECIPIENTS", "100")),
        allowed_sender_domains=_list(e("MAILRELAY_ALLOWED_SENDER_DOMAINS")),
        queue_dir=e("MAILRELAY_QUEUE_DIR", "data/queue"),
        retry_minutes=[int(x) for x in _list(e("MAILRELAY_RETRY_MINUTES", "1,5,15,30,60"))],
        queue_max_age_hours=float(e("MAILRELAY_QUEUE_MAX_AGE_HOURS", "24")),
        log_db=e("MAILRELAY_LOG_DB", "data/mailrelay.db"),
        log_file=e("MAILRELAY_LOG_FILE", "data/smtp_log.jsonl"),
        log_stdout=b("MAILRELAY_LOG_STDOUT", "true"),
        web_listen_port=int(e("MAILRELAY_WEB_LISTEN_PORT", "8080")),
        admin_user=e("MAILRELAY_ADMIN_USER", "admin"),
        upstreams=ups,
    ), strict)


def load_config(path: str | os.PathLike | None, strict: bool = True) -> AppConfig:
    """Use the TOML file if it exists, otherwise environment variables.
    strict=False (read-only CLI commands) does not require upstream servers."""
    if path and Path(path).is_file():
        return load_file(path, strict)
    return load_env(strict)
