"""python -m mailrelay [serve | messages | attempts | queue | show <relay_id>]"""
from __future__ import annotations

import argparse
import json
import os
import signal
import sys
import threading

from . import __version__
from .config import load_config
from .store import Store


def serve(cfg) -> None:
    from .relay import RelayEngine, build_controller
    from .sender import Sender
    from .settings import RuntimeSettings
    from .tls import prepare_tls
    from .web import build_web

    cfg.tls_info = prepare_tls(cfg)             # may generate a self-signed cert into the data volume

    store = Store(cfg.log_db, cfg.log_file, stdout=cfg.log_stdout)
    settings = RuntimeSettings(cfg, store)      # applies values saved in the web UI over env defaults
    engine = RelayEngine(cfg, store, Sender(cfg, store))
    httpd = build_web(cfg, store, engine, settings)
    stop = threading.Event()
    threading.Thread(target=engine.run_queue, args=(stop,), daemon=True, name="queue").start()
    smtp = build_controller(cfg, engine, settings)
    smtp.start()

    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))      # clean `docker stop`
    print(f"mailrelay {__version__}: SMTP relay on :{cfg.smtp_listen_port}, overview on :{cfg.web_listen_port}", flush=True)
    print("  upstreams: " + ", ".join(f"{u.name}={u.host}:{u.port}/{u.security}" for u in cfg.upstreams), flush=True)
    ti = cfg.tls_info
    if ti:
        print(f"  STARTTLS: {ti['source']} cert for {', '.join(ti['names']) or ti['subject']},"
              f" valid until {ti['not_after'][:10]}, min TLS {cfg.tls_min_version}"
              f"{'' if cfg.auth_require_tls else ', AUTH also without STARTTLS'}", flush=True)
        print(f"  STARTTLS SHA-256 fingerprint: {ti['sha256']}", flush=True)
    else:
        print("  STARTTLS: off (set MAILRELAY_TLS_SELF_SIGNED=true or MAILRELAY_TLS_CERT/_KEY)", flush=True)
    print(f"  clients allowed from: {', '.join(cfg.allowed_networks)}"
          f"{'' if not settings.user_count() else f' + SMTP AUTH ({settings.user_count()} users)'}"
          f"{' (auth required)' if cfg.require_auth else ''}", flush=True)
    overridden = [k for k, v in settings.view().items() if v["overridden"]]
    if overridden:
        print(f"  set in web UI (override env): {', '.join(overridden)}", flush=True)
    for w in settings.warnings:
        print(f"  WARNING: {w}", flush=True)
    queued = len(engine.queued())
    if queued:
        print(f"  {queued} message(s) waiting in queue", flush=True)
    try:
        httpd.serve_forever()
    finally:
        stop.set()
        smtp.stop()
        httpd.server_close()


def _table(rows, cols):
    widths = [max(len(h), *(len(str(r.get(k) or "")[:w]) for r in rows)) if rows else len(h) for h, k, w in cols]
    print("  ".join(h.ljust(wd) for (h, _, _), wd in zip(cols, widths)))
    for r in rows:
        print("  ".join(str(r.get(k) or "")[:w].ljust(wd) for (_, k, w), wd in zip(cols, widths)))


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="mailrelay", description="SMTP relay to an authenticated upstream, with logging")
    p.add_argument("-c", "--config", default=os.environ.get("MAILRELAY_CONFIG", "config.toml"),
                   help="TOML file; if missing, configuration is read from environment variables")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("serve", help="run the SMTP relay + web overview")
    m = sub.add_parser("messages", help="list relayed messages")
    m.add_argument("--limit", type=int, default=30)
    m.add_argument("--status", choices=["sent", "queued", "bounced", "expired", "failed"])
    m.add_argument("-q", "--search")
    m.add_argument("--json", action="store_true")
    a = sub.add_parser("attempts", help="list upstream delivery attempts (which server, when)")
    a.add_argument("--limit", type=int, default=30)
    a.add_argument("--upstream"); a.add_argument("--status", choices=["sent", "failed"]); a.add_argument("--since")
    a.add_argument("--json", action="store_true")
    s = sub.add_parser("show", help="one message with all attempts")
    s.add_argument("relay_id")
    sub.add_parser("queue", help="list messages waiting for retry")
    args = p.parse_args(argv)
    cfg = load_config(args.config, strict=args.cmd == "serve")

    if args.cmd == "serve":
        serve(cfg)
        return 0

    store = Store(cfg.log_db)
    if args.cmd == "messages":
        rows = store.messages(args.limit, args.status, args.search)
        if args.json:
            print(json.dumps(rows, indent=2, ensure_ascii=False)); return 0
        _table(rows, [("RECEIVED (UTC)", "received_utc", 23), ("RELAY ID", "relay_id", 18), ("CLIENT", "client_ip", 15),
                      ("FROM", "mail_from", 28), ("TO", "rcpt_to", 28), ("STATUS", "status", 7),
                      ("VIA", "upstream_name", 12), ("UPSTREAM IP", "upstream_ip", 15), ("TRIES", "attempts", 3),
                      ("SUBJECT", "subject", 40)])
    elif args.cmd == "attempts":
        rows = store.attempts(args.limit, args.upstream, args.status, args.since)
        if args.json:
            print(json.dumps(rows, indent=2, ensure_ascii=False)); return 0
        for r in rows:
            r["server"] = f"{r['upstream_host']}:{r['upstream_port']}"
            r["detail"] = r["smtp_response"] if r["status"] == "sent" else r["error"]
        _table(rows, [("TIME (UTC)", "timestamp_utc", 29), ("RELAY ID", "relay_id", 18), ("SERVER", "upstream_name", 12),
                      ("HOST:PORT", "server", 32), ("IP", "upstream_ip", 15), ("STATUS", "status", 6),
                      ("DETAIL", "detail", 70)])
    elif args.cmd == "show":
        m = store.get_message(args.relay_id)
        if not m:
            print("not found", file=sys.stderr); return 1
        print(json.dumps(m, indent=2, ensure_ascii=False))
    elif args.cmd == "queue":
        rows = store.messages(500, "queued")
        _table(rows, [("RELAY ID", "relay_id", 18), ("RECEIVED (UTC)", "received_utc", 23), ("TO", "rcpt_to", 30),
                      ("TRIES", "attempts", 3), ("NEXT RETRY (UTC)", "next_retry_utc", 23), ("LAST ERROR", "last_error", 70)])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
