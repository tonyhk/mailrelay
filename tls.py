"""STARTTLS certificate for inbound clients.

MAILRELAY_TLS_CERT / MAILRELAY_TLS_KEY   use your own certificate (e.g. from an internal CA)
MAILRELAY_TLS_SELF_SIGNED=true           otherwise generate a self-signed one in <data>/tls/ on first start

The generated certificate is kept in the data volume and reused. It is regenerated when it is missing or
unreadable, expires within 30 days, or no longer covers MAILRELAY_HOSTNAME / MAILRELAY_TLS_SANS.
RSA 2048 is used on purpose: many printers, copiers and NAS boxes cannot do ECDSA.
"""
from __future__ import annotations

import ipaddress
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from .config import AppConfig

RENEW_BEFORE = timedelta(days=30)


def _wanted_names(cfg: AppConfig) -> list[str]:
    names = []
    for n in [cfg.hostname, *cfg.tls_sans]:
        n = n.strip().lower()
        if n and n not in names:
            names.append(n)
    return names


def _san(names: list[str]) -> x509.SubjectAlternativeName:
    out = []
    for n in names:
        try:
            out.append(x509.IPAddress(ipaddress.ip_address(n)))
        except ValueError:
            out.append(x509.DNSName(n))
    return x509.SubjectAlternativeName(out)


def _cert_names(cert: x509.Certificate) -> set[str]:
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return set()
    return {n.lower() for n in san.get_values_for_type(x509.DNSName)} | \
           {str(ip) for ip in san.get_values_for_type(x509.IPAddress)}


def cert_info(cert_path: str) -> dict:
    cert = x509.load_pem_x509_certificate(Path(cert_path).read_bytes())
    fp = cert.fingerprint(hashes.SHA256()).hex().upper()
    return {
        "subject": cert.subject.rfc4514_string(),
        "names": sorted(_cert_names(cert)),
        "not_after": cert.not_valid_after_utc.isoformat(),
        "sha256": ":".join(fp[i:i + 2] for i in range(0, len(fp), 2)),
        "self_signed": cert.issuer == cert.subject,
    }


def _needs_new(cert_path: Path, key_path: Path, names: list[str]) -> str | None:
    if not cert_path.is_file() or not key_path.is_file():
        return "no certificate yet"
    try:
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    except (ValueError, TypeError) as e:
        return f"existing certificate unreadable ({e})"
    if cert.not_valid_after_utc - datetime.now(timezone.utc) < RENEW_BEFORE:
        return f"expires {cert.not_valid_after_utc:%Y-%m-%d}"
    missing = set(names) - _cert_names(cert)
    if missing:
        return f"does not cover {', '.join(sorted(missing))}"
    return None


def generate(cert_path: Path, key_path: Path, names: list[str], days: int) -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0][:64]),
                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, "mailrelay self-signed")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=days))
            .add_extension(_san(names), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, key_encipherment=True, content_commitment=False,
                                         data_encipherment=False, key_agreement=False, key_cert_sign=False,
                                         crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(key, hashes.SHA256()))
    cert_path.parent.mkdir(parents=True, exist_ok=True)
    # write key first with 0600, then swap both into place
    tmp_key, tmp_cert = key_path.with_suffix(".tmp"), cert_path.with_suffix(".tmp")
    fd = os.open(tmp_key, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))
    tmp_cert.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    os.replace(tmp_key, key_path)
    os.replace(tmp_cert, cert_path)


def prepare_tls(cfg: AppConfig) -> dict | None:
    """Make sure cfg.tls_cert / cfg.tls_key point to usable files. Returns cert info, or None if TLS is off."""
    if cfg.tls_cert:                                      # own certificate always wins
        for label, p in (("MAILRELAY_TLS_CERT", cfg.tls_cert), ("MAILRELAY_TLS_KEY", cfg.tls_key)):
            if not Path(p).is_file():
                raise SystemExit(f"{label}={p} does not exist (mount it, or unset both and use "
                                 f"MAILRELAY_TLS_SELF_SIGNED=true)")
        return {**cert_info(cfg.tls_cert), "source": "file"}
    if not cfg.tls_self_signed:
        return None
    tls_dir = Path(cfg.tls_dir or Path(cfg.log_db).parent / "tls")
    cert_path, key_path = tls_dir / "selfsigned-cert.pem", tls_dir / "selfsigned-key.pem"
    names = _wanted_names(cfg)
    reason = _needs_new(cert_path, key_path, names)
    if reason:
        print(f"  generating self-signed certificate for {', '.join(names)} ({reason})", flush=True)
        generate(cert_path, key_path, names, cfg.tls_self_signed_days)
    cfg.tls_cert, cfg.tls_key = str(cert_path), str(key_path)
    return {**cert_info(cfg.tls_cert), "source": "generated" if reason else "self-signed (reused)"}
