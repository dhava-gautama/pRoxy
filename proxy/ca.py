from __future__ import annotations

import logging
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes

logger = logging.getLogger("pRoxy.ca")


def get_ca_dir() -> Path:
    """Return the mitmproxy CA certificate directory."""
    return Path(os.path.expanduser("~/.mitmproxy"))


def get_ca_cert_path(fmt: str = "pem") -> Path | None:
    """Return path to the CA certificate file, or None if it doesn't exist yet."""
    ca_dir = get_ca_dir()
    if fmt == "pem":
        p = ca_dir / "mitmproxy-ca-cert.pem"
    elif fmt == "crt":
        p = ca_dir / "mitmproxy-ca-cert.pem"
    elif fmt == "p12":
        p = ca_dir / "mitmproxy-ca-cert.p12"
    else:
        p = ca_dir / "mitmproxy-ca-cert.pem"
    return p if p.exists() else None


def get_android_cert_path() -> tuple[Path, str] | None:
    """Generate the Android system CA cert (<hash>.0) and return (path, filename).

    Android expects certs in /system/etc/security/cacerts/ named as
    <subject_hash_old>.0 in PEM format with human-readable text prepended.
    """
    pem_path = get_ca_cert_path("pem")
    if pem_path is None:
        return None

    ca_dir = get_ca_dir()

    # Get the subject_hash_old using openssl
    try:
        result = subprocess.run(
            ["openssl", "x509", "-inform", "PEM", "-subject_hash_old", "-noout", "-in", str(pem_path)],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode != 0:
            return None
        cert_hash = result.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None

    filename = f"{cert_hash}.0"
    out_path = ca_dir / filename

    # Generate if not already cached
    if not out_path.exists():
        try:
            # Get human-readable text
            text_result = subprocess.run(
                ["openssl", "x509", "-inform", "PEM", "-text", "-noout", "-in", str(pem_path)],
                capture_output=True, text=True, timeout=5,
            )
            pem_content = pem_path.read_text()
            # Android format: readable text + PEM block
            out_path.write_text(text_result.stdout + pem_content)
        except Exception:
            return None

    return out_path, filename


def get_ca_info() -> dict | None:
    """Read the CA certificate and return fingerprint + validity dates."""
    pem_path = get_ca_cert_path("pem")
    if pem_path is None:
        return None

    pem_bytes = pem_path.read_bytes()
    cert = x509.load_pem_x509_certificate(pem_bytes)

    fingerprint = cert.fingerprint(hashes.SHA256()).hex(":")
    subject = cert.subject.rfc4514_string()
    not_before = cert.not_valid_before_utc.isoformat()
    not_after = cert.not_valid_after_utc.isoformat()

    return {
        "fingerprint": fingerprint,
        "subject": subject,
        "not_before": not_before,
        "not_after": not_after,
    }


def regenerate_ca() -> bool:
    """Delete existing CA files and trigger fresh generation via mitmproxy."""
    ca_dir = get_ca_dir()

    # Remove all mitmproxy-generated cert/key/dhparam files and android hash certs
    patterns = ["mitmproxy-ca*", "mitmproxy-dhparam*", "*.0"]
    for pattern in patterns:
        for f in ca_dir.glob(pattern):
            try:
                f.unlink()
                logger.info("Deleted %s", f)
            except OSError as e:
                logger.warning("Failed to delete %s: %s", f, e)

    # Trigger fresh CA generation via mitmproxy's CertStore
    try:
        from mitmproxy.certs import CertStore
        CertStore.from_store(str(ca_dir), "mitmproxy", key_size=2048)
        logger.info("Regenerated CA certificates in %s", ca_dir)
        return True
    except Exception:
        logger.exception("Failed to regenerate CA certificates")
        return False
