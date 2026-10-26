import asyncio
import hashlib
import socket
import ssl
import time
from datetime import datetime, timezone
from functools import cache
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.x509.oid import NameOID

from app.core.config import get_settings
from app.security.sanitize import sanitize_string

TLS_PORT = 443
LOCAL_ADDRESS = "127.0.0.1"
CONNECT_TIMEOUT_SECONDS = 5
WARNING_DAYS = 30
CRITICAL_DAYS = 14
SECONDS_PER_DAY = 86400
ERROR_MAX_LEN = 80
TEXT_MAX_LEN = 120
MAX_NAMES = 10
FINGERPRINT_CHARS = 16
NO_EXPIRY_SORT = 10**6
ORIGIN_CA_PATH = (
    Path(__file__).resolve().parents[1] / "utils" / "cloudflare_origin_ca.pem"
)
ORIGIN_MARKER = "cloudflare origin"
NOTES = (
    "Visitors reach these sites through Cloudflare, which serves its own "
    "edge certificate and renews it by itself. These rows are the origin "
    "certificates that nginx on this host serves to Cloudflare.",
    "A Cloudflare Origin certificate is never renewed automatically, and "
    "it is trusted only until the Cloudflare Origin CA root expires "
    "(trusted_until_utc).",
)


@cache
def origin_ca_expiry() -> float:
    # The earliest expiry among the Cloudflare Origin CA roots in the bundle.
    roots = x509.load_pem_x509_certificates(ORIGIN_CA_PATH.read_bytes())

    return min(root.not_valid_after_utc.timestamp() for root in roots)


@cache
def verified_context() -> ssl.SSLContext:
    # Public authorities plus the Cloudflare Origin CA roots.
    context = ssl.create_default_context()
    context.load_verify_locations(cafile=str(ORIGIN_CA_PATH))

    return context


@cache
def unverified_context() -> ssl.SSLContext:
    # Only to describe a certificate that already failed verification.
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    return context


def fetch_certificate(
    host: str, context: ssl.SSLContext, port: int
) -> bytes:
    with socket.create_connection(
        (LOCAL_ADDRESS, port), timeout=CONNECT_TIMEOUT_SECONDS
    ) as sock:
        with context.wrap_socket(sock, server_hostname=host) as tls:
            return tls.getpeercert(binary_form=True)


def classify_days(days: int) -> str:
    if days <= CRITICAL_DAYS:
        return "critical"

    if days <= WARNING_DAYS:
        return "warning"

    return "ok"


def format_date(moment: float) -> str:
    return datetime.fromtimestamp(moment, tz=timezone.utc).date().isoformat()


def clean(text: str) -> str:
    return sanitize_string(text, TEXT_MAX_LEN)


def issuer_name(cert: x509.Certificate) -> str:
    parts = []

    for oid in (NameOID.ORGANIZATION_NAME, NameOID.ORGANIZATIONAL_UNIT_NAME,
                NameOID.COMMON_NAME):
        for attribute in cert.issuer.get_attributes_for_oid(oid):
            parts.append(str(attribute.value))

    return clean(", ".join(parts)) or "unknown"


def dns_names(cert: x509.Certificate) -> list[str]:
    try:
        extension = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        )

    except x509.ExtensionNotFound:
        return []

    names = extension.value.get_values_for_type(x509.DNSName)

    return [clean(name.lower()) for name in names[:MAX_NAMES]]


def name_covers(name: str, host: str) -> bool:
    if name == host:
        return True

    if not name.startswith("*."):
        return False

    _, _, parent = host.partition(".")

    return parent == name[2:]


def describe(der: bytes, host: str) -> dict[str, Any]:
    cert = x509.load_der_x509_certificate(der)
    names = dns_names(cert)
    issuer = issuer_name(cert)
    expires = cert.not_valid_after_utc.timestamp()
    is_origin = ORIGIN_MARKER in issuer.lower()
    trusted_until = min(expires, origin_ca_expiry()) if is_origin else expires
    covers = False

    for name in names:
        if name_covers(name, host):
            covers = True

    return {
        "issuer": issuer,
        "issuer_kind": "cloudflare_origin" if is_origin else "other",
        "names": names,
        "covers_host": covers,
        "expires_utc": format_date(expires),
        "trusted_until_utc": format_date(trusted_until),
        "days_left": int((trusted_until - time.time()) / SECONDS_PER_DAY),
        "fingerprint": hashlib.sha256(der).hexdigest()[:FINGERPRINT_CHARS],
    }


def check_site(name: str, host: str, port: int = TLS_PORT) -> dict[str, Any]:
    row: dict[str, Any] = {"site": name, "host": host}
    problem = None

    try:
        der = fetch_certificate(host, verified_context(), port)

    except ssl.SSLCertVerificationError as exc:
        problem = clean(str(exc.verify_message))[:ERROR_MAX_LEN]

        try:
            der = fetch_certificate(host, unverified_context(), port)

        except (OSError, ssl.SSLError):
            row.update({"status": "invalid", "detail": problem})

            return row

    except (OSError, ssl.SSLError):
        row["status"] = "unreachable"

        return row

    try:
        row.update(describe(der, host))

    except ValueError:
        row.update({"status": "invalid", "detail": "unreadable certificate"})

        return row

    if problem is not None:
        row.update({"status": "invalid", "detail": problem})
    else:
        row["status"] = classify_days(row["days_left"])

    return row


def sort_key(row: dict[str, Any]) -> int:
    return row.get("days_left", NO_EXPIRY_SORT)


def shared_certificates(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[str, list[str]] = {}

    for row in rows:
        if "fingerprint" in row:
            groups.setdefault(row["fingerprint"], []).append(row["site"])

    shared = []

    for fingerprint, sites in groups.items():
        if len(sites) > 1:
            shared.append({"fingerprint": fingerprint, "sites": sites})

    return shared


async def get_certificates() -> dict[str, Any]:
    jobs = []

    for name, host in get_settings().tls_site_map.items():
        jobs.append(asyncio.to_thread(check_site, name, host))

    rows = list(await asyncio.gather(*jobs))
    rows.sort(key=sort_key)

    return {
        "certificates": rows,
        "shared_certificates": shared_certificates(rows),
        "notes": list(NOTES),
    }
