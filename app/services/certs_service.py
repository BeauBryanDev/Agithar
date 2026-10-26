import asyncio
import socket
import ssl
import time
from datetime import datetime, timezone
from typing import Any

TLS_PORT = 443
CONNECT_TIMEOUT_SECONDS = 5
WARNING_DAYS = 30
CRITICAL_DAYS = 14
SECONDS_PER_DAY = 86400
ERROR_MAX_LEN = 80
NO_EXPIRY_SORT = 10**6
CERT_TARGETS = {
    "agithar.tensorkingdom.com": "127.0.0.1",
    "api-apple.tensorkingdom.com": "127.0.0.1",
    # todo: add  basil and florabelle certs
}


def classify_days(days: int) -> str:
    if days <= CRITICAL_DAYS:
        return "critical"

    if days <= WARNING_DAYS:
        return "warning"

    return "ok"


def fetch_not_after(host: str, address: str) -> str:
    context = ssl.create_default_context()

    with socket.create_connection(
        (address, TLS_PORT), timeout=CONNECT_TIMEOUT_SECONDS
    ) as sock:
        with context.wrap_socket(sock, server_hostname=host) as tls:
            return tls.getpeercert()["notAfter"]


def format_expiry(expires: float) -> str:
    moment = datetime.fromtimestamp(expires, tz=timezone.utc)

    return moment.date().isoformat()


def check_target(host: str, address: str) -> dict[str, Any]:
    try:
        not_after = fetch_not_after(host, address)

    except ssl.SSLCertVerificationError as exc:
        return {
            "host": host,
            "status": "invalid",
            "detail": str(exc.verify_message)[:ERROR_MAX_LEN],
        }

    except (OSError, ssl.SSLError):
        return {"host": host, "status": "unreachable"}

    expires = ssl.cert_time_to_seconds(not_after)
    days = int((expires - time.time()) / SECONDS_PER_DAY)

    return {
        "host": host,
        "status": classify_days(days),
        "days_left": days,
        "expires_utc": format_expiry(expires),
    }


def sort_key(row: dict[str, Any]) -> int:
    return row.get("days_left", NO_EXPIRY_SORT)


async def get_certificates() -> list[dict[str, Any]]:
    jobs = []

    for host, address in CERT_TARGETS.items():
        jobs.append(asyncio.to_thread(check_target, host, address))

    rows = list(await asyncio.gather(*jobs))
    rows.sort(key=sort_key)

    return rows