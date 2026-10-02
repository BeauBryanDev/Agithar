from typing import Any

import httpx

from app.core.config import get_settings
from app.core.logging import get_logger
from app.security.sanitize import sanitize_string
from app.utils.network import normalize_ip

API_URL = "https://api.shodan.io/shodan/host/{ip}"
REQUEST_TIMEOUT_SECONDS = 5.0
MAX_FIELD_CHARS = 128
MAX_HOSTNAMES = 50
MAX_VULNS = 50
MAX_PORTS = 100


logger = get_logger("services.shodan")

# Use this service only against my own VPS infrastructure, never against
# third-party servers.


class ShodanLookupError(Exception):
    pass


def clean_text(value: Any) -> str | None:
    # Shodan text (org, reverse DNS) is attacker-influenced: sanitize it.
    if not isinstance(value, str):
        return None

    return sanitize_string(value, MAX_FIELD_CHARS)


def clean_text_list(values: Any, limit: int) -> list[str]:

    if not isinstance(values, list):
        return []

    cleaned = []

    for value in values[:limit]:
        text = clean_text(value)

        if text:
            cleaned.append(text)

    return cleaned


def clean_ports(values: Any) -> list[int]:

    if not isinstance(values, list):
        return []

    ports = []

    for value in values[:MAX_PORTS]:
        if isinstance(value, int) and not isinstance(value, bool):
            ports.append(value)

    return ports


async def check_ip(ip: str) -> dict[str, Any]:
    settings = get_settings()

    if settings.shodan_api_key is None:
        raise ShodanLookupError("SHODAN_API_KEY is not configured")

    try:
        ip = normalize_ip(ip)
    except ValueError:
        raise ShodanLookupError("invalid ip address") from None

    api_key = settings.shodan_api_key.get_secret_value()

    url = API_URL.format(ip=ip)
    params = {"key": api_key}

    async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT_SECONDS) as client:

        try:
            response = await client.get(url, params=params)
            response.raise_for_status()

        except httpx.HTTPStatusError as exc:
            status = exc.response.status_code

            if status == 404:
                return {"ip": ip, "found": False}

            # Never log exc itself: its text contains the URL with the key.
            logger.warning(
                "shodan lookup failed: http %s",
                status,
                extra={"ip": ip},
            )
            raise ShodanLookupError(f"shodan lookup failed for {ip}") from None

        except httpx.HTTPError as exc:
            logger.warning(
                "shodan lookup failed: %s",
                type(exc).__name__,
                extra={"ip": ip},
            )
            raise ShodanLookupError(f"shodan lookup failed for {ip}") from None

    try:
        data = response.json()
    except ValueError:
        raise ShodanLookupError("shodan returned an invalid body") from None

    if not isinstance(data, dict):
        raise ShodanLookupError("shodan returned an invalid body")

    return {
        "ip": ip,
        "found": True,
        "org": clean_text(data.get("org")),
        "isp": clean_text(data.get("isp")),
        "os": clean_text(data.get("os")),
        "ports": clean_ports(data.get("ports")),
        "hostnames": clean_text_list(data.get("hostnames"), MAX_HOSTNAMES),
        "vulns": clean_text_list(list(data.get("vulns") or []), MAX_VULNS),
    }
