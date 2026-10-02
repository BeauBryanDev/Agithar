import base64
import re
from typing import Any

import httpx

from app.core.config import get_settings
from app.core.logging import get_logger
from app.security.sanitize import sanitize_string
from app.utils.network import normalize_ip

API_BASE = "https://www.virustotal.com/api/v3"
REQUEST_TIMEOUT_SECONDS = 10.0
RATE_LIMIT_PER_MINUTE = 4  # free tier of VirusTotal
MAX_URL_CHARS = 2048
MAX_NAMES = 5
MAX_FIELD_CHARS = 128
HASH_PATTERN = re.compile(r"^(?:[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})$")
URL_SCHEMES = ("http://", "https://")


logger = get_logger("services.virustotal")


class VirusTotalLookupError(Exception):
    pass


def encode_url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


def as_count(value: Any) -> int:
    if isinstance(value, int) and not isinstance(value, bool):
        return value

    return 0


def get_attributes(data: dict[str, Any]) -> dict[str, Any]:
    attributes = data.get("data", {})

    if isinstance(attributes, dict):
        attributes = attributes.get("attributes", {})

    if not isinstance(attributes, dict):
        return {}

    return attributes


def extract_stats(data: dict[str, Any]) -> dict[str, int]:
    stats = get_attributes(data).get("last_analysis_stats", {})

    if not isinstance(stats, dict):
        stats = {}

    return {
        "malicious": as_count(stats.get("malicious")),
        "suspicious": as_count(stats.get("suspicious")),
        "harmless": as_count(stats.get("harmless")),
        "undetected": as_count(stats.get("undetected")),
    }


def clean_names(values: Any) -> list[str]:
    # File names come from uploaders (attacker-controlled): sanitize them.
    if not isinstance(values, list):
        return []

    names = []

    for value in values[:MAX_NAMES]:
        if isinstance(value, str):
            names.append(sanitize_string(value, MAX_FIELD_CHARS))

    return names


def validate_hash(file_hash: str) -> str:
    file_hash = file_hash.strip()

    if not HASH_PATTERN.match(file_hash):
        raise VirusTotalLookupError("invalid file hash")

    return file_hash.lower()


def validate_url(url: str) -> str:
    url = url.strip()

    if len(url) > MAX_URL_CHARS or not url.lower().startswith(URL_SCHEMES):
        raise VirusTotalLookupError("invalid url")

    return url


async def query(kind: str, path: str) -> dict[str, Any] | None:
    settings = get_settings()

    if settings.virustotal_api_key is None:
        raise VirusTotalLookupError("VIRUSTOTAL_API_KEY is not configured")

    headers = {"x-apikey": settings.virustotal_api_key.get_secret_value()}

    async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT_SECONDS) as client:
        try:
            response = await client.get(f"{API_BASE}{path}", headers=headers)

            if response.status_code == 404:
                return None

            response.raise_for_status()

        except httpx.HTTPError as exc:
            # Log only the lookup kind: the path can embed the url or ip.
            logger.warning(
                "virustotal lookup failed: %s",
                type(exc).__name__,
                extra={"kind": kind},
            )
            raise VirusTotalLookupError(
                f"virustotal {kind} lookup failed"
            ) from None

    try:
        data = response.json()
    except ValueError:
        raise VirusTotalLookupError("virustotal returned an invalid body") from None

    if not isinstance(data, dict):
        raise VirusTotalLookupError("virustotal returned an invalid body")

    return data


async def check_ip(ip: str) -> dict[str, Any]:
    try:
        ip = normalize_ip(ip)
    except ValueError:
        raise VirusTotalLookupError("invalid ip address") from None

    data = await query("ip", f"/ip_addresses/{ip}")

    if data is None:
        return {"ip": ip, "found": False}

    return {"ip": ip, "found": True, **extract_stats(data)}


async def check_hash(file_hash: str) -> dict[str, Any]:
    file_hash = validate_hash(file_hash)
    data = await query("hash", f"/files/{file_hash}")

    if data is None:
        return {"hash": file_hash, "found": False}

    attributes = get_attributes(data)

    return {
        "hash": file_hash,
        "found": True,
        "type_description": sanitize_string(
            str(attributes.get("type_description") or ""), MAX_FIELD_CHARS
        ),
        "names": clean_names(attributes.get("names")),
        **extract_stats(data),
    }


async def check_url(url: str) -> dict[str, Any]:
    url = validate_url(url)
    data = await query("url", f"/urls/{encode_url_id(url)}")

    # The url itself is not echoed back: the caller already holds it.
    if data is None:
        return {"found": False}

    return {"found": True, **extract_stats(data)}
