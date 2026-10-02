from typing import Any

import httpx

from app.core.config import get_settings
from app.core.logging import get_logger
from app.security.sanitize import sanitize_string
from app.utils.network import normalize_ip


API_URL = "https://api.abuseipdb.com/api/v2/check"
REQUEST_TIMEOUT_SECONDS = 5.0
MAX_AGE_DAYS = 90
MAX_FIELD_CHARS = 64


logger = get_logger("services.abuse_ip")


class AbuseIPLookupError(Exception):
    pass


def clean_text(value: Any) -> str | None:
    # External text is untrusted: only strings pass, sanitized and capped.
    if not isinstance(value, str):
        return None

    return sanitize_string(value, MAX_FIELD_CHARS)


async def check_ip(ip: str) -> dict[str, Any]:

    settings = get_settings()

    if settings.abuseipdb_api_key is None:
        raise AbuseIPLookupError("ABUSEIPDB_API_KEY is not configured")

    try:
        ip = normalize_ip(ip)
        
    except ValueError:
        raise AbuseIPLookupError("invalid ip address") from None

    api_key = settings.abuseipdb_api_key.get_secret_value()

    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": MAX_AGE_DAYS}

    async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT_SECONDS) as client:
        try:
            response = await client.get(API_URL,
                                        headers=headers,
                                        params=params
                                        )
            response.raise_for_status()

        except httpx.HTTPError as exc:
            logger.warning(
                "abuseipdb lookup failed: %s",
                type(exc).__name__,
                extra={"ip": ip},
            )
            raise AbuseIPLookupError(
                f"abuseipdb lookup failed for {ip}"
            ) from None

    try:
        data = response.json().get("data", {})
        
    except (ValueError, AttributeError):
        raise AbuseIPLookupError("abuseipdb returned an invalid body") from None

    if not isinstance(data, dict):
        raise AbuseIPLookupError("abuseipdb returned an invalid body")

    return {
        "ip": ip,
        "abuse_confidence_score": data.get("abuseConfidenceScore"),
        "total_reports": data.get("totalReports"),
        "country_code": clean_text(data.get("countryCode")),
        "is_whitelisted": data.get("isWhitelisted"),
        "last_reported_at": clean_text(data.get("lastReportedAt")),
    }
