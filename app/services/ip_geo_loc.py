import ipaddress
from typing import Any

import httpx

from app.core.logging import get_logger
from app.security.sanitize import sanitize_string
from app.utils.network import normalize_ip

# WARNING: the free ip-api.com tier is HTTP only. Responses can be altered
# on the network path, so treat every field as untrusted.
API_URL = "http://ip-api.com/json/{ip}"
API_FIELDS = "status,message,country,regionName,city,lat,lon,isp,org,as,query"
REQUEST_TIMEOUT_SECONDS = 5.0
RATE_LIMIT_PER_MINUTE = 45  # free tier of ip-api.com
MAX_FIELD_CHARS = 128
MAX_LATITUDE = 90.0
MAX_LONGITUDE = 180.0


logger = get_logger("services.ip_geo_loc")


class GeoLookupError(Exception):
    pass


def is_public_ip(ip: str) -> bool:
    # is_global excludes CGNAT (100.64/10) and unspecified, but not multicast.
    try:
        parsed = ipaddress.ip_address(ip)

        return parsed.is_global and not parsed.is_multicast

    except ValueError:
        return False


def clean_text(value: Any) -> str | None:
    # Whois-derived text (isp, org, as) is controlled by network owners.
    if not isinstance(value, str):
        return None

    return sanitize_string(value, MAX_FIELD_CHARS)


def clean_coordinate(value: Any, limit: float) -> float | None:

    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None

    if abs(value) > limit:
        return None

    return float(value)


async def geo_lookup(ip: str) -> dict[str, Any]:

    try:
        ip = normalize_ip(ip)
    except ValueError:
        raise GeoLookupError("invalid ip address") from None

    if not is_public_ip(ip):
        return {
            "ip": ip,
            "skipped": True,
            "reason": "private, loopback, or reserved address",
        }

    url = API_URL.format(ip=ip)

    async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT_SECONDS) as client:
        try:
            response = await client.get(url, params={"fields": API_FIELDS})
            response.raise_for_status()

        except httpx.HTTPError as exc:
            logger.warning(
                "geo lookup failed: %s",
                type(exc).__name__,
                extra={"ip": ip},
            )
            raise GeoLookupError(f"geo lookup failed for {ip}") from None

    try:
        data = response.json()
    except ValueError:
        raise GeoLookupError("geo service returned an invalid body") from None

    if not isinstance(data, dict):
        raise GeoLookupError("geo service returned an invalid body")

    if data.get("status") != "success":
        # The API message is external text: it is not logged or re-raised.
        logger.warning("geo lookup rejected", extra={"ip": ip})
        raise GeoLookupError(f"geo lookup rejected for {ip}")

    return {
        "ip": ip,
        "country": clean_text(data.get("country")),
        "region": clean_text(data.get("regionName")),
        "city": clean_text(data.get("city")),
        "lat": clean_coordinate(data.get("lat"), MAX_LATITUDE),
        "lon": clean_coordinate(data.get("lon"), MAX_LONGITUDE),
        "isp": clean_text(data.get("isp")),
        "org": clean_text(data.get("org")),
        "asn": clean_text(data.get("as")),
        "skipped": False,
    }
