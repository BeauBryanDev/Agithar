import ipaddress
from dataclasses import dataclass

from starlette.requests import Request

from app.core.config import get_settings
from app.core.logging import get_logger
from app.utils.cloudflare import is_cloudflare, parse_ip, resolve_client_ip

logger = get_logger("security.client_ip")

# An IPv6 visitor usually owns a whole /64: counting single addresses would
# let one person dodge a limit by rotating inside it.
IPV6_PREFIX = 64
UNIDENTIFIED = "unidentified"


@dataclass(frozen=True)
class Visitor:
    # What a rate limit counts: the address (its /64 for IPv6), an `edge:`
    # key when only a Cloudflare edge was seen, or `unidentified`.
    key: str
    ip: str | None
    identified: bool
    via_cloudflare: bool = False
    # Someone outside Cloudflare sent a CF-Connecting-IP header: ignored.
    forged_header: bool = False


def bucket_of(address: str) -> str:
    ip = ipaddress.ip_address(address)

    if ip.version == 6:
        return str(ipaddress.ip_network(f"{ip}/{IPV6_PREFIX}", strict=False))

    return str(ip)


def connecting_address(request: Request) -> str | None:
    # The address that opened the TCP connection. Behind our own nginx that
    # is loopback, so the real one comes from X-Real-IP, which nginx sets to
    # $remote_addr (a Cloudflare edge, or a visitor that skipped Cloudflare).
    # The header is believed ONLY from a trusted proxy; from anyone else it
    # is just a header any client can write.
    if request.client is None:
        return None

    peer = request.client.host
    parsed = parse_ip(peer)
    trusted = set(get_settings().trusted_proxy_list)

    if parsed is not None and str(parsed) in trusted:
        real = request.headers.get("x-real-ip", "").strip()

        if not real:
            logger.warning("trusted proxy sent no X-Real-IP")

        return real or None

    return peer


def identify(request: Request) -> Visitor:
    # The same rule as the nginx log parser (utils/cloudflare): the visitor
    # address in CF-Connecting-IP counts only when the connection came from
    # a Cloudflare range.
    connecting = connecting_address(request)

    if connecting is None:
        return Visitor(UNIDENTIFIED, None, False)

    resolved = resolve_client_ip(
        connecting, request.headers.get("cf-connecting-ip", "")
    )

    if resolved is not None:
        return Visitor(
            bucket_of(resolved.ip),
            resolved.ip,
            True,
            resolved.via_cloudflare,
            resolved.forged_header,
        )

    # A Cloudflare edge without a usable visitor address, or an address that
    # is not an IP at all. Those visitors share one bucket per edge.
    edge = parse_ip(connecting)

    if edge is not None and is_cloudflare(edge):
        return Visitor(f"edge:{bucket_of(str(edge))}", None, False)

    return Visitor(UNIDENTIFIED, None, False)
