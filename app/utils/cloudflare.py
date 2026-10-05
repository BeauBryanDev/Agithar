import ipaddress
from dataclasses import dataclass

from app.utils.network import normalize_ip

# Cloudflare's published ranges, fetched from https://www.cloudflare.com/ips-v4
# and https://www.cloudflare.com/ips-v6 on 2026-10-05. They change rarely;
# refresh them by hand from those two URLs.
CLOUDFLARE_RANGES = (
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
    "2400:cb00::/32",
    "2606:4700::/32",
    "2803:f800::/32",
    "2405:b500::/32",
    "2405:8100::/32",
    "2a06:98c0::/29",
    "2c0f:f248::/32",
)
NETWORKS = tuple(ipaddress.ip_network(cidr) for cidr in CLOUDFLARE_RANGES)
NO_HEADER = ("", "-")


@dataclass(frozen=True)
class ClientIp:
    ip: str
    via_cloudflare: bool
    # A client outside Cloudflare sent a CF-Connecting-IP header: ignored.
    forged_header: bool = False


Address = ipaddress.IPv4Address | ipaddress.IPv6Address


def parse_ip(text: str) -> Address | None:
    try:
        parsed = ipaddress.ip_address(normalize_ip(text))

    except ValueError:
        return None

    # An IPv4-mapped IPv6 address is the same host as its IPv4 form.
    if parsed.version == 6 and parsed.ipv4_mapped is not None:
        return parsed.ipv4_mapped

    return parsed


def is_cloudflare(address: Address) -> bool:
    return any(
        address in network
        for network in NETWORKS
        if network.version == address.version
    )


def resolve_client_ip(remote_addr: str, cf_header: str) -> ClientIp | None:
    # The CF-Connecting-IP header is believed ONLY when the connection really
    # came from a Cloudflare address; anyone else can send any header.
    # Returns None when the visitor cannot be identified.
    remote = parse_ip(remote_addr)

    if remote is None:
        return None

    header = cf_header.strip()
    has_header = header not in NO_HEADER

    if not is_cloudflare(remote):
        return ClientIp(str(remote), False, forged_header=has_header)

    visitor = parse_ip(header) if has_header else None

    # A real visitor is never a private or reserved address.
    if visitor is None or not visitor.is_global:
        return None

    return ClientIp(str(visitor), True)
