import ipaddress


def normalize_ip(value: str) -> str:
    # Raises ValueError for anything that is not a plain IPv4/IPv6 address,
    # so it is safe to place in a URL path. Scoped IPv6 (%eth0) is rejected
    # because the scope id accepts arbitrary text.
    parsed = ipaddress.ip_address(value.strip())

    if getattr(parsed, "scope_id", None):
        raise ValueError("scoped ip addresses are not accepted")

    return str(parsed)
