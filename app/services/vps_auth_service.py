import asyncio
import ipaddress
import re
from collections import Counter
from typing import Any

from app.services.os_service import OsQueryError

AUTH_LOG_PATH = "/var/log/auth.log"
TAIL_BYTES = 512 * 1024
MAX_TOP = 10
MAX_RECENT = 20
USER_MAX_LEN = 32
UNSAFE_USER_CHARS = re.compile(r"[^A-Za-z0-9._-]")
ACCEPTED = re.compile(
    r"^(\S+) .*sshd\[\d+\]: Accepted (\w+) for (\S+) from (\S+) port"
)
FAILED = re.compile(
    r"^(\S+) .*sshd\[\d+\]: Failed (\w+) for (?:invalid user )?(\S+) "
    r"from (\S+) port"
)


def clean_user(name: str) -> str:
    return UNSAFE_USER_CHARS.sub("_", name)[:USER_MAX_LEN]


def clean_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value))

    except ValueError:
        return "invalid"


def read_tail(path: str) -> list[str]:
    try:
        with open(path, "rb") as handle:
            handle.seek(0, 2)
            size = handle.tell()
            handle.seek(max(0, size - TAIL_BYTES))
            data = handle.read()

    except FileNotFoundError:
        raise OsQueryError("auth log not found") from None

    except PermissionError:
        raise OsQueryError("auth log not readable") from None

    return data.decode("utf-8", errors="replace").splitlines()


def build_event(match: re.Match) -> dict[str, str]:
    when, method, user, ip = match.groups()

    return {
        "time": when[:32],
        "method": method,
        "user": clean_user(user),
        "ip": clean_ip(ip),
    }


def parse_events(
    lines: list[str],
) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    accepted = []
    failed = []

    for line in lines:
        match = ACCEPTED.match(line)

        if match:
            accepted.append(build_event(match))
            continue

        match = FAILED.match(line)

        if match:
            failed.append(build_event(match))

    return accepted, failed


def top_counts(values: list[str], 
               label: str
               ) -> list[dict[str, Any]]:
    
    rows = []

    for value, count in Counter(values).most_common(MAX_TOP):
        rows.append({label: value, "attempts": count})

    return rows


def collect_auth_activity() -> dict[str, Any]:
    accepted, failed = parse_events(read_tail(AUTH_LOG_PATH))
    failed_ips = [event["ip"] for event in failed]
    failed_users = [event["user"] for event in failed]

    return {
        "window": "last 512 KB of auth.log",
        "accepted_recent": accepted[-MAX_RECENT:],
        "failed_total": len(failed),
        "failed_top_ips": top_counts(failed_ips, "ip"),
        "failed_top_users": top_counts(failed_users, "user"),
    }


async def get_auth_activity() -> dict[str, Any]:
    
    return await asyncio.to_thread(collect_auth_activity)