import asyncio
from datetime import datetime, timezone
from typing import Any

import psutil

SSH_PORT = 22
MAX_ROWS = 50
EXPECTED_USERS = frozenset({"ubuntu", "agithar", "admin"})


def format_start(timestamp: float) -> str:
    moment = datetime.fromtimestamp(timestamp, tz=timezone.utc)

    return moment.isoformat(timespec="seconds")


def collect_logged_in_users() -> list[dict[str, Any]]:
    rows = []

    for session in psutil.users():
        rows.append(
            {
                "user": session.name,
                "terminal": session.terminal,
                "from_host": session.host or "local",
                "started_utc": format_start(session.started),
                "expected": session.name in EXPECTED_USERS,
            }
        )

    return rows[:MAX_ROWS]


def is_ssh_connection(conn: Any) -> bool:
    if conn.status != psutil.CONN_ESTABLISHED:
        return False

    if not conn.laddr or not conn.raddr:
        return False

    return conn.laddr.port == SSH_PORT


def collect_ssh_connections() -> list[dict[str, Any]]:
    
    rows = []

    for conn in psutil.net_connections(kind="tcp"):
        if is_ssh_connection(conn):
            rows.append(
                {
                    "remote_ip": conn.raddr.ip,
                    "remote_port": conn.raddr.port,
                }
            )

    return rows[:MAX_ROWS]


def count_remote_sessions(users: list[dict[str, Any]]) -> int:
    return sum(1 for row in users if row["from_host"] != "local")


def collect_sessions() -> dict[str, Any]:
    users = collect_logged_in_users()
    ssh = collect_ssh_connections()
    unexpected = []

    for row in users:
        if not row["expected"]:
            unexpected.append(row["user"])

    return {
        "logged_in": users,
        "ssh_established": ssh,
        "unexpected_users": unexpected,
        "ssh_exceeds_sessions": len(ssh) > count_remote_sessions(users),
    }


async def get_sessions() -> dict[str, Any]:
    return await asyncio.to_thread(collect_sessions)