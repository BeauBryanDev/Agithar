import asyncio
import socket
from typing import Any
from collections import Counter

import psutil

MAX_PORT_ROWS = 100
WILDCARD_ADDRS = frozenset({"0.0.0.0", "::"})
LOOPBACK_ADDRS = frozenset({"127.0.0.1", "::1"})


def classify_bind(address: str) -> str:
    if address in WILDCARD_ADDRS:
        return "all_interfaces"

    if address in LOOPBACK_ADDRS:
        return "loopback"

    return "specific"


def describe_process(pid: int | None) -> dict[str, Any]:
    empty = {"pid": pid, "process": None, "user": None}

    if pid is None:
        return empty

    try:
        proc = psutil.Process(pid)

        return {
            "pid": pid,
            "process": proc.name(),
            "user": proc.username(),
        }

    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return empty


def is_listening(conn: Any) -> bool:
    if conn.type == socket.SOCK_STREAM:
        return conn.status == psutil.CONN_LISTEN

    return not conn.raddr


def port_sort_key(row: dict[str, Any]) -> tuple[str, int]:
    return (row["exposure"], row["port"])


def collect_listening_ports() -> list[dict[str, Any]]:
    rows = []

    for conn in psutil.net_connections(kind="inet"):
        if not conn.laddr or not is_listening(conn):
            continue

        row = {
            "port": conn.laddr.port,
            "proto": "tcp" if conn.type == socket.SOCK_STREAM else "udp",
            "bind": conn.laddr.ip,
            "exposure": classify_bind(conn.laddr.ip),
        }
        row.update(describe_process(conn.pid))
        rows.append(row)

    rows.sort(key=port_sort_key)

    return rows[:MAX_PORT_ROWS]


async def get_listening_ports() -> list[dict[str, Any]]:

    return await asyncio.to_thread(collect_listening_ports)


MAX_REMOTE_IPS = 15


def collect_listen_ports(conns: list[Any]) -> set[int]:
    ports = set()

    for conn in conns:
        if conn.status == psutil.CONN_LISTEN and conn.laddr:
            ports.add(conn.laddr.port)

    return ports


def collect_connection_summary() -> dict[str, Any]:
    conns = psutil.net_connections(kind="tcp")
    listen_ports = collect_listen_ports(conns)
    states: Counter = Counter()
    remotes: Counter = Counter()

    for conn in conns:
        if conn.status == psutil.CONN_LISTEN:
            continue

        states[conn.status] += 1

        if not conn.raddr or conn.raddr.ip in LOOPBACK_ADDRS:
            continue

        way = "inbound" if conn.laddr.port in listen_ports else "outbound"
        remotes[(conn.raddr.ip, way)] += 1

    top = []

    for (ip, way), count in remotes.most_common(MAX_REMOTE_IPS):
        top.append({"ip": ip, "direction": way, "connections": count})

    return {"by_state": dict(states), "top_remotes": top}


async def get_connection_summary() -> dict[str, Any]:
    return await asyncio.to_thread(collect_connection_summary)