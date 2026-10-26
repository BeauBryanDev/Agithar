import asyncio
import re
import time
from typing import Any

import psutil

TOP_N = 10
CPU_SAMPLE_SECONDS = 0.5
CMD_MAX_LEN = 200
NAME_MAX_LEN = 32
REDACTED = "[redacted]"
SENSITIVE_WORDS = ("pass", "token", "secret", "key", "auth", "cred")
SERVER_PARENTS = frozenset(
    {"nginx", "apache2", "gunicorn", "uwsgi", "java", "php-fpm"}
)
SUSPECT_CHILDREN = frozenset(
    {"sh", "bash", "dash", "zsh", "nc", "ncat", "socat"}
)
PROCESS_ERRORS = (
    psutil.NoSuchProcess,
    psutil.AccessDenied,
    psutil.ZombieProcess,
)
KEY_VALUE = re.compile(
    r"^(-{0,2}[\w-]*(?:pass|token|secret|key|auth|cred)[\w-]*)=.*$",
    re.IGNORECASE,
)
URL_CREDS = re.compile(r"(://[^/\s:@]+):[^@\s]+@")
UNSAFE_CHARS = re.compile(r"[^\x20-\x7e]")


def is_sensitive_flag(arg: str) -> bool:
    if not arg.startswith("-"):
        return False

    lowered = arg.lower()

    return any(word in lowered for word in SENSITIVE_WORDS)


def redact_args(args: list[str]) -> list[str]:
    
    parts = []
    hide_next = False

    for arg in args:
        if hide_next:
            parts.append(REDACTED)
            hide_next = False
            continue

        match = KEY_VALUE.match(arg)

        if match:
            parts.append(f"{match.group(1)}={REDACTED}")
            continue

        hide_next = is_sensitive_flag(arg)
        parts.append(URL_CREDS.sub(r"\1:" + REDACTED + "@", arg))

    return parts


def clean_text(text: str, limit: int) -> str:
    return UNSAFE_CHARS.sub("?", text)[:limit]


def clean_command(args: list[str], name: str) -> str:
    if not args:
        return f"[{name}]"

    return clean_text(" ".join(redact_args(args)), CMD_MAX_LEN)


def uptime_minutes(created: float) -> int:
    return int((time.time() - created) / 60)


def read_process(proc: psutil.Process) -> dict[str, Any] | None:
    try:
        with proc.oneshot():
            name = clean_text(proc.name(), NAME_MAX_LEN)

            return {
                "pid": proc.pid,
                "ppid": proc.ppid(),
                "name": name,
                "user": clean_text(proc.username(), NAME_MAX_LEN),
                "cpu_percent": proc.cpu_percent(None),
                "memory_percent": round(proc.memory_percent(), 1),
                "uptime_min": uptime_minutes(proc.create_time()),
                "command": clean_command(proc.cmdline(), name),
            }

    except PROCESS_ERRORS:
        return None


def prime_cpu(procs: list[psutil.Process]) -> None:
    for proc in procs:
        try:
            proc.cpu_percent(None)

        except PROCESS_ERRORS:
            continue


def cpu_key(row: dict[str, Any]) -> float:
    return row["cpu_percent"]


def memory_key(row: dict[str, Any]) -> float:
    return row["memory_percent"]


def find_suspicious(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    
    names = {
        row["pid"]: row["name"] for row in rows
        }
    
    found = []

    for row in rows:
        parent = names.get(row["ppid"], "")

        if parent in SERVER_PARENTS and row["name"] in SUSPECT_CHILDREN:
            found.append({**row, "parent": parent})

    return found[:TOP_N]


def collect_processes() -> dict[str, Any]:
    
    procs = list(psutil.process_iter())
    prime_cpu(procs)
    time.sleep(CPU_SAMPLE_SECONDS)
    rows = []

    for proc in procs:
        row = read_process(proc)

        if row:
            rows.append(row)

    by_cpu = sorted(rows, key=cpu_key, reverse=True)
    by_memory = sorted(rows, key=memory_key, reverse=True)

    return {
        "total_processes": len(rows),
        "top_cpu": by_cpu[:TOP_N],
        "top_memory": by_memory[:TOP_N],
        "suspicious_children": find_suspicious(rows),
    }


async def get_processes() -> dict[str, Any]:
    
    return await asyncio.to_thread(collect_processes)