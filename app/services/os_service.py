import asyncio
import shutil
import subprocess
from typing import Any

import psutil

from app.core.logging import get_logger

SYSTEMCTL_TIMEOUT_SECONDS = 5
NOT_FOUND_EXIT_CODE = 4
STATE_NOT_FOUND = "not-found"
STATE_UNKNOWN = "unknown"
KNOWN_STATES = frozenset(
    {"active", "inactive", "failed", "activating", "deactivating", "reloading"}
)
# Web App Projects Aightar must save-guard and monitor sibling services, 
# and the system services it depends on.
SIBLING_UNITS = {
    "florabelle": "florabelle.service",
    "basil": "maisonroast.service",
}
SYSTEM_UNITS = {
    "nginx": "nginx.service",
    "agithar": "cybersoc.service",
}
ALLOWED_UNITS = frozenset(SIBLING_UNITS.values()) | frozenset(
    SYSTEM_UNITS.values()
)
# Services whitelist: only these unit names ever reach systemctl.
# subprocess.run is used with an argument list, never shell=True, so a
# prompt injection cannot turn a unit name into a command.

logger = get_logger("services.os")


class OsQueryError(Exception):
    pass


def get_resource_usage() -> dict[str, Any]:
    disk = shutil.disk_usage("/")
    net = psutil.net_io_counters()

    return {
        "cpu_percent": psutil.cpu_percent(interval=1.0),
        "memory_percent": psutil.virtual_memory().percent,
        "disk_percent": round(disk.used / disk.total * 100, 1),
        "disk_free_gb": round(disk.free / (1024**3), 2),
        "net_bytes_sent": net.bytes_sent,
        "net_bytes_recv": net.bytes_recv,
    }


def get_service_status(service_name: str) -> str:
    if not isinstance(service_name, str) or service_name not in ALLOWED_UNITS:
        raise OsQueryError("service is not monitored")

    try:
        result = subprocess.run(
            ["systemctl", "is-active", service_name],
            capture_output=True,
            text=True,
            timeout=SYSTEMCTL_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired:
        logger.warning("systemctl timed out", extra={"service": service_name})
        raise OsQueryError(f"systemctl timed out for {service_name}") from None
    
    except OSError:
        logger.warning("systemctl is not available")
        raise OsQueryError("systemctl is not available") from None

    # A missing unit also prints inactive: only the exit code tells them apart.
    if result.returncode == NOT_FOUND_EXIT_CODE:
        return STATE_NOT_FOUND

    state = result.stdout.strip()

    return state if state in KNOWN_STATES else STATE_UNKNOWN


# Do not use psutil.Process(): systemctl is-active is enough, Agithar does
# not need PIDs and this keeps the attack surface small on the same VPS.

def get_units_status(units: dict[str, str]) -> dict[str, str]:
    statuses = {}

    for label, unit in units.items():
        try:
            statuses[label] = get_service_status(unit)
        except OsQueryError:
            statuses[label] = STATE_UNKNOWN

    return statuses


def get_sibling_status() -> dict[str, str]:
    return get_units_status(SIBLING_UNITS)


def get_system_status() -> dict[str, str]:
    return get_units_status(SYSTEM_UNITS)


def collect_snapshot() -> dict[str, Any]:
    return {
        "resources": get_resource_usage(),
        "siblings": get_sibling_status(),
        "system": get_system_status(),
    }


async def get_server_snapshot() -> dict[str, Any]:
    # The CPU sample blocks for a second, so it runs outside the event loop.
    return await asyncio.to_thread(collect_snapshot)
