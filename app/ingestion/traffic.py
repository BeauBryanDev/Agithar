from collections import Counter
from datetime import datetime, timezone
from typing import Any

from app.ingestion.log_tail import LogWindow
from app.ingestion.nginx_parser import AccessLine
from app.security.sanitize import sanitize_string

TOP = 8
MAX_PATH_CHARS = 120
MALFORMED = "(malformed request)"
# Ordered: a bot that also says "Mozilla" must match before the browser.
AGENT_FAMILIES = (
    ("gptbot", "GPTBot"),
    ("googlebot", "Googlebot"),
    ("bingbot", "Bingbot"),
    ("zgrab", "zgrab scanner"),
    ("censys", "Censys scanner"),
    ("palo alto", "Palo Alto scanner"),
    ("nmap", "nmap"),
    ("sqlmap", "sqlmap"),
    ("curl/", "curl"),
    ("go-http-client", "Go http client"),
    ("python-requests", "python-requests"),
    ("python-urllib", "python-urllib"),
    ("wget", "wget"),
    ("mozilla", "browser"),
)


def agent_family(user_agent: str) -> str:
    lowered = user_agent.lower()

    for needle, label in AGENT_FAMILIES:
        if needle in lowered:
            return label

    return "empty" if user_agent in ("", "-") else "other"


def path_of(line: AccessLine) -> str:
    # The query string is dropped: it can hold tokens and attacker text.
    if not line.valid_request or line.target is None:
        return MALFORMED

    path = line.target.split("?", 1)[0]

    return sanitize_string(path, MAX_PATH_CHARS)


def status_class(status: int) -> str:
    return f"{status // 100}xx"


def iso(timestamp: float | None) -> str | None:
    if timestamp is None:
        return None

    return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()


def top(counter: Counter, name: str) -> list[dict[str, Any]]:
    return [{name: key, "requests": n} for key, n in counter.most_common(TOP)]


def summarize(
    window: LogWindow, minutes: int, shop_of: dict[str, str]
) -> dict[str, Any]:
    lines = window.lines
    total = len(lines)
    classes = Counter(status_class(line.status) for line in lines)
    errors = [line for line in lines if line.status >= 400]
    per_minute = Counter(int(line.timestamp // 60) for line in lines)
    peak_minute, peak = per_minute.most_common(1)[0] if per_minute else (0, 0)
    ips = Counter(line.client_ip for line in lines)
    error_ips = Counter(line.client_ip for line in errors)

    return {
        "window_minutes": minutes,
        "data_starts_at": iso(window.oldest),
        "window_complete": window.complete,
        # True: older lines exist but were not read (size cap).
        "older_lines_not_read": not window.reached_start
        and not window.complete,
        "requests": total,
        "requests_per_minute": round(total / minutes, 2),
        "peak_minute": {"time": iso(peak_minute * 60), "requests": peak}
        if peak else None,
        "status_classes": dict(sorted(classes.items())),
        "error_rate": round(len(errors) / total, 3) if total else 0.0,
        "not_found_rate": round(
            sum(1 for line in lines if line.status == 404) / total, 3
        ) if total else 0.0,
        "unique_clients": len(ips),
        "by_shop": dict(Counter(shop_of.get(line.host, "other")
                                for line in lines)),
        "top_paths": top(Counter(path_of(line) for line in lines), "path"),
        "top_error_paths": top(
            Counter(path_of(line) for line in errors), "path"
        ),
        "top_clients": [
            {"ip": ip, "requests": n, "errors": error_ips[ip]}
            for ip, n in ips.most_common(TOP)
        ],
        "client_types": top(
            Counter(agent_family(line.user_agent) for line in lines), "type"
        ),
        "unreadable_lines": dict(window.rejected),
    }


def recent_errors(
    window: LogWindow, limit: int, shop_of: dict[str, str]
) -> list[dict[str, Any]]:
    errors = [line for line in window.lines if line.status >= 400]

    return [
        {
            "time": iso(line.timestamp),
            "shop": shop_of.get(line.host, "other"),
            "ip": line.client_ip,
            "method": line.method,
            "path": path_of(line),
            "status": line.status,
            "client_type": agent_family(line.user_agent),
        }
        for line in reversed(errors[-limit:])
    ]
