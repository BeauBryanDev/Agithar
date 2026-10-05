from typing import Any

from app.ingestion.nginx_parser import AccessLine

WINDOW_SECONDS = 10


def http_payload(line: AccessLine) -> dict[str, Any] | None:
    # http_payload_sensor was trained on "path?query + body" with no method,
    # so only the request target is sent. nginx does not log the body.
    # A line that is not a real HTTP request (scanner garbage) is not sent.
    if not line.valid_request:
        return None

    return {"url": line.target}


def recon_request(line: AccessLine) -> dict[str, Any] | None:
    # recon_sensor was trained on the raw target, the status and the user
    # agent of every request in a 10 second window of one client IP.
    if not line.valid_request:
        return None

    return {
        "path": line.target,
        "status": line.status,
        "user_agent": line.user_agent,
    }


def window_index(timestamp: float) -> int:
    # Same as training: epoch seconds floored to the window, in UTC.
    return int(timestamp // WINDOW_SECONDS)
