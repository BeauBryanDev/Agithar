import re
from dataclasses import dataclass
from datetime import datetime

from app.utils.cloudflare import resolve_client_ip

# Log line written by /etc/nginx/conf.d/agithar_log.conf on valtoria:
# $remote_addr "$http_cf_connecting_ip" [$time_iso8601] "$host" "$request"
# $status $body_bytes_sent "$http_user_agent"
# nginx escapes a quote, a backslash and control bytes inside a quoted field
# as \xNN, so a raw quote inside a field means the line is forged or broken.
LINE = re.compile(
    r'^(?P<remote>\S+) "(?P<cf>[^"]*)" \[(?P<time>[^\]]+)\] '
    r'"(?P<host>[^"]*)" "(?P<request>[^"]*)" '
    r"(?P<status>[0-9]{3}) (?:[0-9]+|-) "
    r'"(?P<agent>[^"]*)"$'
)
METHOD = re.compile(r"^[A-Z]{3,10}$")
MAX_LINE_CHARS = 16384
# The scan detector rejects a window that holds a path over 2048 characters,
# so one long path could blind it: the target is cut to that limit here.
MAX_TARGET_CHARS = 2048
MAX_AGENT_CHARS = 1024
MAX_HOST_CHARS = 255
MIN_STATUS = 100
MAX_STATUS = 599
MIN_EPOCH = 946684800.0


class LineError(Exception):
    # The message is one of a few fixed reasons, safe to count and to log.
    pass


@dataclass(frozen=True)
class AccessLine:
    client_ip: str
    via_cloudflare: bool
    forged_cf_header: bool
    timestamp: float
    host: str
    method: str | None
    target: str | None
    status: int
    user_agent: str
    valid_request: bool


def parse_time(text: str) -> float:
    try:
        moment = datetime.fromisoformat(text)

    except ValueError:
        raise LineError("bad time") from None

    if moment.tzinfo is None:
        raise LineError("bad time")

    epoch = moment.timestamp()

    if epoch < MIN_EPOCH:
        raise LineError("bad time")

    return epoch


def split_request(request: str) -> tuple[str | None, str | None]:
    # Same split as the scan detector's training: method, target, version.
    parts = request.split(" ", 2)

    if len(parts) < 2:
        return None, None

    method, target = parts[0], parts[1]
    ok_method = METHOD.match(method) is not None
    ok_target = target.startswith(("/", "http://", "https://")) or (
        target == "*" or method == "CONNECT"
    )

    if not ok_method or not target or not ok_target:
        return None, None

    return method, target[:MAX_TARGET_CHARS]


def parse_line(line: str) -> AccessLine:
    if len(line) > MAX_LINE_CHARS:
        raise LineError("line too long")

    match = LINE.match(line.rstrip("\r\n"))

    if match is None:
        raise LineError("bad format")

    status = int(match["status"])

    if not MIN_STATUS <= status <= MAX_STATUS:
        raise LineError("bad status")

    client = resolve_client_ip(match["remote"], match["cf"])

    if client is None:
        raise LineError("unattributed")

    method, target = split_request(match["request"])

    return AccessLine(
        client_ip=client.ip,
        via_cloudflare=client.via_cloudflare,
        forged_cf_header=client.forged_header,
        timestamp=parse_time(match["time"]),
        host=match["host"][:MAX_HOST_CHARS].lower(),
        method=method,
        target=target,
        status=status,
        user_agent=match["agent"][:MAX_AGENT_CHARS],
        valid_request=target is not None,
    )
