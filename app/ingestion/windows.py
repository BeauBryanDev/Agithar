from dataclasses import dataclass, field
from typing import Any

from app.core.logging import get_logger
from app.ingestion.nginx_parser import AccessLine
from app.ingestion.payloads import recon_request, window_index

logger = get_logger("ingestion.windows")

# A window is closed once the log time has moved this many windows past it.
GRACE_WINDOWS = 1
# The scan detector accepts 50000 requests; far fewer are kept per window.
MAX_REQUESTS_PER_WINDOW = 5000
MAX_OPEN_WINDOWS = 20000


@dataclass
class ClosedWindow:
    ip: str
    index: int
    requests: list[dict[str, Any]]
    start_timestamp: float
    # First request of the window, to build the sanitized event context.
    sample: AccessLine
    # Requests beyond the cap that were counted but not kept.
    dropped: int = 0


@dataclass
class OpenWindow:
    sample: AccessLine
    requests: list[dict[str, Any]] = field(default_factory=list)
    dropped: int = 0


class WindowBuilder:
    # Groups requests per client IP in fixed 10 second windows, the same
    # window as the scan detector's training (epoch seconds // 10, UTC).
    # Windows are closed by LOG time, so replaying an old log never splits
    # a window; an idle flush by the wall clock closes the rest.

    def __init__(
        self,
        grace_windows: int = GRACE_WINDOWS,
        max_open_windows: int = MAX_OPEN_WINDOWS,
        max_requests: int = MAX_REQUESTS_PER_WINDOW,
    ) -> None:
        self.grace = grace_windows
        self.max_open = max_open_windows
        self.max_requests = max_requests
        self._open: dict[tuple[str, int], OpenWindow] = {}
        self._latest = 0

    @property
    def open_count(self) -> int:
        return len(self._open)

    def add(self, line: AccessLine) -> None:
        request = recon_request(line)

        if request is None:
            return

        index = window_index(line.timestamp)
        self._latest = max(self._latest, index)
        key = (line.client_ip, index)
        window = self._open.get(key)

        if window is None:
            window = self._open[key] = OpenWindow(sample=line)

        if len(window.requests) >= self.max_requests:
            window.dropped += 1
            return

        window.requests.append(request)

    def close(self, key: tuple[str, int]) -> ClosedWindow:
        window = self._open.pop(key)

        return ClosedWindow(
            ip=key[0],
            index=key[1],
            requests=window.requests,
            start_timestamp=window.sample.timestamp,
            sample=window.sample,
            dropped=window.dropped,
        )

    def close_ready(self, idle_now: float | None = None) -> list[ClosedWindow]:
        # idle_now is the wall clock time, given only when the tailer has
        # caught up and nothing new arrived; without it only the log time
        # decides, which is what a backlog needs.
        limit = self._latest - self.grace
        keys = [key for key in self._open if key[1] < limit]

        if idle_now is not None:
            idle_index = window_index(idle_now) - self.grace - 1
            keys += [
                key for key in self._open
                if key not in keys and key[1] <= idle_index
            ]

        # A flood of distinct IPs must not exhaust memory: the oldest go.
        overflow = len(self._open) - len(keys) - self.max_open

        if overflow > 0:
            logger.warning("too many open windows, closing the oldest early")
            rest = [k for k in self._open if k not in keys]
            rest.sort(key=lambda k: k[1])
            keys += rest[:overflow]

        return [self.close(key) for key in sorted(keys, key=lambda k: k[1])]
