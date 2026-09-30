from dataclasses import dataclass, field
from typing import Any

WINDOW_SECONDS = 60
MAX_WINDOWS = 10000
RETAIN_BUCKETS = 2


@dataclass
class Window:
    key: str
    ip: str
    bucket: int
    best: dict[str, dict[str, Any]] = field(default_factory=dict)
    counts: dict[str, int] = field(default_factory=dict)
    escalated_rank: int = 0


def get_bucket(timestamp: float) -> int:
    return int(timestamp // WINDOW_SECONDS)


def get_window_key(ip: str, timestamp: float) -> str:
    return f"{ip}:{get_bucket(timestamp)}"


class WindowStore:
    def __init__(self) -> None:
        self.windows: dict[str, Window] = {}
        self.newest_bucket = 0

    def add(self, event: dict[str, Any]) -> Window:
        bucket = get_bucket(event["timestamp"])
        key = get_window_key(event["ip"], event["timestamp"])

        window = self.windows.get(key)
        if window is None:
            window = Window(key=key, ip=event["ip"], bucket=bucket)
            self.windows[key] = window

        self.record(window, event)
        self.newest_bucket = max(self.newest_bucket, bucket)
        self.evict()

        return window

    def record(self, window: Window, event: dict[str, Any]) -> None:
        sensor = event["source_sensor"]
        window.counts[sensor] = window.counts.get(sensor, 0) + 1
        current = window.best.get(sensor)

        if current is None or event["score"] > current["score"]:
            window.best[sensor] = event

    def evict(self) -> None:
        oldest_allowed = self.newest_bucket - RETAIN_BUCKETS
        stale = []

        for key, window in self.windows.items():
            if window.bucket < oldest_allowed:
                stale.append(key)

        for key in stale:
            del self.windows[key]

        while len(self.windows) > MAX_WINDOWS:
            del self.windows[next(iter(self.windows))]
