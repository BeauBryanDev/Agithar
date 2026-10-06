import threading
from collections import Counter, deque
from typing import Any

from app.core.config import get_settings

MAX_EVENTS = 5000
MINUTES_KEPT = 120
WINDOW_MINUTES = 60
MAX_FEED = 200
MAX_TOP = 20
SENSOR_LABEL_CAP = 40


class LiveStats:
    # Small in-memory view of what the feed just saw: the newest anomalies,
    # requests per minute and the busiest sources. Bounded on every side and
    # lost on restart; the log file stays the record. Written from the feed's
    # worker thread, read from the event loop, hence the lock.

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._events: deque[dict[str, Any]] = deque(maxlen=MAX_EVENTS)
        self._requests: Counter[int] = Counter()
        self._anomalies: Counter[int] = Counter()

    def record_request(self, timestamp: float) -> None:
        minute = int(timestamp // 60)

        with self._lock:
            self._requests[minute] += 1
            self._prune(minute)

    def record_anomaly(
        self,
        timestamp: float,
        ip: str,
        sensor: str,
        score: float,
        status: int,
        path: str | None,
        host: str | None,
    ) -> None:
        minute = int(timestamp // 60)
        event = {
            "timestamp": float(timestamp),
            "ip": ip,
            "sensor": sensor[:SENSOR_LABEL_CAP],
            "score": round(float(score), 3),
            "status": int(status),
            "path": path or "",
            "host": host or "",
        }

        with self._lock:
            self._events.append(event)
            self._anomalies[minute] += 1
            self._prune(minute)

    def by_sensor(self, now: float, recent: int = 5) -> dict[str, dict]:
        # What each sensor flagged in the last hour, from the same buffer.
        cutoff = (int(now // 60) - WINDOW_MINUTES + 1) * 60

        with self._lock:
            events = list(self._events)

        out: dict[str, dict] = {}

        for event in events:
            if event["timestamp"] < cutoff:
                continue

            row = out.setdefault(
                event["sensor"], {"anomalies": 0, "last": None, "events": []}
            )
            row["anomalies"] += 1
            row["last"] = max(row["last"] or 0.0, event["timestamp"])
            row["events"].append(event)

        for row in out.values():
            row["events"] = list(reversed(row["events"][-recent:]))

        return out

    def _prune(self, newest: int) -> None:
        oldest = newest - MINUTES_KEPT

        for counter in (self._requests, self._anomalies):
            for minute in [m for m in counter if m < oldest]:
                del counter[minute]

    def snapshot(self, now: float, 
                 feed: int = 100, 
                 top: int = 8
                 ) -> dict:
        """ it takes the snapshot of the live data

        Args:
            now (float): the current time
            feed (int, optional): the number of events to return. Defaults to 100.
            top (int, optional): the number of top IPs to return. Defaults to 8.

        Returns:
            dict: the snapshot
        """
        feed = min(max(feed, 1), MAX_FEED)
        top = min(max(top, 1), MAX_TOP)
        end = int(now // 60)
        start = end - WINDOW_MINUTES + 1
        cutoff = start * 60

        with self._lock:
            events = list(self._events)
            requests = dict(self._requests)
            anomalies = dict(self._anomalies)

        recent = [e for e in events if e["timestamp"] >= cutoff]
        ips: dict[str, dict[str, Any]] = {}
        paths: Counter[str] = Counter()

        for e in recent:
            row = ips.setdefault(
                e["ip"], {"count": 0, "max_score": 0.0, "sensors": set()}
            )
            row["count"] += 1
            row["max_score"] = max(row["max_score"], e["score"])
            row["sensors"].add(e["sensor"])

            if e["path"]:
                paths[e["path"]] += 1

        top_ips = sorted(
            ips.items(), key=lambda kv: (-kv[1]["count"], kv[0])
        )[:top]

        return {
            "events": list(reversed(events[-feed:])),
            "per_minute": [
                {
                    "minute": m * 60,
                    "requests": requests.get(m, 0),
                    "anomalies": anomalies.get(m, 0),
                }
                for m in range(start, end + 1)
            ],
            "top_ips": [
                {
                    "ip": ip,
                    "count": row["count"],
                    "max_score": row["max_score"],
                    "sensors": sorted(row["sensors"]),
                }
                for ip, row in top_ips
            ],
            "top_paths": [
                {"path": path, "count": count}
                for path, count in paths.most_common(top)
            ],
            "anomalies_in_window": len(recent),
            "window_minutes": WINDOW_MINUTES,
        }
