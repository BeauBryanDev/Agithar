import asyncio
import time
from collections import Counter
from dataclasses import dataclass
from typing import Any, Callable

from app.core.config import Settings
from app.core.logging import get_logger
from app.db.postgresql.session import (
    DatabaseNotConfiguredError,
    get_session_factory,
)
from app.ingestion.nginx_parser import AccessLine, LineError, parse_line
from app.ingestion.payloads import http_payload
from app.ingestion.tailer import LogTailer, follow
from app.ingestion.windows import ClosedWindow, WindowBuilder
from app.schemas.events import EventContext
from app.sensors.base import SensorResult
from app.services.event_service import EventRejectedError, ingest_result

logger = get_logger("ingestion.nginx")

HTTP_SENSOR = "http_payload_sensor"
RECON_SENSOR = "recon_sensor"
STATS_INTERVAL_SECONDS = 300.0
STOP_TIMEOUT_SECONDS = 10.0


@dataclass
class Pending:
    # An anomalous sensor result, ready for the correlator.
    result: SensorResult
    ip: str
    timestamp: float
    method: str | None
    target: str | None
    user_agent: str
    status: int


class NginxFeed:
    # nginx log line -> parse -> host and IP filters -> payload sensor for
    # every request, scan detector for every closed 10 second window ->
    # event_service -> dispatcher. In log-only mode nothing is raised: the
    # results are only logged and counted.

    def __init__(
        self,
        registry: Any,
        correlator: Any,
        dispatcher: Any,
        tailer: LogTailer,
        *,
        hosts: list[str],
        ignore_ips: list[str],
        log_only: bool,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.registry = registry
        self.correlator = correlator
        self.dispatcher = dispatcher
        self.tailer = tailer
        self.hosts = frozenset(hosts)
        self.ignore = frozenset(ignore_ips)
        self.log_only = log_only
        self.clock = clock
        self.windows = WindowBuilder()
        self.stats: Counter[str] = Counter()
        self._last_stats = clock()
        self._stop = asyncio.Event()
        self._task: asyncio.Task | None = None

    def keep(self, line: AccessLine) -> bool:
        if line.forged_cf_header:
            self.stats["forged_cf_header"] += 1

        if line.host not in self.hosts:
            self.stats["skipped_host"] += 1
            return False

        if line.client_ip in self.ignore:
            self.stats["skipped_ip"] += 1
            return False

        if not line.valid_request:
            self.stats["garbage_request"] += 1
            return False

        return True

    def predict(self, name: str, payload: dict[str, Any]):
        try:
            return self.registry.predict(name, payload)

        except Exception as exc:
            self.stats["sensor_errors"] += 1
            logger.warning("%s failed: %s", name, type(exc).__name__)

            return None

    def score_request(self, line: AccessLine) -> Pending | None:
        result = self.predict(HTTP_SENSOR, http_payload(line))

        if result is None or not result.is_anomalous:
            return None

        self.stats["payload_anomalies"] += 1

        return Pending(
            result, line.client_ip, line.timestamp, line.method,
            line.target, line.user_agent, line.status,
        )

    def score_window(self, window: ClosedWindow) -> Pending | None:
        self.stats["windows_scored"] += 1
        result = self.predict(RECON_SENSOR, {"requests": window.requests})

        if result is None or not result.is_anomalous:
            return None

        self.stats["recon_anomalies"] += 1
        sample = window.sample

        return Pending(
            result, window.ip, window.start_timestamp, sample.method,
            sample.target, sample.user_agent, sample.status,
        )

    def process(self, lines: list[str], idle: bool) -> list[Pending]:
        # Runs in a worker thread: the models are CPU work.
        pending: list[Pending] = []

        for raw in lines:
            self.stats["lines"] += 1

            try:
                line = parse_line(raw)

            except LineError as exc:
                self.stats[f"rejected: {exc}"] += 1
                continue

            if not self.keep(line):
                continue

            self.stats["scored_requests"] += 1
            found = self.score_request(line)
            pending += [found] if found else []
            self.windows.add(line)

        closed = self.windows.close_ready(self.clock() if idle else None)
        scored = [self.score_window(window) for window in closed]
        pending += [item for item in scored if item]

        return pending

    def log_anomaly(self, item: Pending) -> None:
        # The path is logged without its query string, never the raw URL.
        context = EventContext.from_raw(
            item.method, item.target, item.user_agent, item.status
        )
        logger.info(
            "anomaly %s score=%.3f ip=%s status=%s path=%s",
            item.result.sensor, item.result.score, item.ip,
            item.status, context.path,
        )

    def emit(self, pending: list[Pending]) -> list[dict[str, Any]]:
        # Runs in a worker thread: the database is synchronous.
        try:
            session = get_session_factory()()

        except DatabaseNotConfiguredError:
            session = None

        cases = []

        try:
            for item in pending:
                try:
                    outcome = ingest_result(
                        self.correlator, session, item.result, item.ip,
                        item.timestamp, method=item.method,
                        target=item.target, user_agent=item.user_agent,
                        status=item.status,
                    )

                except EventRejectedError:
                    self.stats["events_rejected"] += 1
                    continue

                if outcome.escalated:
                    self.stats["cases_escalated"] += 1
                    cases.append(outcome)

        finally:
            if session is not None:
                session.close()

        return cases

    def log_stats(self) -> None:
        if self.clock() - self._last_stats < STATS_INTERVAL_SECONDS:
            return

        self._last_stats = self.clock()

        if self.stats:
            counts = dict(sorted(self.stats.items()))
            logger.info("ingestion stats: %s", counts)

    async def handle(self, lines: list[str], idle: bool) -> None:
        # A failure here must not stop the feed: it is logged and counted.
        try:
            pending = await asyncio.to_thread(self.process, lines, idle)

            for item in pending:
                self.log_anomaly(item)

            if pending and not self.log_only:
                outcomes = await asyncio.to_thread(self.emit, pending)

                for outcome in outcomes:
                    self.dispatcher.submit(outcome.case, outcome.incident_id)

            self.log_stats()

        except Exception as exc:
            self.stats["handler_errors"] += 1
            logger.error("feed batch failed: %s", type(exc).__name__)

    async def start(self) -> None:
        self._stop.clear()
        self._task = asyncio.create_task(
            follow(self.tailer, self.handle, self._stop)
        )
        logger.info("nginx feed started (log only: %s)", self.log_only)

    async def stop(self) -> None:
        self._stop.set()

        if self._task is not None:
            await asyncio.wait_for(self._task, timeout=STOP_TIMEOUT_SECONDS)
            self._task = None

        logger.info("nginx feed stopped: %s", dict(sorted(self.stats.items())))


def create_feed(
    settings: Settings, registry: Any, correlator: Any, dispatcher: Any
) -> NginxFeed:
    tailer = LogTailer(settings.nginx_log_path, settings.ingestion_state_path)

    return NginxFeed(
        registry,
        correlator,
        dispatcher,
        tailer,
        hosts=settings.ingestion_host_list,
        ignore_ips=settings.ingestion_ignore_ip_list,
        log_only=settings.ingestion_log_only,
    )
