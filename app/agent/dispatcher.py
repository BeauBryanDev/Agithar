import asyncio
import time
from collections import deque
from typing import Any

from app.agent.states import new_state
from app.core.config import get_settings
from app.core.logging import get_logger
from app.services.notification_service import (
    NotificationError,
    notify_admin,
)

logger = get_logger("agent.dispatcher")

RECURSION_LIMIT = 40
HOUR_SECONDS = 3600.0
Latest = tuple[dict[str, Any], int | None] | None


class Dispatcher:
    # Runs escalated cases through the agent graph. Call submit() from the
    # event loop. One task per case id; a window that escalates again while
    # its run is in progress is coalesced into one rerun with the newest data.

    def __init__(self, graph: Any = None) -> None:
        settings = get_settings()
        self._graph = graph
        self._slots = asyncio.Semaphore(settings.dispatch_max_concurrent)
        self._tasks: set[asyncio.Task] = set()
        self._inflight: dict[str, Latest] = {}
        self._starts: deque[float] = deque()

    @property
    def pending(self) -> int:
        return len(self._tasks)

    def stats(self) -> dict[str, int]:
        # Read-only numbers for the telemetry endpoint.
        settings = get_settings()
        now = time.monotonic()
        recent = sum(1 for t in self._starts if now - t <= HOUR_SECONDS)

        return {
            "running": len(self._tasks),
            "max_concurrent": settings.dispatch_max_concurrent,
            "queue_limit": settings.dispatch_queue_limit,
            "runs_last_hour": recent,
            "hourly_cap": settings.dispatch_max_cases_per_hour,
        }

    def graph(self) -> Any:
        if self._graph is None:
            from app.agent.graph.agithar import agithar_graph

            self._graph = agithar_graph

        return self._graph

    def refusal(self) -> str | None:
        settings = get_settings()
        now = time.monotonic()

        while self._starts and now - self._starts[0] > HOUR_SECONDS:
            self._starts.popleft()

        if len(self._tasks) >= settings.dispatch_queue_limit:
            return "queue full"

        if len(self._starts) >= settings.dispatch_max_cases_per_hour:
            return "hourly case limit reached"

        return None

    def submit(self, 
               case: dict[str, Any], 
               incident_id: int | None
               ) -> bool:
        " Submit a case to the dispatcher. "
        case_id = case["case_id"]

        if case_id in self._inflight:
            # The window escalated again: rerun once, with the newest data.
            self._inflight[case_id] = (case, incident_id)

            return True

        reason = self.refusal()

        if reason is not None:
            logger.error("case not run (%s): %s", reason, case_id)
            self.track(asyncio.create_task(self.alert(case, incident_id)))

            return False

        self._starts.append(time.monotonic())
        self._inflight[case_id] = None
        self.track(asyncio.create_task(self.run(case, incident_id)))

        return True

    def track(self, task: asyncio.Task) -> None:
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def alert(self, 
                    case: dict[str, Any], 
                    incident_id: int | None
                    ):
        # The admin is told even when the agent could not look at the case.
        try:
            await notify_admin(case, None, incident_id)

        except NotificationError as exc:
            logger.error("pending alert not sent: %s", exc)

        except Exception as exc:
            logger.error("pending alert failed: %s", type(exc).__name__)

    async def run(self, 
                  case: dict[str, Any], 
                  incident_id: int | None
                  ):
        " Run a case through the graph. "
        case_id = case["case_id"]

        try:
            while True:
                await self.run_once(case, incident_id)
                latest = self._inflight.get(case_id)

                if latest is None:
                    break

                self._inflight[case_id] = None
                case, incident_id = latest

        finally:
            self._inflight.pop(case_id, None)

    async def run_once(self, 
                       case: dict[str, Any], 
                       incident_id: int | None
                       ):
        " Run a case through the graph once. "
        timeout = get_settings().dispatch_case_timeout_seconds

        async with self._slots:
            try:
                await asyncio.wait_for(
                    self.graph().ainvoke(
                        new_state(case, incident_id),
                        config={"recursion_limit": RECURSION_LIMIT},
                    ),
                    timeout=timeout,
                )

            except Exception as exc:
                logger.error(
                    "case run failed: %s (%s)",
                    type(exc).__name__, case["case_id"],
                )
                await self.alert(case, incident_id)

    async def shutdown(self) -> None:
        for task in list(self._tasks):
            task.cancel()

        await asyncio.gather(*self._tasks, return_exceptions=True)


_dispatcher: Dispatcher | None = None


def get_dispatcher() -> Dispatcher:
    global _dispatcher

    if _dispatcher is None:
        _dispatcher = Dispatcher()

    return _dispatcher
