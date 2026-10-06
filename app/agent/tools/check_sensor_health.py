import asyncio
from typing import Literal

from langchain_core.tools import StructuredTool
from pydantic import BaseModel, ConfigDict, Field

from app.agent.tools import analyze_input
from app.agent.tools.common import guarded
from app.sensors import catalog
from app.sensors.health import SensorHealthError, report

NAME = "check_sensor_health"

SensorChoice = Literal[
    "all",
    "http_payload_sensor",
    "recon_sensor",
    "log_sentinel",
    "net_guard",
    "netflow_sensor",
]


class SensorArgs(BaseModel):
    sensor: SensorChoice = Field(
        default="all", description="One sensor, or all five"
    )

    model_config = ConfigDict(extra="forbid")


def compute(sensor: str) -> dict:
    registry = analyze_input.current_registry()

    if registry is None:
        raise SensorHealthError("sensors are not available")

    full = report(registry)
    names = list(full) if sensor == "all" else [sensor]

    return {
        "how_cases_are_raised": catalog.HOW_CASES_ARE_RAISED,
        "all_healthy": all(s["status"] == "ok" for s in full.values()),
        "sensors": {name: full[name] for name in names},
    }


async def run(sensor: str = "all") -> str:
    return await guarded(NAME, asyncio.to_thread(compute, sensor))


TOOL = StructuredTool.from_function(
    coroutine=run,
    name=NAME,
    description=(
        "Check the health of your five sensors and learn what they are. "
        "For each one it runs a harmless probe through the real model "
        "(status ok, error, failed_to_load; latency; threshold) and gives "
        "its profile: what it detects, the model and its training data, "
        "what data feeds it today, how to read its score, its known "
        "limits and its weight in the correlator. A passing probe proves "
        "the model runs, not that it is accurate. Use it when a sensor "
        "seems silent, before trusting a score, or when asked about your "
        "sensors."
    ),
    args_schema=SensorArgs,
)
