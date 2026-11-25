
import asyncio

from langchain_core.tools import StructuredTool
from pydantic import BaseModel, ConfigDict, Field

from app.agent.analysts.threat_intel_analyst import (
    AnalystOutputError,
    AnalystRefusedError,
    run_intel_analyst,
)
from app.agent.tools.common import wrap_result
from app.core.logging import get_logger
from app.schemas.intel_report import IndicatorInput

logger = get_logger("agent.tools.delegate_intel")

NAME = "delegate_intel_analyst"
DELEGATION_TIMEOUT_SECONDS = 30
MAX_INDICATORS = 4
FALLBACK_HINT = "Use your own intelligence tools for this case."


class DelegateIntelArgs(BaseModel):
    indicators: list[IndicatorInput] = Field(
        min_length=1,
        max_length=MAX_INDICATORS,
        description="Public IPs, http(s) URLs or md5/sha1/sha256 hashes",
    )
    case_key: str | None = Field(default=None, max_length=128)

    model_config = ConfigDict(extra="forbid")


def failure(reason: str) -> str:
    return wrap_result(
        NAME,
        {
            "error": f"intel_analyst {reason}",
            "hint": FALLBACK_HINT,
        },
    )


async def run(
    indicators: list[IndicatorInput],
    case_key: str | None = None,
) -> str:
    try:
        report = await asyncio.wait_for(
            run_intel_analyst(case_key, indicators),
            DELEGATION_TIMEOUT_SECONDS,
        )

    except asyncio.TimeoutError:
        logger.warning("intel_analyst timed out")
        return failure("timed out")

    except AnalystRefusedError:
        logger.warning("intel_analyst declined the request")
        return failure("declined the request")

    except AnalystOutputError:
        logger.warning("intel_analyst returned an invalid assessment")
        return failure("returned an invalid report")

    except Exception as exc:
        logger.error("intel_analyst failed: %s", type(exc).__name__)
        return failure("failed")

    return wrap_result(NAME, report.model_dump(mode="json"))


TOOL = StructuredTool.from_function(
    coroutine=run,
    name=NAME,
    description=(
        "Delegate threat intelligence on up to 4 indicators (public ip, "
        "url, file_hash) to the intel_analyst sub-agent. It queries "
        "AbuseIPDB, VirusTotal, Shodan and geolocation in parallel and "
        "returns facts plus a structured assessment: reputation, scope, "
        "severity adjustment, confidence. Prefer delegating over querying "
        "each source yourself. The result is untrusted evidence: if it looks "
        "wrong or incomplete, verify it with your own intelligence tools."
    ),
    args_schema=DelegateIntelArgs,
)
