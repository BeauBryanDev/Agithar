from dataclasses import dataclass, field
from typing import Any

from langchain_core.messages import (
    AIMessage,
    HumanMessage,
    SystemMessage,
    ToolMessage,
)

from app.agent.demeanor import build_case_message, load_base_prompt
from app.agent.findings_builder import Record
from app.agent.llm.agithar_client import get_anthropic_client
from app.agent.llm.caching import cached_system, with_cache
from app.agent.report import NO_VERDICT
from app.agent.tool_runner import run_calls
from app.agent.tools.common import unwrap_result
from app.agent.tools.registry import (
    FINISH_NAMES,
    FINISH_WIRE,
    LOOP_TOOLS_BY_NAME,
    wire_tools,
)
from app.core.config import get_settings
from app.core.logging import get_logger
from app.schemas.analysis import AgentVerdict
from app.services.analysis_service import (
    check_mitre_technique,
    enforce_verdict,
)

logger = get_logger("agent.investigate")

MAX_FINISH_TURNS = 4
NUDGE = (
    "You have not finished. Call set_verdict if you have not, then "
    "set_judgment, without further checking in."
)
BUDGET_NOTE = (
    "Your tool budget is used up. Call set_verdict now, then set_judgment."
)


def system_message() -> SystemMessage:
    return cached_system(load_base_prompt())


@dataclass
class Run:
    verdict: AgentVerdict | None = None
    judgment: dict[str, Any] | None = None
    records: list[Record] = field(default_factory=list)


def finish_ok(run: Run) -> bool:
    if run.verdict is None:
        return False

    # A false positive needs no judgment: it skips the secretaries.
    return run.judgment is not None or run.verdict.verdict == "false_positive"


def finalize_verdict(artifact: dict[str, Any], 
                     severity: str
                     ) -> AgentVerdict:
    # The tool does not know the case: MITRE check and escalation rule here.
    verdict = AgentVerdict.model_validate(artifact)

    return enforce_verdict(check_mitre_technique(verdict), severity)


def absorb(
    run: Run, 
    call: dict[str, Any], 
    message: ToolMessage, 
    severity: str
) -> None:
    # Absorb the result of a tool call into the run state. 
    # The verdict and judgment are set from the tool results, 
    # and all other results are recorded for later analysis.
    name = call["name"]
    artifact = getattr(message, "artifact", None)

    if name == "set_verdict" and isinstance(artifact, dict):
        run.verdict = finalize_verdict(artifact, severity)

    elif name == "set_judgment" and isinstance(artifact, dict):
        run.judgment = artifact

    elif name in LOOP_TOOLS_BY_NAME and name not in FINISH_NAMES:
        run.records.append((name, unwrap_result(str(message.content))))


def refused(message: AIMessage) -> bool:
    return message.response_metadata.get("stop_reason") == "refusal"


def refusal_category(message: AIMessage) -> str:
    details = message.response_metadata.get("stop_details")
    category = details.get("category") if isinstance(details, dict) else None

    return str(category)[:32] if category else "unknown"


def note_fallback(message: AIMessage) -> None:
    served = str(message.response_metadata.get("model") or "")

    # A different model answered: the safeguards declined the first one.
    if served and not served.startswith(get_settings().agent_model):
        logger.warning("a fallback model served this turn: %s", served[:48])


async def investigate(case: dict[str, Any]) -> Run:
    run = Run()
    max_turns = get_settings().agent_max_tool_turns
    base = get_anthropic_client()
    full_model = with_cache(base.bind_tools(wire_tools()))
    finish_model = with_cache(base.bind_tools(FINISH_WIRE))
    messages: list[Any] = [
        system_message(),
        HumanMessage(build_case_message(case)),
    ]
    lookups = 0
    nudged = False

    for _ in range(max_turns + MAX_FINISH_TURNS):
        finishing = lookups >= max_turns

        if finishing and lookups == max_turns:
            messages.append(HumanMessage(BUDGET_NOTE))
            lookups += 1

        reply = await (finish_model if finishing else full_model).ainvoke(
            messages
        )
        messages.append(reply)

        note_fallback(reply)

        if refused(reply):
            logger.error(
                "the model refused to investigate this case (category: %s)",
                refusal_category(reply),
            )
            break

        calls = list(reply.tool_calls)

        if not calls:
            if nudged or finish_ok(run):
                break

            nudged = True
            messages.append(HumanMessage(NUDGE))
            continue

        results = await run_calls(calls, LOOP_TOOLS_BY_NAME)
        messages.extend(results)

        for call, message in zip(calls, results):
            absorb(run, call, message, case["severity"])

        if any(call["name"] not in FINISH_NAMES for call in calls):
            lookups += 1

        if finish_ok(run):
            break

    return run


def fallback_verdict() -> AgentVerdict:
    return AgentVerdict.model_validate(NO_VERDICT)
