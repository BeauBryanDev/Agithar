import asyncio
from typing import Any

from langchain_core.messages import ToolMessage
from pydantic import ValidationError

from app.agent.tools.common import validation_message
from app.core.logging import get_logger

logger = get_logger("agent.tools")

MAX_CALLS_PER_TURN = 6


async def execute(
    call: dict[str, Any],
    tools_by_name: dict[str, Any]
) -> ToolMessage:
    # An unknown tool or a crashing one answers the model with a fixed text;
    # the exception itself is only logged by class name.
    tool = tools_by_name.get(call["name"])

    if tool is None:
        return ToolMessage("unknown tool", tool_call_id=call["id"])

    try:
        return await tool.ainvoke(call)

    except ValidationError as exc:
        # The model sent bad arguments: say which, so it can call again.
        return ToolMessage(
            validation_message(exc), tool_call_id=call["id"]
        )

    except Exception as exc:
        logger.error("tool call failed: %s", type(exc).__name__)

        return ToolMessage("tool failed", tool_call_id=call["id"])


async def run_calls(
    calls: list[dict[str, Any]],
    tools_by_name: dict[str, Any],
    max_calls: int = MAX_CALLS_PER_TURN,
) -> list[ToolMessage]:
    # Every call gets a result, including the ones over the per-turn limit.
    allowed, extra = calls[:max_calls], calls[max_calls:]
    messages = list(
        await asyncio.gather(*(execute(c, tools_by_name) for c in allowed))
    )
    messages += [
        ToolMessage("too many calls in one turn", tool_call_id=c["id"])
        for c in extra
    ]

    return messages
