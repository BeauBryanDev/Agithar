from typing import Any

from app.agent.secretary import write_draft
from app.agent.states import AutomatonState


async def blue_secretary_node(state: AutomatonState) -> dict[str, Any]:
    return await write_draft(state, "blue")
