# draft router no final file yet

from app.agent.states import AutomatonState


def route_after_investigate(state: AutomatonState) -> list[str]:
    verdict = state["verdict"] or {}

    # A clear false positive skips the secretaries; notify closes it quietly.
    if verdict.get("verdict") == "false_positive":
        return ["notify_admin"]

    return ["blue_secretary", "red_secretary"]


def route_after_review(state: AutomatonState) -> list[str]:
    pending = []

    if state["status_blue"] == "pending":
        pending.append("blue_secretary")

    if state["status_red"] == "pending":
        pending.append("red_secretary")

    return pending or ["compose_final_report"]
