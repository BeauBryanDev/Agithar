
from langgraph.graph import END, START, StateGraph

from app.agent.nodes.blue_secretary import blue_secretary_node
from app.agent.nodes.master import (
    compose_final_report_node,
    master_investigate_node,
    master_review_node,
)
from app.agent.nodes.notify import notify_admin_node
from app.agent.nodes.red_secretary import red_secretary_node
from app.agent.nodes.router import (
    route_after_investigate,
    route_after_review,
)
from app.agent.states import AutomatonState

builder = StateGraph(AutomatonState)

builder.add_node("master_investigate", master_investigate_node)
builder.add_node("blue_secretary", blue_secretary_node)
builder.add_node("red_secretary", red_secretary_node)
builder.add_node("master_review", master_review_node)
builder.add_node("compose_final_report", compose_final_report_node)
builder.add_node("notify_admin", notify_admin_node)

builder.add_edge(START, "master_investigate")

# fork: both secretaries start from the same investigation output; a clear
# false positive goes straight to notify_admin, which closes it quietly
builder.add_conditional_edges(
    "master_investigate",
    route_after_investigate,
    ["blue_secretary", "red_secretary", "notify_admin"],
)

# join: master_review only waits for whichever branch actually ran this round
builder.add_edge("blue_secretary", "master_review")
builder.add_edge("red_secretary", "master_review")

builder.add_conditional_edges(
    "master_review",
    route_after_review,
    ["blue_secretary", "red_secretary", "compose_final_report"],
)

builder.add_edge("compose_final_report", "notify_admin")
builder.add_edge("notify_admin", END)

# no checkpointer: the graph runs once per case and is discarded, per design
agithar_graph = builder.compile()

