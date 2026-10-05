from langchain_core.tools import StructuredTool

from app.agent.tools import (
    analyze_input,
    blueteam_knowledge,
    cve_lookup,
    exploit_db,
    incident_history,
    linux_knowledge,
    mitre_lookup,
    mitre_tactics,
    offensive_knowledge,
    owasp10lookup,
    recent_incidents,
    server_status,
    set_judgment,
    set_verdict,
    shodan_lookup,
    threat_intelligence,
    virustotal_lookup,
)

# The master's allowlist. notify_admin and the write services are
# deliberately absent: nothing outside this tuple can be called.
MASTER_TOOLS: tuple[StructuredTool, ...] = (
    cve_lookup.TOOL,
    owasp10lookup.TOOL,
    mitre_lookup.TOOL,
    blueteam_knowledge.TOOL,
    linux_knowledge.TOOL,
    threat_intelligence.TOOL,
    shodan_lookup.TOOL,
    virustotal_lookup.TOOL,
    exploit_db.TOOL,
    server_status.TOOL,
    incident_history.TOOL,
    recent_incidents.TOOL,
    mitre_tactics.TOOL,
    offensive_knowledge.TOOL,
    analyze_input.TOOL,
)

TOOLS_BY_NAME = {tool.name: tool for tool in MASTER_TOOLS}

# The two tools that end the loop. Their wire schema is strict; the master
# node reads the validated result from the tool message artifact.
FINISH_TOOLS: tuple[StructuredTool, ...] = (
    set_verdict.TOOL,
    set_judgment.TOOL,
)
FINISH_NAMES = frozenset(tool.name for tool in FINISH_TOOLS)
FINISH_WIRE = [set_verdict.WIRE_SCHEMA, set_judgment.WIRE_SCHEMA]
LOOP_TOOLS_BY_NAME = {
    tool.name: tool for tool in (*MASTER_TOOLS, *FINISH_TOOLS)
}


def wire_tools() -> list:
    # What is bound to the model: the lookup tools as they are and the two
    # finish tools as strict schemas.
    return [*MASTER_TOOLS, *FINISH_WIRE]
