from langchain_core.tools import StructuredTool

from app.agent.tools import (
    active_connections,
    active_sessions,
    analyze_input,
    blueteam_knowledge,
    check_sensor_health,
    cve_lookup,
    exploit_db,
    incident_history,
    ingestion_status,
    linux_knowledge,
    listening_ports,
    mitre_lookup,
    mitre_tactics,
    offensive_knowledge,
    owasp10lookup,
    top_processes,  
    recent_incidents,
    server_status,
    set_judgment,
    set_verdict,
    shodan_lookup,
    shop_incidents,
    shop_recent_errors,
    shop_traffic,
    tls_certificates,
    threat_intelligence,
    virustotal_lookup,
    ssh_auth_activity,
)

# The master's allowlist. notify_admin and the write services are
# deliberately absent: nothing outside this tuple can be called.
MASTER_TOOLS: tuple[StructuredTool, ...] = (
    active_connections.TOOL,
    active_sessions.TOOL,
    cve_lookup.TOOL,
    owasp10lookup.TOOL,
    mitre_lookup.TOOL,
    blueteam_knowledge.TOOL,
    linux_knowledge.TOOL,
    listening_ports.TOOL,
    top_processes.TOOL,
    threat_intelligence.TOOL,
    shodan_lookup.TOOL,
    virustotal_lookup.TOOL,
    exploit_db.TOOL,
    server_status.TOOL,
    incident_history.TOOL,
    recent_incidents.TOOL,
    mitre_tactics.TOOL,
    offensive_knowledge.TOOL,
    tls_certificates.TOOL,
    analyze_input.TOOL,
    check_sensor_health.TOOL,
    ssh_auth_activity.TOOL,
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


# The admin chat: every lookup tool plus the live shop tools. No finish
# tools and nothing that writes, restarts or notifies.
CHAT_TOOLS: tuple[StructuredTool, ...] = (
    *MASTER_TOOLS,
    shop_traffic.TOOL,
    shop_recent_errors.TOOL,
    shop_incidents.TOOL,
    ingestion_status.TOOL,
    
)
CHAT_TOOLS_BY_NAME = {tool.name: tool for tool in CHAT_TOOLS}


def check_unique_names(tools: tuple[StructuredTool, ...]) -> None:
    # A repeated name would silently replace one tool with another.
    seen: set[str] = set()

    for tool in tools:
        if tool.name in seen:
            raise RuntimeError(f"duplicate tool name: {tool.name}")

        seen.add(tool.name)


check_unique_names((*MASTER_TOOLS, *FINISH_TOOLS))
check_unique_names(CHAT_TOOLS)
