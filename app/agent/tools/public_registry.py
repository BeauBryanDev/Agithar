from langchain_core.tools import StructuredTool

from app.agent.tools import (
    exploit_db,
    mitre_lookup,
    mitre_tactics,
    owasp10lookup,
    public_tools,
)

# Public demo allowlist. Nothing here touches shop data, incident history,
# infrastructure status, or the rate-limited third-party APIs (Shodan,
# VirusTotal, AbuseIPDB). The tools that cost money or CPU are the LIMITED
# public versions from public_tools (capped excerpts, a budget for live NVD
# calls, a small and rate-limited sensor analysis). If a tool is not listed
# here, it does not exist for the public graph, whatever the prompt says.
PUBLIC_TOOLS: tuple[StructuredTool, ...] = (
    public_tools.analyze_input_tool,
    public_tools.blueteam_knowledge,
    public_tools.cve_lookup,
    owasp10lookup.TOOL,
    mitre_lookup.TOOL,
    mitre_tactics.TOOL,
    public_tools.offensive_knowledge,
    public_tools.linux_knowledge,
    exploit_db.TOOL,
)

PUBLIC_TOOLS_BY_NAME = {tool.name: tool for tool in PUBLIC_TOOLS}
