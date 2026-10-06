import re
from typing import Any

from app.schemas.analysis import AgentVerdict
from app.schemas.findings import (
    MAX_CVES,
    MAX_FACTS,
    MAX_INDICATORS,
    MAX_PORTS,
    BlueFindings,
    RedFindings,
)

# One record per tool call the master made: (tool name, parsed JSON data).
Record = tuple[str, Any]

CVSS_LEVELS = ("none", "low", "medium", "high", "critical")
COUNTRY = re.compile(r"^[A-Z]{2}$")
MAX_FACT_SENSORS = 5
LOW_CONFIDENCE = 0.7


def results_of(records: list[Record], 
               tool: str
               ) -> list[dict[str, Any]]:
    # Successful dict results only: an {"error": ...} result is skipped.
    return [
        data
        for name, data in records
        if name == tool and isinstance(data, dict) and "error" not in data
    ]


def as_int(value: Any, 
           low: int, 
           high: int
           ) -> int | None:
    # Returns the value if it is an int in the range [low, high], else None.
    if isinstance(value, bool) or not isinstance(value, int):
        return None

    return value if low <= value <= high else None


def names_of(records: list[Record]) -> list[str]:
    # Returns a list of all tool names used in the records.
    return list(dict.fromkeys(name for name, _ in records))


def build_cves(records: list[Record]) -> list[dict[str, Any]]:
    # Builds a list of CVE records from the results of the CVE lookup.
    cves: dict[str, dict[str, Any]] = {}

    for data in results_of(records, "cve_lookup"):
        vulnerability = data.get("vulnerability")

        if not data.get("found") or not isinstance(vulnerability, dict):
            continue

        cvss = vulnerability.get("cvss") or {}
        severity = cvss.get("severity")
        
        cves[vulnerability["cve_id"]] = {
            "cve_id": vulnerability["cve_id"],
            "cvss_score": cvss.get("base_score"),
            "cvss_severity": severity if severity in CVSS_LEVELS else None,
            "has_public_exploit": bool(vulnerability.get("exploits")),
        }

    return list(cves.values())[:MAX_CVES]


def build_intel(records: list[Record]) -> dict[str, Any] | None:
    
    found = results_of(records, "threat_intelligence")

    if not found:
        return None

    sources = found[0]
    abuse = sources.get("abuseipdb") or {}
    virustotal = sources.get("virustotal") or {}
    country = abuse.get("country_code")

    score = as_int(abuse.get("abuse_confidence_score"), 0, 100)

    return {
        "abuse_confidence": score,
        "vt_malicious": as_int(virustotal.get("malicious"), 0, 10**6),
        "vt_suspicious": as_int(virustotal.get("suspicious"), 0, 10**6),
        "country_code": country if COUNTRY.match(str(country)) else None,
    }


def count_prior(records: list[Record], 
                incident_saved: bool
                ) -> int:
    # Counts the number of prior incidents in the records.
    history = results_of(records, "incident_history")
    total = as_int(history[0].get("total"), 0, 10**9) if history else 0

    # The current case is already stored, so it is not a prior incident.
    return max((total or 0) - (1 if incident_saved else 0), 0)


def build_facts(
    case: dict[str, Any],
    intel: dict[str, Any] | None,
    prior: int,
) -> list[dict[str, str]]:
    # Builds a list of facts from the case and the intel.
    facts = []
    scores = sorted(case["sensor_scores"].items(), 
                    key=lambda kv: -kv[1])

    for name, score in scores[:MAX_FACT_SENSORS]:
        facts.append(
            {"source": "correlator", 
             "text": f"{name} best score {score:.2f}"
             }
        )

    if intel and intel["abuse_confidence"] is not None:
        
        text = f"AbuseIPDB confidence {intel['abuse_confidence']} of 100"
        facts.append({"source": "threat_intelligence", "text": text})

    if intel and intel["vt_malicious"] is not None:
        
        text = f"VirusTotal engines flagging the IP: {intel['vt_malicious']}"
        facts.append({"source": "threat_intelligence", "text": text})

    facts.append(
        {"source": "incident_history", "text": f"{prior} earlier incidents"}
    )

    return facts[:MAX_FACTS]


def build_indicators(case: dict[str, Any]) -> dict[str, Any]:
    # Builds a list of indicators from the case.
    paths: list[str] = []
    hashes: list[str] = []

    for event in case["evidence"]:
        
        context = event.get("context") or {}
        paths.append(context.get("path"))
        hashes.append(context.get("user_agent_sha256"))

    return {
        "ip": case["ip"],
        "url_paths": [p for p in dict.fromkeys(paths) if p][:MAX_INDICATORS],
        "user_agent_hashes": [
            h for h in dict.fromkeys(hashes) if h
        ][:MAX_INDICATORS],
    }


def build_gaps(case: dict[str, Any], 
               verdict: AgentVerdict
               ) -> list[str]:
    # Builds a list of detection gaps from the case and the verdict.
    sensors = set(case["contributing_sensors"])
    gaps = []

    if case["num_sensors"] == 1:
        gaps.append("single_sensor_only")

    if verdict.confidence < LOW_CONFIDENCE:
        gaps.append("low_sensor_confidence")

    if not sensors & {"net_guard", "netflow_sensor"}:
        gaps.append("no_flow_data")

    if "log_sentinel" not in sensors:
        gaps.append("no_log_sequence")

    if "http_payload_sensor" not in sensors:
        gaps.append("no_http_payload")

    return gaps


def build_ports(records: list[Record]) -> list[dict[str, Any]]:
    # Builds a list of ports from the results of the Shodan lookup.
    ports: list[int] = []

    for data in results_of(records, "shodan_lookup"):
        for port in data.get("ports") or []:
            if as_int(port, 1, 65535) is not None:
                ports.append(port)

    return [{"port": port} for port in dict.fromkeys(ports)][:MAX_PORTS]


def shared_fields(
    case: dict[str, Any],
    verdict: AgentVerdict,
    records: list[Record],
    incident_saved: bool,
) -> dict[str, Any]:
    intel = build_intel(records)
    prior = count_prior(records, incident_saved)

    return {
        "case_id": case["case_id"],
        "severity": case["severity"],
        "verdict": verdict,
        "sources_used": names_of(records),
        "key_facts": build_facts(case, intel, prior),
        "cves": build_cves(records),
        "intel": intel,
        "prior_incidents": prior,
    }

# BLUE SECRETARY FUNCTIONS CALLED BY MASTER
def build_blue_findings(
    case: dict[str, Any],
    verdict: AgentVerdict,
    records: list[Record],
    actions: list[str],
    incident_saved: bool,
) -> dict[str, Any]:
    # Raises pydantic ValidationError if the master's actions are not allowed.
    findings = BlueFindings(
        **shared_fields(case, verdict, records, incident_saved),
        indicators=build_indicators(case),
        recommended_actions=actions,
        detection_gaps=build_gaps(case, verdict),
    )
    # The findings are validated by the master's schema.
    # a real data structure is returned as dict rather thant plain text, 
    # so the master can use it in its own schema validation.
    return findings.model_dump(mode="json")


# RED SECRETARY FUNCTIONS CALLED BY MASTER
def build_red_findings(
    case: dict[str, Any],
    verdict: AgentVerdict,
    records: list[Record],
    impact: list[str],
    components: list[str],
    actions: list[str],
    incident_saved: bool,
) -> dict[str, Any]:
    findings = RedFindings(
        **shared_fields(case, verdict, records, incident_saved),
        exposed_ports=build_ports(records),
        impact=impact,
        affected_components=components,
        recommended_actions=actions,
    )

    return findings.model_dump(mode="json")
