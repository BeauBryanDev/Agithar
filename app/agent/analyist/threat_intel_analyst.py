
import re
import json 
import asyncio
from collections.abc import Awaitable, Callable
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any

from langchain_core.messages import HumanMessage, SystemMessage

from app.agent.llm.analysts_client import get_analyst_client
from app.core.logging import get_logger
from app.schemas.intel_report import (
    IndicatorFacts,
    IndicatorInput,
    IntelAssessment,
    IntelReport,
)
from app.security.sanitize import escape_json, sanitize_string
from app.services import (
    abuse_ip_service,
    ip_geo_loc,
    shodan_service,
    virustotal_service,
)

logger = get_logger("agent.analysts.intel")

PROMPT_PATH = (
    Path(__file__).resolve().parent.parent
    / "prompts"
    / "threat_intel_analyst.md"
)
SOURCE_TIMEOUT_SECONDS = 10
MAX_INDICATORS = 10
MAX_PORTS = 64
MAX_TAGS = 16
MAX_ASN_CHARS = 128
SUMMARY_CHARS = 500
NOTES_CHARS = 800
COUNTRY_PATTERN = re.compile(r"^[A-Z]{2}$")
VT_COUNT_KEYS = ("malicious", "suspicious", "harmless", "undetected")

Lookup = Callable[[str], Awaitable[dict[str, Any]]]


class AnalystRefusedError(Exception):
    pass


class AnalystOutputError(Exception):
    pass


@lru_cache(maxsize=1)
def load_prompt() -> str:
    return PROMPT_PATH.read_text(encoding="utf-8")


def sources_for(indicator: IndicatorInput) -> dict[str, Lookup]:
    # VirusTotal has no domain lookup here, so a domain gets no sources.
    if indicator.kind == "ip":
        return {
            "virustotal": virustotal_service.check_ip,
            "abuseipdb": abuse_ip_service.check_ip,
            "shodan": shodan_service.check_ip,
            "geo": ip_geo_loc.geo_lookup,
        }

    if indicator.kind == "url":
        return {"virustotal": virustotal_service.check_url}

    if indicator.kind == "file_hash":
        return {"virustotal": virustotal_service.check_hash}

    return {}


async def query_source(
    name: str,
    lookup: Lookup,
    value: str,
) -> tuple[str, dict[str, Any] | None]:
    # The coroutine is created inside the try, so a failure while building
    # the call only empties this source's fields.
    try:
        data = await asyncio.wait_for(lookup(value), SOURCE_TIMEOUT_SECONDS)

    except Exception as exc:
        logger.warning("intel source %s failed: %s", name, type(exc).__name__)
        return name, None

    if not isinstance(data, dict):
        return name, None

    return name, data


def as_int(value: Any, 
    low: int = 0, 
    high: int | None = None
) -> int | None:

    if isinstance(value, bool) or not isinstance(value, int):
        return None

    if value < low or (high is not None and value > high):
        return None

    return value


def clean_country(value: Any) -> str | None:
    if not isinstance(value, str):
        return None

    code = value.strip().upper()

    if not COUNTRY_PATTERN.match(code):
        return None

    return code


def clean_asn(value: Any) -> str | None:
    if not isinstance(value, str):
        return None

    return sanitize_string(value, MAX_ASN_CHARS)[:MAX_ASN_CHARS] or None


def clean_ports(values: Any) -> list[int]:
    if not isinstance(values, list):
        return []

    ports = []

    for value in values:
        port = as_int(value, 1, 65535)

        if port is not None and port not in ports:
            ports.append(port)

    return ports[:MAX_PORTS]


def vt_engines(vt: dict[str, Any]) -> int | None:
    if not vt.get("found"):
        return None

    total = 0

    for key in VT_COUNT_KEYS:
        total += as_int(vt.get(key)) or 0

    return total


def build_facts(
    indicator: IndicatorInput,
    results: dict[str, dict[str, Any] | None],
) -> IndicatorFacts:
    abuse = results.get("abuseipdb") or {}
    shodan = results.get("shodan") or {}
    vt = results.get("virustotal") or {}
    geo = results.get("geo") or {}

    return IndicatorFacts(
        value=indicator.value,
        kind=indicator.kind,
        abuseipdb_score=as_int(abuse.get("abuse_confidence_score"), 0, 100),
        abuseipdb_reports=as_int(abuse.get("total_reports")),
        virustotal_malicious=as_int(vt.get("malicious")),
        virustotal_engines=vt_engines(vt),
        shodan_ports=clean_ports(shodan.get("ports")),
        shodan_tags=list(shodan.get("tags") or [])[:MAX_TAGS],
        country=clean_country(abuse.get("country_code")),
        asn_org=clean_asn(geo.get("asn") or geo.get("org")),
        failed_sources=[name for name, data in results.items() if data is None],
    )


async def gather_indicator(indicator: IndicatorInput) -> IndicatorFacts:
    sources = sources_for(indicator)

    pairs = await asyncio.gather(
        *(
            query_source(name, lookup, indicator.value)
            for name, lookup in sources.items()
        )
    )

    return build_facts(indicator, dict(pairs))


def build_messages(
    case_key: str | None,
    facts: list[IndicatorFacts],
) -> list[SystemMessage | HumanMessage]:
    payload = escape_json([fact.model_dump(mode="json") for fact in facts])
    case_line = sanitize_string(case_key or "none", 128)

    return [
        SystemMessage(load_prompt()),
        HumanMessage(
            f"Case: {case_line}\n"
            f"<intel_facts>\n{payload}\n</intel_facts>"
        ),
    ]


def clean_assessment(parsed: IntelAssessment) -> IntelAssessment:
    # Text written by the model is sanitized and checked again.
    data = parsed.model_dump()
    data["summary"] = sanitize_string(data["summary"], SUMMARY_CHARS)
    data["notes"] = sanitize_string(data["notes"], NOTES_CHARS)
    data["summary"] = data["summary"][:SUMMARY_CHARS]
    data["notes"] = data["notes"][:NOTES_CHARS]

    return IntelAssessment.model_validate(data)


async def assess(
    case_key: str | None,
    facts: list[IndicatorFacts],
) -> IntelAssessment:
    llm = get_analyst_client().with_structured_output(
        IntelAssessment,
        method="json_schema",
        include_raw=True,
    )
    output = await llm.ainvoke(build_messages(case_key, facts))

    raw = output.get("raw")
    stop_reason = getattr(raw, "response_metadata", {}).get("stop_reason")

    if stop_reason == "refusal":
        raise AnalystRefusedError("intel analyst declined the request")

    parsed = output.get("parsed")

    if output.get("parsing_error") is not None or parsed is None:
        raise AnalystOutputError("intel assessment did not parse")

    return clean_assessment(parsed)


async def run_intel_analyst(
    case_key: str | None,
    indicators: list[IndicatorInput],
) -> IntelReport:
    selected = indicators[:MAX_INDICATORS]
    facts = list(
        await asyncio.gather(*(gather_indicator(i) for i in selected))
    )
    assessment = await assess(case_key, facts)

    return IntelReport(
        case_key=case_key,
        generated_at=datetime.now(timezone.utc),
        facts=facts,
        assessment=assessment,
    )
