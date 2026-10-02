import ipaddress
import re
from dataclasses import dataclass
from typing import Any

from app.core.logging import get_logger
from app.correlator.decision import decide
from app.correlator.scoring import compute_composite
from app.schemas.analysis import (
    AgentVerdict,
    AnalyzeRequest,
    AnalyzeResponse,
    DetectorResult,
    EvidenceRef,
    MAX_EVIDENCE_ITEMS,
)
from app.sensors.base import SensorResult
from app.sensors.registry import SensorRegistry

MAX_LINES = 2000
MAX_LINE_CHARS = 8192
MAX_RECON_IPS = 20
MAX_EVENT_TOKENS = 10000
MEDIUM_CONFIDENCE_FLOOR = 0.7
HTTP_SENSOR = "http_payload_sensor"
RECON_SENSOR = "recon_sensor"
LOG_SENSOR = "log_sentinel"


APACHE_PATTERN = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[[^\]]+\] "(?P<method>[A-Z]{3,7}) '
    r'(?P<target>\S+)(?: HTTP/[\d.]+)?" (?P<status>\d{3}) \S+'
    r'(?: "[^"]*" "(?P<agent>[^"]*)")?\s*$'
)
REQUEST_PATTERN = re.compile(
    r"^(?P<method>[A-Z]{3,7}) (?P<target>\S+)(?: HTTP/[\d.]+)?$"
)
EVENTS_PATTERN = re.compile(r"^E\d{1,2}(\s+E\d{1,2})*$")


logger = get_logger("services.analysis")


@dataclass(frozen=True)
class Job:
    sensor: str
    payload: dict[str, Any]


def parse_access_line(line: str) -> dict[str, Any] | None:
    match = APACHE_PATTERN.match(line)

    if match is None:
        return None

    try:
        ip = str(ipaddress.ip_address(match["ip"]))
        
    except ValueError:
        return None

    return {
        "ip": ip,
        "target": match["target"],
        "status": int(match["status"]),
        "agent": match["agent"] or "",
    }


def jobs_from_access_log(lines: list[str]) -> list[Job]:
    parsed = [parse_access_line(line) for line in lines]
    rows = [row for row in parsed if row is not None]
    by_ip: dict[str, list[dict[str, Any]]] = {}
    jobs = [Job(HTTP_SENSOR, {"url": row["target"]}) for row in rows]

    for row in rows:
        by_ip.setdefault(row["ip"], []).append(
            {
                "path": row["target"],
                "status": row["status"],
                "user_agent": row["agent"],
            }
        )

    for requests in list(by_ip.values())[:MAX_RECON_IPS]:
        jobs.append(Job(RECON_SENSOR, {"requests": requests}))

    return jobs


def jobs_from_request(text: str) -> list[Job]:
    head, _, body = text.partition("\n\n")
    match = REQUEST_PATTERN.match(head.strip())

    if match is None:
        return []

    return [Job(HTTP_SENSOR, {"url": match["target"], "body": body})]


def jobs_from_input(text: str) -> list[Job]:
    stripped = text.strip()

    if EVENTS_PATTERN.match(stripped):
        events = stripped.split()[:MAX_EVENT_TOKENS]

        return [Job(LOG_SENSOR, {"events": events})]

    lines = [line for line in stripped.splitlines() if line.strip()]
    lines = [line[:MAX_LINE_CHARS] for line in lines[:MAX_LINES]]
    jobs = jobs_from_access_log(lines)

    if jobs:
        return jobs

    return jobs_from_request(stripped) or [
        Job(HTTP_SENSOR, {"url": "/", "body": stripped})
    ]


def run_jobs(
    registry: SensorRegistry, jobs: list[Job]
) -> tuple[list[SensorResult], int]:
    results: list[SensorResult] = []
    skipped = 0

    for job in jobs:
        if job.sensor not in registry.sensors:
            skipped += 1
            continue

        try:
            results.append(registry.predict(job.sensor, job.payload))
            
        except ValueError:
            skipped += 1

    return results, skipped


def best_anomalous(results: list[SensorResult]) -> dict[str, dict]:
    best: dict[str, dict] = {}

    for result in results:
        event = result.to_event()
        current = best.get(result.sensor)

        if result.is_anomalous and (
            current is None or event["score"] > current["score"]
        ):
            best[result.sensor] = event

    return best


def score_of(result: SensorResult) -> float:
    return result.score


def to_evidence(results: list[SensorResult]) -> list[DetectorResult]:
    ranked = sorted(results, key=score_of, reverse=True)
    evidence = []

    for index, result in enumerate(ranked[:MAX_EVIDENCE_ITEMS]):
        evidence.append(
            DetectorResult(
                id=f"{result.sensor}-{index}",
                detector=result.sensor,
                anomaly_score=min(max(result.score, 0.0), 1.0),
                verdict="anomaly" if result.is_anomalous else "normal",
                threshold=result.threshold or 0.0,
                raw={"detail": result.detail},
            )
        )

    return evidence


def enforce_verdict(verdict: AgentVerdict, 
                    severity: str) -> AgentVerdict:
    needs_human = severity == "high" or (
        severity == "medium"
        and verdict.confidence < MEDIUM_CONFIDENCE_FLOOR
    )
    needs_human = needs_human or verdict.verdict == "needs_human"

    return verdict.model_copy(
        update={
            "needs_human": needs_human,
            "verdict": "needs_human" if needs_human else verdict.verdict,
        }
    )


def build_text(
    severity: str,
    composite: dict[str, Any],
    evidence: list[DetectorResult],
    total: int,
    skipped: int,
) -> tuple[str, list[EvidenceRef]]:
    text = (
        f"Preliminary severity {severity} (composite "
        f"{composite['composite_score']:.2f}) from {total} sensor "
        f"runs, {skipped} skipped."
    )
    refs: list[EvidenceRef] = []
    seen: set[str] = set()

    for item in evidence:
        if item.verdict != "anomaly" or item.detector in seen:
            continue

        seen.add(item.detector)
        sentence = (
            f"{item.detector} flagged an anomaly, score "
            f"{item.anomaly_score:.2f} against threshold "
            f"{item.threshold:.2f}."
        )
        start = len(text) + 1
        text = f"{text} {sentence}"
        refs.append(EvidenceRef(id=item.id, 
                                claim_span=(start, len(text))))

    return text, refs


def analyze(
    registry: SensorRegistry, 
    request: AnalyzeRequest
) -> AnalyzeResponse:
    jobs = jobs_from_input(request.input)
    results, skipped = run_jobs(registry, jobs)

    if not results:
        raise ValueError("no sensor could analyze this input")

    composite = compute_composite(best_anomalous(results))
    severity = decide(composite)["severity"]
    evidence = to_evidence(results)
    text, refs = build_text(
        severity, 
        composite, 
        evidence, 
        len(results), 
        skipped
    )
    logger.info(
        "analysis done",
        extra={"severity": severity, 
               "runs": len(results)
               },
    )

    return AnalyzeResponse(text=text, 
                           evidence=evidence, 
                           evidence_refs=refs)
