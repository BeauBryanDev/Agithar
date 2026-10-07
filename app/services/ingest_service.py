import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any

from app.core.logging import get_logger
from app.correlator.decision import SEVERITY_RANK, decide
from app.correlator.scoring import compute_composite
from app.ingestion.upload import (
    UploadRejected,
    check_content,
    check_extension,
    detect_kind,
    header_columns,
    parse_access_line,
    read_flow_rows,
    safe_name,
    split_lines,
)
from app.ingestion.windows import WindowBuilder
from app.schemas.ingests import (
    Finding,
    IngestResult,
    SensorStat,
    SourceSummary,
)
from app.security.sanitize import sanitize_string
from app.sensors.base import SensorResult
from app.sensors.registry import SensorRegistry

logger = get_logger("services.ingest")

HTTP, RECON, LOGS = "http_payload_sensor", "recon_sensor", "log_sentinel"
GUARD, NETFLOW = "net_guard", "netflow_sensor"
FAR_FUTURE = 1e11
MAX_FINDING_KEYS = 5000
MAX_FINDINGS = 50
MAX_SOURCES = 20
MAX_EVENT_BLOCKS = 5000
CHECK_EVERY = 100
OPTIONAL_FLOW_COLUMN = "fwd header length.1"

KIND_LABEL = {
    "access_log": "Web access log (HTTP payload and scan sensors)",
    "event_ids": "HDFS event ids (LogSentinel)",
    "flow_csv": "Network flow CSV (NetGuard and Netflow sensors)",
}
NOTE_NOTHING_SAVED = (
    "Nothing was saved: this analysis creates no incidents and sends no "
    "alerts."
)
NOTE_PROOF = "Scores are model outputs, not proof of an attack."
NOTE_BODIES = (
    "Access logs hold no request bodies, so attacks inside POST bodies "
    "cannot be seen."
)
NOTE_FLOWS = (
    "The flow sensors were trained on CIC-IDS-2017; traffic from other "
    "networks can score unpredictably."
)


class Budget:
    def __init__(self, seconds: float) -> None:
        self.deadline = time.monotonic() + seconds

    def expired(self) -> bool:
        return time.monotonic() > self.deadline


@dataclass
class Acc:
    scored: int = 0
    flagged: int = 0
    max_score: float = 0.0

    def add(self, result: SensorResult) -> None:
        self.scored += 1
        self.max_score = max(self.max_score, result.score)

        if result.is_anomalous:
            self.flagged += 1


@dataclass
class Source:
    items: int = 0
    flagged: int = 0
    best: dict[str, dict[str, Any]] = field(default_factory=dict)

    def flag(self, result: SensorResult) -> None:
        self.flagged += 1
        event = result.to_event()
        current = self.best.get(result.sensor)

        if current is None or event["score"] > current["score"]:
            self.best[result.sensor] = event


@dataclass
class Outcome:
    items: int = 0
    unreadable: int = 0
    truncated: str | None = None
    stats: dict[str, Acc] = field(default_factory=dict)
    sources: dict[str, Source] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    breakdown: dict[str, int] = field(default_factory=dict)
    first: float | None = None
    last: float | None = None
    notes: list[str] = field(default_factory=list)

    def stat(self, sensor: str) -> Acc:
        return self.stats.setdefault(sensor, Acc())

    def source(self, name: str) -> Source:
        return self.sources.setdefault(name, Source())


def path_of(target: str | None) -> str | None:
    if not target:
        return None

    bare = target.split("?", 1)[0].split("#", 1)[0]

    return sanitize_string(bare, 200)


def known_flow_columns(registry: SensorRegistry) -> set[str]:
    names: set[str] = set()

    if GUARD in registry.sensors:
        names |= {n.lower() for n in registry.get(GUARD).preprocessor.names}

    if NETFLOW in registry.sensors:
        names |= {n.lower() for n in registry.get(NETFLOW).names}

    return names


def run_access_log(
    registry: SensorRegistry, 
    lines: list[str], 
    budget: Budget
) -> Outcome:
    """ run the access log analysis

    Args:
        registry (SensorRegistry): the sensor registry
        lines (list[str]): the access log lines
        budget (Budget): the time budget

    Returns:
        Outcome: the analysis result
    """ 
    out = Outcome(notes=[NOTE_BODIES, NOTE_PROOF])
    rows = []

    for raw in lines:
        row = parse_access_line(raw)

        if row is None:
            out.unreadable += 1

        else:
            rows.append(row)

    rows.sort(key=lambda r: r.timestamp)
    classes: Counter[str] = Counter()
    cache: dict[str, SensorResult | None] = {}
    found: dict[tuple, dict[str, Any]] = {}
    scored_rows = rows

    for index, row in enumerate(rows):
        if index % CHECK_EVERY == 0 and budget.expired():
            out.truncated = "time budget reached"
            scored_rows = rows[:index]
            break

        source = out.source(row.client_ip)
        source.items += 1
        classes[f"{row.status // 100}xx"] += 1

        if HTTP not in registry.sensors or not row.valid_request:
            continue

        if row.target not in cache:
            try:
                cache[row.target] = registry.predict(
                    HTTP, {"url": row.target}
                )

            except ValueError:
                cache[row.target] = None

        result = cache[row.target]

        if result is None:
            continue

        out.stat(HTTP).add(result)

        if not result.is_anomalous:
            continue

        source.flag(result)
        key = (row.client_ip, path_of(row.target))
        entry = found.get(key)

        if entry is None and len(found) < MAX_FINDING_KEYS:
            found[key] = entry = {
                "score": result.score, "count": 0,
                "status": row.status, "time": row.timestamp,
            }

        if entry is not None:
            entry["count"] += 1

            if result.score > entry["score"]:
                entry["score"], entry["status"] = result.score, row.status

    for (ip, path), e in found.items():
        out.findings.append(Finding(
            sensor=HTTP,
            score=round(e["score"], 3), 
            source=ip, 
            path=path,
            status=e["status"],
            count=e["count"],
            time=e["time"],
        ))

    if RECON in registry.sensors and not out.truncated:
        scan_windows(registry, scored_rows, out, budget)

    out.items = len(scored_rows)
    out.breakdown = {**dict(sorted(classes.items())),
                     "sources": len(out.sources)}

    if scored_rows:
        out.first = scored_rows[0].timestamp
        out.last = scored_rows[-1].timestamp

    return out


def scan_windows(registry, rows, 
                 out: Outcome, 
                 budget: Budget
                 ) -> None:
    
    builder = WindowBuilder()

    for row in rows:
        builder.add(row)

    for window in builder.close_ready(idle_now=FAR_FUTURE):
        if len(window.requests) < 2:
            continue

        if budget.expired():
            out.truncated = "time budget reached"
            return

        try:
            result = registry.predict(RECON, {"requests": window.requests})

        except ValueError:
            continue

        out.stat(RECON).add(result)

        if result.is_anomalous:
            out.source(window.ip).flag(result)
            out.findings.append(Finding(
                sensor=RECON, score=round(result.score, 3),
                source=window.ip, count=len(window.requests),
                detail=f"{len(window.requests)} requests in 10 seconds",
                time=window.start_timestamp,
            ))


def run_flow_csv(
    registry: SensorRegistry,
    lines: list[str],
    max_rows: int,
    budget: Budget
) -> Outcome:
    """ run the flow CSV analysis

    Args:
        registry (SensorRegistry): the sensor registry
        lines (list[str]): the flow CSV lines
        max_rows (int): the maximum number of rows to read
        budget (Budget): the time budget

    Returns:
        Outcome: the analysis result
    """
    out = Outcome(notes=[NOTE_FLOWS, NOTE_PROOF])
    header = header_columns(lines)
    guard = registry.sensors.get(GUARD)
    netflow = registry.sensors.get(NETFLOW)
    need_guard = {n.lower(): n for n in guard.preprocessor.names} if guard else {}
    need_flow = {n.lower(): n for n in netflow.names} if netflow else {}
    guard_ok = bool(guard) and all(k in header for k in need_guard)
    flow_ok = bool(netflow) and all(
        k in header for k in need_flow if k != OPTIONAL_FLOW_COLUMN
    )

    if not guard_ok and not flow_ok:
        raise UploadRejected(
            "The CSV columns do not match the CIC-IDS flow format."
        )

    if not guard_ok:
        out.notes.append("NetGuard skipped: some of its columns are missing.")

    if not flow_ok:
        out.notes.append("Netflow skipped: some of its columns are missing.")

    needed = {**(need_guard if guard_ok else {}),
              **(need_flow if flow_ok else {})
              }
    
    classes: Counter[str] = Counter()
    candidates: list[Finding] = []
    total = len(lines) - 1

    for number, features, context in read_flow_rows(lines, needed, max_rows):
        if number % CHECK_EVERY == 0 and budget.expired():
            out.truncated = "time budget reached"
            break

        if features is None:
            out.unreadable += 1
            continue

        out.items += 1
        name = context["src"] or "all flows"
        source = out.source(name)
        source.items += 1
        predicted = None

        for sensor, active in ((GUARD, guard_ok), (NETFLOW, flow_ok)):
            if not active:
                continue

            try:
                result = registry.predict(sensor, {"features": features})

            except ValueError:
                continue

            out.stat(sensor).add(result)

            if sensor == GUARD:
                predicted = str(result.detail.get("predicted_class", ""))
                classes[sanitize_string(predicted, 30) or "unknown"] += 1

            if result.is_anomalous:
                source.flag(result)
                port = context["port"]
                detail = f"row {number}"
                detail += f", {sanitize_string(predicted, 30)}" if predicted else ""
                detail += f", port {int(port)}" if port is not None else ""
                detail += f", label {context['label']}" if context["label"] else ""

                if len(candidates) < MAX_FINDING_KEYS:
                    candidates.append(Finding(
                        sensor=sensor, score=round(result.score, 3),
                        source=context["src"], detail=detail,
                    ))

    out.findings = candidates
    out.breakdown = dict(sorted(classes.items()))

    if total > max_rows and not out.truncated:
        out.truncated = f"row cap of {max_rows} reached"

    return out


def run_event_ids(
    registry: SensorRegistry,
    lines: list[str], 
    budget: Budget
) -> Outcome:
    """ run the event IDs analysis

    Args:
        registry (SensorRegistry): the sensor registry
        lines (list[str]): the event IDs lines
        budget (Budget): the time budget

    Returns:
        Outcome: the analysis result
    """
    out = Outcome(notes=[NOTE_PROOF])
    source = out.source("event blocks")

    if LOGS not in registry.sensors:
        raise UploadRejected("LogSentinel is not available.")

    for number, line in enumerate(lines[:MAX_EVENT_BLOCKS], start=1):
        if number % CHECK_EVERY == 0 and budget.expired():
            out.truncated = "time budget reached"
            break

        tokens = line.split()

        try:
            result = registry.predict(LOGS, {"events": tokens})

        except ValueError:
            out.unreadable += 1
            continue

        out.items += 1
        source.items += 1
        out.stat(LOGS).add(result)

        if result.is_anomalous:
            source.flag(result)
            out.findings.append(Finding(
                sensor=LOGS, score=round(result.score, 3),
                detail=f"block on line {number}, {len(tokens)} events",
            ))

    if len(lines) > MAX_EVENT_BLOCKS and not out.truncated:
        out.truncated = f"line cap of {MAX_EVENT_BLOCKS} reached"

    return out


def summarise(out: Outcome) -> tuple[list[SourceSummary], str, float]:
    rows = []

    for name, source in out.sources.items():
        if not source.best:
            continue

        composite = compute_composite(source.best)
        decision = decide(composite)
        rows.append(SourceSummary(
            source=sanitize_string(name, 60),
            severity=decision["severity"],
            composite_score=round(decision["composite_score"], 3),
            sensors=sorted(source.best),
            items=source.items,
            flagged=source.flagged,
        ))

    # sort by severity, then composite score, descending
    rows.sort(key=lambda r: (-SEVERITY_RANK[r.severity], -r.composite_score))

    if not rows:
        return [], "low", 0.0

    return rows[:MAX_SOURCES], rows[0].severity, rows[0].composite_score


def analyze_upload(
    registry: SensorRegistry,
    filename: str,
    data: bytes,
    *,
    max_lines: int,
    max_flow_rows: int,
    budget_seconds: float,
) -> IngestResult:
    """ analyse an uploaded file

    Args:
        registry (SensorRegistry): the sensor registry
        filename (str): the file name
        data (bytes): the file content
        max_lines (int): the maximum number of lines to read
        max_flow_rows (int): the maximum number of rows to read in a flow CSV
        budget_seconds (float): the time budget

    Returns:
        IngestResult: the analysis result
    """
    started = time.monotonic()
    name = safe_name(filename)
    check_extension(name)
    check_content(data)
    lines, cut = split_lines(data, max_lines)

    if not lines:
        raise UploadRejected("The file is empty.")

    kind = detect_kind(lines, known_flow_columns(registry))
    budget = Budget(budget_seconds)

    if kind == "access_log":
        out = run_access_log(registry, lines, budget)

    elif kind == "flow_csv":
        out = run_flow_csv(registry, lines, max_flow_rows, budget)

    else:
        out = run_event_ids(registry, lines, budget)

    if cut and not out.truncated:
        out.truncated = f"line cap of {max_lines} reached"

    if out.items == 0 and out.truncated:
        raise UploadRejected(
            "The time budget ran out before anything was analysed.", 503
        )

    if out.items == 0:
        raise UploadRejected("No line could be read as the detected format.")

    sources, severity, composite = summarise(out)
    findings = sorted(out.findings, 
                      key=lambda f: -f.score)[:MAX_FINDINGS] # lambda f: -f.score is used 
    #to sort findings by score in descending order during the analysis
    notes = [NOTE_NOTHING_SAVED, *out.notes]

    if out.truncated:
        notes.append(f"Only part of the file was analysed: {out.truncated}.")

    logger.info(
        "upload analysed",
        extra={"kind": kind, 
               "items": out.items,
               "severity": severity
               },
    )

    return IngestResult(
        filename=name,
        size_bytes=len(data),
        kind=kind,
        kind_label=KIND_LABEL[kind],
        items_read=out.items,
        items_unreadable=out.unreadable,
        truncated=out.truncated is not None,
        truncated_reason=out.truncated,
        duration_ms=int((time.monotonic() - started) * 1000),
        severity=severity,
        composite_score=composite,
        time_first=out.first,
        time_last=out.last,
        sensors=[
            SensorStat(sensor=s, 
                       scored=a.scored, 
                       flagged=a.flagged,
                       max_score=round(a.max_score, 3)
                       ) for s, a in sorted(out.stats.items())
        ],
        sources=sources,
        findings=findings,
        breakdown=out.breakdown,
        notes=notes,
    )
