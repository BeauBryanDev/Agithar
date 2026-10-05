
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db.postgresql.incidents import IOC, Incident
from app.security.sanitize import sanitize_string

IOC_TYPE_IP = "ip"
IOC_TYPE_URL = "url"
IOC_TYPE_USER_AGENT = "user_agent"
MAX_IOC_VALUE_CHARS = 255
MAX_PAGE_SIZE = 100
SEVERITIES = ("low", "medium", "high")
MAX_REPORT_CHARS = 20000
VERDICT_STATUSES = ("confirmed", "false_positive", "needs_human")


def extract_iocs(case: dict[str, Any]) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = [(IOC_TYPE_IP, case["ip"])]

    for event in case["evidence"]:
        context = event.get("context") or {}
        path = context.get("path")
        agent = context.get("user_agent_sha256")

        if path:
            found.append((IOC_TYPE_URL, 
                          path[:MAX_IOC_VALUE_CHARS])
                         )

        if agent:
            found.append((IOC_TYPE_USER_AGENT, agent))

    return list(dict.fromkeys(found))


def get_incident_by_case_key(session: Session, 
                             case_key: str
                             ) -> Incident | None:
    
    return (
        session.query(Incident)
        .filter(Incident.case_key == case_key)
        .one_or_none()
    )


def apply_case(incident: Incident, 
               case: dict[str, Any]
               ) -> None:
    incident.ip = case["ip"]
    incident.severity = case["severity"]
    incident.composite_score = case["composite_score"]
    incident.num_sensors = case["num_sensors"]
    incident.num_strong_sensors = case["num_strong_sensors"]
    incident.contributing_sensors = case["contributing_sensors"]
    incident.sensor_scores = case["sensor_scores"]
    incident.event_counts = case["event_counts"]
    incident.evidence = case["evidence"]


def add_missing_iocs(
    session: Session,
    incident: Incident, 
    case: dict[str, Any]
) -> None:
    known = {(ioc.ioc_type, ioc.value) for ioc in incident.iocs}

    for ioc_type, value in extract_iocs(case):
        if (ioc_type, value) not in known:
            session.add(
                IOC(
                    incident_id=incident.incident_id,
                    ioc_type=ioc_type,
                    value=value,
                )
            )


def flush_incident(
    session: Session, 
    incident: Incident, 
    case: dict[str, Any]
) -> Incident:
    # Two workers may create the same window at once: the unique case_key
    # rejects the second insert, which then becomes an update.
    try:
        session.flush()
    except IntegrityError:
        session.rollback()
        incident = get_incident_by_case_key(session, case["case_id"])

        if incident is None:
            raise

        apply_case(incident, case)
        session.flush()

    return incident


def save_incident(session: Session, case: dict[str, Any]) -> Incident:
    # A window can escalate again when its severity rises: same case_key,
    # so the existing incident is updated instead of inserted twice.
    incident = get_incident_by_case_key(session, case["case_id"])

    if incident is None:
        incident = Incident(case_key=case["case_id"])
        session.add(incident)

    apply_case(incident, case)
    incident = flush_incident(session, incident, case)
    add_missing_iocs(session, incident, case)

    session.commit()
    session.refresh(incident)

    return incident


def list_incidents(
    session: Session,
    column: Any,
    value: str,
    skip: int,
    limit: int,
) -> tuple[list[Incident], int]:
    skip = max(skip, 0)
    limit = min(max(limit, 1), MAX_PAGE_SIZE)

    total = session.scalar(
        select(func.count()).select_from(Incident).where(column == value)
    )
    items = session.scalars(
        select(Incident)
        .where(column == value)
        .order_by(Incident.created_at.desc(), 
                  Incident.incident_id.desc())
        .offset(skip)
        .limit(limit)
    ).all()

    return list(items), total or 0


def list_incidents_by_ip(
    session: Session,
    ip: str,
    skip: int = 0,
    limit: int = 50,
) -> tuple[list[Incident], int]:
    
    return list_incidents(session, 
                          Incident.ip, 
                          ip, skip, limit
                          )


def list_incidents_by_severity(
    session: Session,
    severity: str,
    skip: int = 0,
    limit: int = 50,
) -> tuple[list[Incident], int]:
    if severity not in SEVERITIES:
        raise ValueError("severity must be low, medium or high")

    return list_incidents(session, 
                          Incident.severity, 
                          severity, skip, limit)


def save_report(
    session: Session,
    incident_id: int,
    verdict: dict[str, Any],
    report_md: str | None,
    notified: bool,
) -> Incident:
    incident = session.get(Incident, incident_id)

    if incident is None:
        raise ValueError("incident not found")

    if verdict["verdict"] not in VERDICT_STATUSES:
        raise ValueError("unknown verdict")

    incident.verdict = verdict
    incident.status = verdict["verdict"]
    incident.notified = notified
    incident.report_md = (
        sanitize_string(report_md, 
                        MAX_REPORT_CHARS, 
                        keep_newlines=True
                        ) if report_md else None    
    )

    session.commit()
    session.refresh(incident)

    return incident
