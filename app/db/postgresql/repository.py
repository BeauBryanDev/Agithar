
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.postgresql.incidents import IOC, Incident

IOC_TYPE_IP = "ip"
IOC_TYPE_URL = "url"
IOC_TYPE_USER_AGENT = "user_agent"
MAX_IOC_VALUE_CHARS = 255
MAX_PAGE_SIZE = 100
SEVERITIES = ("low", "medium", "high")


def extract_iocs(case: dict[str, Any]) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = [(IOC_TYPE_IP, case["ip"])]

    for event in case["evidence"]:
        context = event.get("context") or {}
        path = context.get("path")
        agent = context.get("user_agent_sha256")

        if path:
            found.append((IOC_TYPE_URL, path[:MAX_IOC_VALUE_CHARS]))

        if agent:
            found.append((IOC_TYPE_USER_AGENT, agent))

    return list(dict.fromkeys(found))


def save_incident(session: Session, case: dict[str, Any]) -> Incident:
    incident = Incident(
        case_key=case["case_id"],
        ip=case["ip"],
        severity=case["severity"],
        composite_score=case["composite_score"],
        num_sensors=case["num_sensors"],
        num_strong_sensors=case["num_strong_sensors"],
        contributing_sensors=case["contributing_sensors"],
        sensor_scores=case["sensor_scores"],
        event_counts=case["event_counts"],
        evidence=case["evidence"],
    )
    session.add(incident)
    session.flush()

    for ioc_type, value in extract_iocs(case):
        session.add(
            IOC(
                incident_id=incident.incident_id,
                ioc_type=ioc_type,
                value=value,
            )
        )

    session.commit()
    session.refresh(incident)

    return incident

# read incidents by case key

def get_incident_by_case_key(session: Session, 
                             case_key: str
                             ) -> Incident | None:
    
    return (
        session.query(Incident)
        .filter(Incident.case_key == case_key)
        .one_or_none()
    )
    
    
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
