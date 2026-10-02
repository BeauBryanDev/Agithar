
from typing import Any

from sqlalchemy.orm import Session

from app.db.postgresql.incidents import IOC, Incident

IOC_TYPE_IP = "ip"


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

    # TODO: today the only IOC extracted is the window IP. Sensor `detail`
    # fields carry no per-event artifacts yet (URL, user_agent, hash).
    # Once sensors are extended to log those, parse each evidence entry
    # here and add one IOC row per artifact found.
    session.add(IOC(incident_id=incident.incident_id, 
                    ioc_type=IOC_TYPE_IP, 
                    value=case["ip"])
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
    
    
# TODO. ADD List incidents by IP
# TODO. ADD List incidents by severity