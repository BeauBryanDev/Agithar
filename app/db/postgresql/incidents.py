
from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, Integer, String, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.postgresql.users import Base


class Incident(Base):
    __tablename__ = "incidents"

    incident_id: Mapped[int] = mapped_column(
        Integer, primary_key=True, autoincrement=True
    )
    case_key: Mapped[str] = mapped_column(
        String(80), unique=True, index=True, nullable=False
    )
    ip: Mapped[str] = mapped_column(String(45), index=True, nullable=False)
    severity: Mapped[str] = mapped_column(String(10), nullable=False)
    composite_score: Mapped[float] = mapped_column(nullable=False)
    num_sensors: Mapped[int] = mapped_column(Integer, nullable=False)
    num_strong_sensors: Mapped[int] = mapped_column(Integer, nullable=False)
    contributing_sensors: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    sensor_scores: Mapped[dict] = mapped_column(JSONB, nullable=False)
    event_counts: Mapped[dict] = mapped_column(JSONB, nullable=False)
    evidence: Mapped[list[dict]] = mapped_column(JSONB, nullable=False)
    status: Mapped[str] = mapped_column(
        String(20), default="open", 
        server_default="open", 
        nullable=False
    )
    
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), 
        server_default=func.now(),
        nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    iocs: Mapped[list["IOC"]] = relationship(back_populates="incident")
    actions: Mapped[list["ActionTaken"]] = relationship(back_populates="incident")

    def __repr__(self) -> str:
        return f"Incident(incident_id={self.incident_id}, case_key={self.case_key!r})"


class IOC(Base):
    __tablename__ = "iocs"

    ioc_id: Mapped[int] = mapped_column(
        Integer, primary_key=True, autoincrement=True
    )
    incident_id: Mapped[int] = mapped_column(
        ForeignKey("incidents.incident_id"), index=True, nullable=False
    )
    ioc_type: Mapped[str] = mapped_column(String(20), nullable=False)
    value: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), 
        server_default=func.now(), 
        nullable=False
    )

    incident: Mapped["Incident"] = relationship(back_populates="iocs")

    def __repr__(self) -> str:
        return f"IOC(ioc_id={self.ioc_id}, ioc_type={self.ioc_type!r}, value={self.value!r})"


class ActionTaken(Base):
    __tablename__ = "actions_taken"

    action_id: Mapped[int] = mapped_column(
        Integer, primary_key=True, autoincrement=True
    )
    incident_id: Mapped[int] = mapped_column(
        ForeignKey("incidents.incident_id"), index=True, nullable=False
    )
    tool_name: Mapped[str] = mapped_column(String(50), nullable=False)
    params: Mapped[Optional[dict]] = mapped_column(JSONB)
    result: Mapped[Optional[dict]] = mapped_column(JSONB)
    performed_by: Mapped[str] = mapped_column(String(50), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    incident: Mapped["Incident"] = relationship(back_populates="actions")

    def __repr__(self) -> str:
        return f"ActionTaken(action_id={self.action_id}, tool_name={self.tool_name!r})"
    
    