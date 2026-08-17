"""SQLAlchemy ORM models — Phase 0: scans + pipeline_events."""

import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, Enum, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class ScanStatus(str, enum.Enum):
    QUEUED = "queued"
    RUNNING = "running"
    STAGE_RECON = "stage_recon"
    STAGE_BUGFINDING = "stage_bugfinding"
    STAGE_POV = "stage_pov"
    STAGE_VULNDNA = "stage_vulndna"
    STAGE_PATCH = "stage_patch"
    STAGE_REPORT = "stage_report"
    AWAITING_GATE = "awaiting_gate"
    APPROVED = "approved"
    REJECTED = "rejected"
    HOLD = "hold"
    COMPLETED = "completed"
    FAILED = "failed"


# Frontend-facing stage ids (matches frontend/src/data/stages.js)
STAGE_FRONTEND_MAP = {
    ScanStatus.STAGE_RECON: "recon",
    ScanStatus.STAGE_BUGFINDING: "bugfinding",
    ScanStatus.STAGE_POV: "verification",
    ScanStatus.STAGE_VULNDNA: "vulndna",
    ScanStatus.STAGE_PATCH: "patchengine",
    ScanStatus.STAGE_REPORT: "reportgate",
    ScanStatus.AWAITING_GATE: "reportgate",
}


PIPELINE_STAGES = [
    ScanStatus.STAGE_RECON,
    ScanStatus.STAGE_BUGFINDING,
    ScanStatus.STAGE_POV,
    ScanStatus.STAGE_VULNDNA,
    ScanStatus.STAGE_PATCH,
    ScanStatus.STAGE_REPORT,
]


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    target_name: Mapped[str] = mapped_column(String(512), nullable=False)
    status: Mapped[ScanStatus] = mapped_column(
        Enum(ScanStatus, name="scan_status", native_enum=False),
        default=ScanStatus.QUEUED,
        nullable=False,
    )
    current_stage: Mapped[str | None] = mapped_column(String(64), nullable=True)
    artifact_root: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    languages: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    file_count: Mapped[int] = mapped_column(Integer, default=0)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    duration_sec: Mapped[int] = mapped_column(Integer, default=0)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )

    events: Mapped[list["PipelineEvent"]] = relationship(
        "PipelineEvent", back_populates="scan", cascade="all, delete-orphan"
    )
    recon_targets: Mapped[list["ReconTarget"]] = relationship(
        "ReconTarget", back_populates="scan", cascade="all, delete-orphan"
    )
    static_findings: Mapped[list["StaticFinding"]] = relationship(
        "StaticFinding", back_populates="scan", cascade="all, delete-orphan"
    )


class ReconTarget(Base):
    __tablename__ = "recon_targets"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )
    function: Mapped[str] = mapped_column(String(256), nullable=False)
    file: Mapped[str] = mapped_column(String(1024), nullable=False)
    line: Mapped[int] = mapped_column(Integer, default=0)
    risk: Mapped[str] = mapped_column(String(32), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    sinks: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    call_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    input_sources: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    score: Mapped[int] = mapped_column(Integer, default=0)
    rank: Mapped[int] = mapped_column(Integer, default=0)

    scan: Mapped["Scan"] = relationship("Scan", back_populates="recon_targets")


class StaticFinding(Base):
    __tablename__ = "static_findings"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )
    rule: Mapped[str] = mapped_column(String(512), nullable=False)
    file: Mapped[str] = mapped_column(String(1024), nullable=False)
    line: Mapped[int] = mapped_column(Integer, default=0)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    code_snippet: Mapped[str | None] = mapped_column(Text, nullable=True)

    scan: Mapped["Scan"] = relationship("Scan", back_populates="static_findings")


class PipelineEventLevel(str, enum.Enum):
    INFO = "info"
    WARN = "warn"
    ERROR = "error"


class PipelineEvent(Base):
    __tablename__ = "pipeline_events"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )
    stage: Mapped[str | None] = mapped_column(String(64), nullable=True)
    level: Mapped[PipelineEventLevel] = mapped_column(
        Enum(PipelineEventLevel, name="pipeline_event_level", native_enum=False),
        default=PipelineEventLevel.INFO,
        nullable=False,
    )
    message: Mapped[str] = mapped_column(Text, nullable=False)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )

    scan: Mapped["Scan"] = relationship("Scan", back_populates="events")
