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
    fuzz_runs: Mapped[list["FuzzRun"]] = relationship(
        "FuzzRun", back_populates="scan", cascade="all, delete-orphan"
    )
    crashes: Mapped[list["Crash"]] = relationship(
        "Crash", back_populates="scan", cascade="all, delete-orphan"
    )
    verified_povs: Mapped[list["VerifiedPoV"]] = relationship(
        "VerifiedPoV", back_populates="scan", cascade="all, delete-orphan"
    )
    patch_candidates: Mapped[list["PatchCandidate"]] = relationship(
        "PatchCandidate", back_populates="scan", cascade="all, delete-orphan"
    )
    reports: Mapped[list["Report"]] = relationship(
        "Report", back_populates="scan", cascade="all, delete-orphan"
    )
    gate_decisions: Mapped[list["GateDecision"]] = relationship(
        "GateDecision", back_populates="scan", cascade="all, delete-orphan"
    )
    learning_log_entries: Mapped[list["LearningLogEntry"]] = relationship(
        "LearningLogEntry", back_populates="scan", cascade="all, delete-orphan"
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


class FuzzRun(Base):
    __tablename__ = "fuzz_runs"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )
    status: Mapped[str] = mapped_column(String(32), default="complete", nullable=False)
    runtime_sec: Mapped[int] = mapped_column(Integer, default=0)
    execs_per_sec: Mapped[int] = mapped_column(Integer, default=0)
    total_execs: Mapped[int] = mapped_column(Integer, default=0)
    crashes_found: Mapped[int] = mapped_column(Integer, default=0)
    unique_crashes: Mapped[int] = mapped_column(Integer, default=0)
    coverage_pct: Mapped[float] = mapped_column(Integer, default=0)
    coverage_gain: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    target_reached: Mapped[bool] = mapped_column(default=False)
    escalated: Mapped[bool] = mapped_column(default=False)
    seeds_count: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )

    scan: Mapped["Scan"] = relationship("Scan", back_populates="fuzz_runs")


class Crash(Base):
    __tablename__ = "crashes"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )
    status: Mapped[str] = mapped_column(String(32), default="unverified", nullable=False)
    type: Mapped[str] = mapped_column(String(128), nullable=False)
    cwe: Mapped[str] = mapped_column(String(32), nullable=False)
    file: Mapped[str] = mapped_column(String(1024), nullable=False)
    line: Mapped[int] = mapped_column(Integer, default=0)
    function: Mapped[str] = mapped_column(String(256), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), default="HIGH", nullable=False)
    signal: Mapped[str] = mapped_column(String(32), default="SIGABRT", nullable=False)
    return_code: Mapped[int] = mapped_column(Integer, default=0)
    confidence: Mapped[int] = mapped_column(Integer, default=0)
    asan_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    stack_trace: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    reproduced: Mapped[bool] = mapped_column(default=False)
    deduplicated: Mapped[bool] = mapped_column(default=False)
    crash_input: Mapped[str | None] = mapped_column(Text, nullable=True)
    discovery_method: Mapped[str] = mapped_column(String(64), default="fuzzing", nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )

    scan: Mapped["Scan"] = relationship("Scan", back_populates="crashes")
    verified_pov: Mapped["VerifiedPoV | None"] = relationship(
        "VerifiedPoV", back_populates="crash", uselist=False, cascade="all, delete-orphan"
    )


class VerifiedPoV(Base):
    __tablename__ = "verified_povs"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )
    crash_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("crashes.id", ondelete="SET NULL"), nullable=True
    )
    confidence: Mapped[int] = mapped_column(Integer, default=0)
    cwe: Mapped[str] = mapped_column(String(32), nullable=False)
    crash_type: Mapped[str | None] = mapped_column(String(128), nullable=True)
    sanitizer_report: Mapped[str | None] = mapped_column(Text, nullable=True)
    dedup_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    reproducible: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )

    scan: Mapped["Scan"] = relationship("Scan", back_populates="verified_povs")
    crash: Mapped["Crash | None"] = relationship("Crash", back_populates="verified_pov")


class PatchCandidate(Base):
    __tablename__ = "patch_candidates"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )
    agent: Mapped[str] = mapped_column(String(32), nullable=False)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    strategy: Mapped[str] = mapped_column(Text, nullable=False)
    diff: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="REJECTED", nullable=False)
    score_security: Mapped[float] = mapped_column(default=0.0)
    score_regression: Mapped[float] = mapped_column(default=0.0)
    score_performance: Mapped[float] = mapped_column(default=0.0)
    score_rediscovery: Mapped[float] = mapped_column(default=0.0)
    score_total: Mapped[float] = mapped_column(default=0.0)
    rejected_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    lines_changed: Mapped[int] = mapped_column(Integer, default=0)
    files_changed: Mapped[int] = mapped_column(Integer, default=1)
    verification_passed: Mapped[bool] = mapped_column(default=False)
    attacks_blocked: Mapped[int] = mapped_column(Integer, default=0)
    attacks_total: Mapped[int] = mapped_column(Integer, default=9)
    regression_passed: Mapped[int] = mapped_column(Integer, default=0)
    regression_total: Mapped[int] = mapped_column(Integer, default=0)
    performance_overhead: Mapped[str] = mapped_column(String(32), default="0.0%")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )

    scan: Mapped["Scan"] = relationship("Scan", back_populates="patch_candidates")


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )
    report_id: Mapped[str] = mapped_column(String(64), nullable=False)
    recommendation: Mapped[str] = mapped_column(String(32), default="REVIEW", nullable=False)
    confidence: Mapped[int] = mapped_column(Integer, default=0)
    cvss_score: Mapped[float] = mapped_column(default=0.0)
    root_cause: Mapped[str] = mapped_column(Text, nullable=False)
    report_json: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )

    scan: Mapped["Scan"] = relationship("Scan", back_populates="reports")


class GateDecision(Base):
    __tablename__ = "gate_decisions"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )
    decision: Mapped[str] = mapped_column(String(32), nullable=False)
    decided_by: Mapped[str] = mapped_column(String(128), default="Security Lead", nullable=False)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    decided_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )

    scan: Mapped["Scan"] = relationship("Scan", back_populates="gate_decisions")


class LearningLogEntry(Base):
    __tablename__ = "learning_log_entries"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    scan_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scans.id", ondelete="SET NULL"), nullable=True
    )
    entry_id: Mapped[str] = mapped_column(String(64), nullable=False)
    date: Mapped[str] = mapped_column(String(32), nullable=False)
    target: Mapped[str] = mapped_column(String(256), nullable=False)
    cwe: Mapped[str] = mapped_column(String(32), nullable=False)
    crash_type: Mapped[str] = mapped_column(String(128), nullable=False)
    discovery_method: Mapped[str] = mapped_column(String(128), nullable=False)
    winning_agent: Mapped[str] = mapped_column(String(128), nullable=False)
    confidence: Mapped[int] = mapped_column(Integer, default=0)
    patch_success: Mapped[bool] = mapped_column(default=True)
    top_cve: Mapped[str | None] = mapped_column(String(64), nullable=True)
    notes: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )

    scan: Mapped["Scan | None"] = relationship("Scan", back_populates="learning_log_entries")


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
