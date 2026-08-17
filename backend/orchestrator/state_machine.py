"""Scan status state machine helpers."""

from db.models import PIPELINE_STAGES, STAGE_FRONTEND_MAP, ScanStatus


def frontend_stage(status: ScanStatus, current_stage: str | None) -> str:
    """Map backend status to frontend stage id."""
    if status in STAGE_FRONTEND_MAP:
        return STAGE_FRONTEND_MAP[status]
    if current_stage:
        return current_stage
    if status == ScanStatus.QUEUED:
        return "recon"
    if status in (ScanStatus.RUNNING, ScanStatus.FAILED):
        return current_stage or "recon"
    return "reportgate"


def frontend_scan_status(status: ScanStatus) -> str:
    """Map backend status to frontend dashboard status badge."""
    mapping = {
        ScanStatus.QUEUED: "queued",
        ScanStatus.RUNNING: "running",
        ScanStatus.STAGE_RECON: "running",
        ScanStatus.STAGE_BUGFINDING: "running",
        ScanStatus.STAGE_POV: "running",
        ScanStatus.STAGE_VULNDNA: "running",
        ScanStatus.STAGE_PATCH: "running",
        ScanStatus.STAGE_REPORT: "running",
        ScanStatus.AWAITING_GATE: "review",
        ScanStatus.APPROVED: "safe",
        ScanStatus.REJECTED: "hold",
        ScanStatus.HOLD: "hold",
        ScanStatus.COMPLETED: "safe",
        ScanStatus.FAILED: "hold",
    }
    return mapping.get(status, "running")


def stage_backend_name(status: ScanStatus) -> str:
    """Short stage key for events (recon, bugfinding, …)."""
    return STAGE_FRONTEND_MAP.get(status, status.value.replace("stage_", ""))


def next_pipeline_stage(current: ScanStatus) -> ScanStatus | None:
    try:
        idx = PIPELINE_STAGES.index(current)
    except ValueError:
        if current == ScanStatus.RUNNING:
            return PIPELINE_STAGES[0]
        return None
    if idx + 1 < len(PIPELINE_STAGES):
        return PIPELINE_STAGES[idx + 1]
    return None
