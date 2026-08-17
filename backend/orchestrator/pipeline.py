"""Phase 3 pipeline — real recon stage + stub for remaining stages."""

import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy.orm import Session

from core.config import get_settings
from core.events import publish_scan_event
from db.models import PIPELINE_STAGES, PipelineEvent, PipelineEventLevel, Scan, ScanStatus
from db.session import SessionLocal
from orchestrator.state_machine import frontend_stage, stage_backend_name


def _log_event(
    db: Session,
    scan: Scan,
    stage: str,
    message: str,
    level: PipelineEventLevel = PipelineEventLevel.INFO,
) -> None:
    event = PipelineEvent(
        scan_id=scan.id,
        stage=stage,
        level=level,
        message=message,
    )
    db.add(event)
    db.commit()
    publish_scan_event(
        str(scan.id),
        "log",
        stage=stage,
        level=level.value,
        message=message,
    )


def _run_recon_stage(db: Session, scan: Scan) -> None:
    from recon.engine import run_recon

    source_dir = _source_dir(scan)
    if not source_dir.is_dir():
        raise FileNotFoundError(f"Source directory not found: {source_dir}")

    _log_event(db, scan, "recon", "Parsing AST + running Semgrep security audit")
    result = run_recon(str(scan.id), source_dir)
    _log_event(
        db,
        scan,
        "recon",
        f"Recon complete — {result.functions_mapped} functions, "
        f"{result.findings_count} static findings, top target score {result.targets[0].score if result.targets else 0}",
    )


def _source_dir(scan: Scan) -> Path:
    settings = get_settings()
    if scan.artifact_root:
        root = Path(scan.artifact_root) / "source"
        extracted = root / "extracted"
        if extracted.is_dir():
            return extracted
        if root.is_dir():
            return root
    return settings.scan_source_dir(str(scan.id))


def run_pipeline(scan_id: str) -> None:
    """Run pipeline — real recon, stub for other stages (Phase 3)."""
    settings = get_settings()
    db = SessionLocal()
    try:
        scan = db.get(Scan, uuid.UUID(scan_id))
        if not scan:
            return

        scan.status = ScanStatus.RUNNING
        scan.started_at = scan.started_at or datetime.now(timezone.utc)
        db.commit()
        publish_scan_event(str(scan.id), "pipeline_started")

        for stage_status in PIPELINE_STAGES:
            stage_key = stage_backend_name(stage_status)
            scan.status = stage_status
            scan.current_stage = frontend_stage(stage_status, None)
            db.commit()

            publish_scan_event(str(scan.id), "stage_started", stage=stage_key)
            stage_start = time.perf_counter()

            if stage_status == ScanStatus.STAGE_RECON:
                _run_recon_stage(db, scan)
            else:
                _log_event(db, scan, stage_key, f"Stage {stage_key} started (stub)")
                time.sleep(settings.pipeline_stage_delay_sec)
                _log_event(db, scan, stage_key, f"Stage {stage_key} completed (stub)")

            duration = time.perf_counter() - stage_start
            publish_scan_event(
                str(scan.id),
                "stage_completed",
                stage=stage_key,
                duration_sec=round(duration, 1),
            )

        scan.status = ScanStatus.AWAITING_GATE
        scan.current_stage = "reportgate"
        scan.completed_at = datetime.now(timezone.utc)
        if scan.started_at:
            scan.duration_sec = int((scan.completed_at - scan.started_at).total_seconds())
        db.commit()

        publish_scan_event(str(scan.id), "scan_complete", recommendation="REVIEW")

    except Exception as exc:
        db.rollback()
        scan = db.get(Scan, uuid.UUID(scan_id))
        if scan:
            scan.status = ScanStatus.FAILED
            scan.error_message = str(exc)
            db.commit()
            publish_scan_event(
                str(scan.id),
                "stage_failed",
                stage=scan.current_stage or "unknown",
                error=str(exc),
            )
        raise
    finally:
        db.close()


def run_stub_pipeline(scan_id: str) -> None:
    """Backward-compatible alias."""
    run_pipeline(scan_id)


def enqueue_pipeline(scan_id: str) -> None:
    from workers.pipeline.task import run_pipeline_task

    run_pipeline_task.delay(scan_id)
