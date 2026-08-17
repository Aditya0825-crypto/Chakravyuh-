"""Celery task for Stage 2 Bug Finding."""

from pathlib import Path
import uuid

from workers.celery_app import celery_app


@celery_app.task(name="chakravyuh.bug_finding", bind=True, max_retries=0)
def task_bug_finding(self, scan_id: str) -> dict:
    from core.config import get_settings
    from core.events import publish_scan_event
    from db.models import Scan, ScanStatus
    from db.session import SessionLocal
    from workers.bug_finding.orchestrator import run_bug_finding

    settings = get_settings()
    db = SessionLocal()

    try:
        scan = db.get(Scan, uuid.UUID(scan_id))
        if not scan:
            return {"scan_id": scan_id, "error": "scan not found"}

        scan.status = ScanStatus.STAGE_BUGFINDING
        scan.current_stage = "bugfinding"
        db.commit()

        publish_scan_event(scan_id, "stage_started", stage="bugfinding")

        source_dir = _resolve_source_dir(scan, settings)
        result = run_bug_finding(scan_id, source_dir)

        publish_scan_event(
            scan_id,
            "stage_completed",
            stage="bugfinding",
            duration_sec=round(result.duration_sec, 1),
            crashes_found=len(result.crashes),
        )

        return {
            "scan_id": scan_id,
            "crashes_found": len(result.crashes),
            "duration_sec": result.duration_sec,
        }
    except Exception as exc:
        publish_scan_event(scan_id, "stage_failed", stage="bugfinding", error=str(exc))
        raise
    finally:
        db.close()


def _resolve_source_dir(scan, settings) -> Path:
    if scan.artifact_root:
        root = Path(scan.artifact_root) / "source"
        extracted = root / "extracted"
        if extracted.is_dir():
            return extracted
        if root.is_dir():
            return root
    return settings.scan_source_dir(str(scan.id))
