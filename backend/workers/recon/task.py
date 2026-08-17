"""Celery task for Stage 1 Recon."""

from workers.celery_app import celery_app


@celery_app.task(name="chakravyuh.recon", bind=True, max_retries=0)
def task_recon(self, scan_id: str) -> dict:
    from pathlib import Path

    from core.config import get_settings
    from core.events import publish_scan_event
    from db.models import Scan, ScanStatus
    from db.session import SessionLocal
    from recon.engine import run_recon

    settings = get_settings()
    db = SessionLocal()
    try:
        scan = db.get(Scan, __import__("uuid").UUID(scan_id))
        if not scan:
            return {"scan_id": scan_id, "error": "scan not found"}

        scan.status = ScanStatus.STAGE_RECON
        scan.current_stage = "recon"
        db.commit()

        publish_scan_event(scan_id, "stage_started", stage="recon")

        source_dir = _resolve_source_dir(scan, settings)
        result = run_recon(scan_id, source_dir)

        publish_scan_event(
            scan_id,
            "stage_completed",
            stage="recon",
            duration_sec=round(result.duration_sec, 1),
            targets=len(result.targets),
            findings=result.findings_count,
        )
        return {
            "scan_id": scan_id,
            "targets": len(result.targets),
            "findings": result.findings_count,
            "duration_sec": result.duration_sec,
        }
    except Exception as exc:
        publish_scan_event(scan_id, "stage_failed", stage="recon", error=str(exc))
        raise
    finally:
        db.close()


def _resolve_source_dir(scan, settings) -> "Path":
    from pathlib import Path

    if scan.artifact_root:
        root = Path(scan.artifact_root) / "source"
        extracted = root / "extracted"
        if extracted.is_dir():
            return extracted
        if root.is_dir():
            return root
    return settings.scan_source_dir(str(scan.id))
