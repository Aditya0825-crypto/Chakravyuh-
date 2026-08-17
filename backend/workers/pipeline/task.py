"""Celery task: run stub pipeline (Phase 0)."""

from workers.celery_app import celery_app


@celery_app.task(name="chakravyuh.run_pipeline", bind=True, max_retries=0)
def run_pipeline_task(self, scan_id: str) -> dict:
    from orchestrator.pipeline import run_pipeline

    run_pipeline(scan_id)
    return {"scan_id": scan_id, "status": "awaiting_gate"}
