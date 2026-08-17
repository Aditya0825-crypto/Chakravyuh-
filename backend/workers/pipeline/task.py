import sys
from pathlib import Path

backend_dir = Path(__file__).resolve().parent.parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from workers.celery_app import celery_app


@celery_app.task(name="chakravyuh.run_pipeline", bind=True, max_retries=0)
def run_pipeline_task(self, scan_id: str) -> dict:
    from orchestrator.pipeline import run_pipeline

    run_pipeline(scan_id)
    return {"scan_id": scan_id, "status": "awaiting_gate"}
