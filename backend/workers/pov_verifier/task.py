"""Celery task for Stage 3 PoV Verifier."""

from workers.celery_app import celery_app


@celery_app.task(name="chakravyuh.pov_verifier", bind=True, max_retries=0)
def task_pov_verifier(self, scan_id: str) -> dict:
    """
    Replay candidate crashes and persist verified PoVs.

    Phase 1: stub — full wiring when Stage 2 produces crash artifacts.
    """
    return {"scan_id": scan_id, "verified_count": 0, "status": "stub"}
