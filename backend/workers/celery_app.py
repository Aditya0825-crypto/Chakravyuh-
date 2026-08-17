"""Celery application instance."""

from celery import Celery

from core.config import get_settings

settings = get_settings()

celery_app = Celery(
    "chakravyuh",
    broker=settings.redis_url,
    backend=settings.redis_url,
    include=[
        "workers.pipeline.task",
        "workers.recon.task",
        "workers.bug_finding.task",
        "workers.pov_verifier.task",
        "workers.vulndna.task",
        "workers.patch_engine.task",
        "workers.report.task",
    ],
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    worker_prefetch_multiplier=1,
)
