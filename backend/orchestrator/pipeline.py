"""Pipeline Orchestrator — executes real Recon (1), Bug Finding (2), PoV Verifier (3), VulnDNA (4), and Patch Engine (5)."""

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


def _run_bug_finding_stage(db: Session, scan: Scan) -> None:
    from workers.bug_finding.orchestrator import run_bug_finding

    source_dir = _source_dir(scan)
    if not source_dir.is_dir():
        raise FileNotFoundError(f"Source directory not found: {source_dir}")

    _log_event(db, scan, "bugfinding", "Running multi-method discovery (Static + Directed PoC Generation + Fuzzing)")
    result = run_bug_finding(str(scan.id), source_dir)
    _log_event(
        db,
        scan,
        "bugfinding",
        f"Bug Finding complete — {len(result.crashes)} crash candidates found in {result.duration_sec:.1f}s",
    )


def _run_pov_verifier_stage(db: Session, scan: Scan) -> None:
    from workers.pov_verifier.task import run_pov_verifier

    source_dir = _source_dir(scan)
    _log_event(db, scan, "verification", "Replaying crashes in isolated ASan sandbox & deduplicating stack hashes")
    result = run_pov_verifier(str(scan.id), source_dir)
    _log_event(
        db,
        scan,
        "verification",
        f"PoV Verification complete — {result.verified_count} verified PoVs recorded",
    )


def _run_vulndna_stage(db: Session, scan: Scan) -> None:
    from workers.vulndna.task import run_vulndna_stage

    _log_event(db, scan, "vulndna", "Querying VulnDNA corpus for historical CVE precedents and fix patterns")
    result = run_vulndna_stage(str(scan.id))
    _log_event(
        db,
        scan,
        "vulndna",
        f"VulnDNA complete — {len(result.matches)} CVE precedent matches (Top: {result.top_cve})",
    )


def _run_patch_stage(db: Session, scan: Scan) -> None:
    from workers.patch_engine.task import run_patch_engine_stage

    source_dir = _source_dir(scan)
    _log_event(db, scan, "patchengine", "Synthesizing 3 candidate patches & running adversarial attack variant matrix")
    result = run_patch_engine_stage(str(scan.id), source_dir)
    winner_name = result.winner.name if result.winner else "None"
    winner_score = result.winner.score_total if result.winner else 0.0
    _log_event(
        db,
        scan,
        "patchengine",
        f"Patch Arena complete — Selected Winner: {winner_name} (Score: {winner_score:.1f}/100)",
    )


def _run_report_stage(db: Session, scan: Scan) -> None:
    from workers.report.task import run_report_stage

    _log_event(db, scan, "reportgate", "Assembling comprehensive security report and computing deterministic recommendation")
    result = run_report_stage(str(scan.id))
    _log_event(
        db,
        scan,
        "reportgate",
        f"Security Report complete [{result.report_id}] — Recommendation: {result.recommendation} (CVSS: {result.cvss_score})",
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
    """Run pipeline — real Recon, Bug Finding, PoV Verification, VulnDNA, Patch Arena, and Report Assembly."""
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
            elif stage_status == ScanStatus.STAGE_BUGFINDING:
                _run_bug_finding_stage(db, scan)
            elif stage_status == ScanStatus.STAGE_POV:
                _run_pov_verifier_stage(db, scan)
            elif stage_status == ScanStatus.STAGE_VULNDNA:
                _run_vulndna_stage(db, scan)
            elif stage_status == ScanStatus.STAGE_PATCH:
                _run_patch_stage(db, scan)
            elif stage_status == ScanStatus.STAGE_REPORT:
                _run_report_stage(db, scan)
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
