"""Celery task & runner for Stage 4 VulnDNA Evidence Retrieval."""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy import select

from core.config import get_settings
from core.events import publish_scan_event
from db.models import Crash, PipelineEvent, PipelineEventLevel, Scan, ScanStatus, VerifiedPoV
from db.session import SessionLocal
from vulndna.models import VulnDNAMatch, VulnDNAQuery
from vulndna.query import search_vulndna
from workers.celery_app import celery_app


@dataclass
class VulnDNAResult:
    scan_id: str
    matches: list[VulnDNAMatch]
    top_cve: str | None
    corpus_size: int
    duration_sec: float


def run_vulndna_stage(scan_id: str) -> VulnDNAResult:
    """
    Execute Stage 4 VulnDNA Evidence Retrieval:
    1. Fetch all VerifiedPoVs for the scan.
    2. Query ChromaDB corpus (with embedded seed fallback).
    3. Return top CVE matches and fix patterns.
    4. Emit WebSocket events.
    """
    start_time = time.perf_counter()
    scan_uuid = uuid.UUID(scan_id)
    db = SessionLocal()

    try:
        scan = db.get(Scan, scan_uuid)
        if not scan:
            raise ValueError(f"Scan {scan_id} not found")

        _log(db, scan, "Fingerprinting verified PoVs and querying VulnDNA CVE precedent corpus...")

        # 1. Fetch verified PoVs and their crashes
        stmt = (
            select(VerifiedPoV, Crash)
            .outerjoin(Crash, VerifiedPoV.crash_id == Crash.id)
            .where(VerifiedPoV.scan_id == scan_uuid)
        )
        pov_records = db.execute(stmt).all()

        all_matches: list[VulnDNAMatch] = []
        corpus_sz = 0

        if pov_records:
            for pov, crash in pov_records:
                q = VulnDNAQuery(
                    crash_type=crash.type if crash else "Heap Buffer Overflow",
                    cwe=pov.cwe,
                    function=crash.function if crash else "handle_request",
                    file=crash.file if crash else "server.c",
                    asan_summary=crash.asan_summary if crash else (pov.sanitizer_report or ""),
                    stack_trace=crash.stack_trace if crash else [],
                )
                matches, meta = search_vulndna(q, n_results=5)
                corpus_sz = max(corpus_sz, meta.get("corpus_size", 0))
                for m in matches:
                    if not any(existing.cve_id == m.cve_id for existing in all_matches):
                        all_matches.append(m)
        else:
            # Fallback query if no PoVs produced
            q = VulnDNAQuery(
                crash_type="heap-buffer-overflow",
                cwe="CWE-122",
                function="handle_request",
                file="server.c",
                asan_summary="heap-buffer-overflow strcpy write",
            )
            all_matches, meta = search_vulndna(q, n_results=5)
            corpus_sz = meta.get("corpus_size", 0)

        # Sort matches by similarity
        all_matches.sort(key=lambda m: m.similarity, reverse=True)
        top_cve = all_matches[0].cve_id if all_matches else None
        top_sim = all_matches[0].similarity if all_matches else 0.0

        duration = time.perf_counter() - start_time
        _log(
            db,
            scan,
            f"VulnDNA search complete — {len(all_matches)} precedent matches identified (Top match: {top_cve} [{top_sim:.1f}% similarity])",
        )

        return VulnDNAResult(
            scan_id=scan_id,
            matches=all_matches,
            top_cve=top_cve,
            corpus_size=corpus_sz,
            duration_sec=duration,
        )

    except Exception as exc:
        db.rollback()
        raise
    finally:
        db.close()


@celery_app.task(name="chakravyuh.vulndna", bind=True, max_retries=0)
def task_vulndna(self, scan_id: str) -> dict:
    from core.events import publish_scan_event
    from db.models import Scan, ScanStatus
    from db.session import SessionLocal

    db = SessionLocal()
    try:
        scan = db.get(Scan, uuid.UUID(scan_id))
        if not scan:
            return {"scan_id": scan_id, "error": "scan not found"}

        scan.status = ScanStatus.STAGE_VULNDNA
        scan.current_stage = "vulndna"
        db.commit()

        publish_scan_event(scan_id, "stage_started", stage="vulndna")

        res = run_vulndna_stage(scan_id)

        publish_scan_event(
            scan_id,
            "stage_completed",
            stage="vulndna",
            duration_sec=round(res.duration_sec, 1),
            matches_found=len(res.matches),
            top_cve=res.top_cve,
        )

        return {
            "scan_id": scan_id,
            "match_count": len(res.matches),
            "top_cve": res.top_cve,
            "corpus_size": res.corpus_size,
            "duration_sec": res.duration_sec,
        }
    except Exception as exc:
        publish_scan_event(scan_id, "stage_failed", stage="vulndna", error=str(exc))
        raise
    finally:
        db.close()


def _log(
    db: SessionLocal,
    scan: Scan,
    message: str,
    level: PipelineEventLevel = PipelineEventLevel.INFO,
) -> None:
    event = PipelineEvent(
        scan_id=scan.id,
        stage="vulndna",
        level=level,
        message=message,
    )
    db.add(event)
    db.commit()
    publish_scan_event(
        str(scan.id),
        "log",
        stage="vulndna",
        level=level.value,
        message=message,
    )
