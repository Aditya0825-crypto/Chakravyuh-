"""API router for findings, fuzz results, and crashes."""

import uuid
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.schemas.findings import CrashItemSchema, FindingsResponse, FuzzingResultsSchema, SemgrepFindingItem
from db.models import Crash, FuzzRun, Scan, StaticFinding
from db.session import get_db

router = APIRouter(prefix="/scans", tags=["findings"])


@router.get("/{scan_id}/findings", response_model=FindingsResponse)
def get_scan_findings(scan_id: str, db: Session = Depends(get_db)):
    try:
        scan_uuid = uuid.UUID(scan_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid scan ID")

    scan = db.get(Scan, scan_uuid)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # 1. Static findings
    static_stmt = select(StaticFinding).where(StaticFinding.scan_id == scan_uuid)
    static_records = list(db.scalars(static_stmt).all())
    static_items = [
        SemgrepFindingItem(
            id=f"sg-{str(f.id)[:8]}",
            rule=f.rule,
            file=f.file,
            line=f.line,
            severity=f.severity,
            message=f.message,
            code=f.code_snippet or "",
        )
        for f in static_records
    ]

    # 2. Fuzzing results
    fuzz_stmt = select(FuzzRun).where(FuzzRun.scan_id == scan_uuid).order_by(FuzzRun.created_at.desc())
    fuzz_run = db.scalars(fuzz_stmt).first()

    fuzz_schema = FuzzingResultsSchema(
        status=fuzz_run.status if fuzz_run else "complete",
        runtime=f"{fuzz_run.runtime_sec}s" if fuzz_run else "0s",
        execsPerSec=fuzz_run.execs_per_sec if fuzz_run else 0,
        totalExecs=fuzz_run.total_execs if fuzz_run else 0,
        crashesFound=fuzz_run.crashes_found if fuzz_run else 0,
        uniqueCrashes=fuzz_run.unique_crashes if fuzz_run else 0,
        coverage=float(fuzz_run.coverage_pct) if fuzz_run else 0.0,
        coverageGain=fuzz_run.coverage_gain or [] if fuzz_run else [],
        targetReached=fuzz_run.target_reached if fuzz_run else False,
        escalated=fuzz_run.escalated if fuzz_run else False,
        seeds=fuzz_run.seeds_count if fuzz_run else 0,
    )

    # 3. Crashes
    crash_stmt = select(Crash).where(Crash.scan_id == scan_uuid).order_by(Crash.confidence.desc())
    crash_records = list(db.scalars(crash_stmt).all())
    crash_items = [
        CrashItemSchema(
            id=f"crash-{str(c.id)[:8]}",
            status=c.status,
            type=c.type,
            cwe=c.cwe,
            file=c.file,
            line=c.line,
            function=c.function,
            severity=c.severity,
            signal=c.signal,
            returnCode=c.return_code,
            confidence=c.confidence,
            asanSummary=c.asan_summary or "",
            stackTrace=c.stack_trace or [],
            reproduced=c.reproduced,
            deduplicated=c.deduplicated,
            crashInput=c.crash_input or "",
            discoveryMethod=c.discovery_method,
        )
        for c in crash_records
    ]

    return FindingsResponse(
        scan_id=scan_id,
        fuzzing_results=fuzz_schema,
        static_findings=static_items,
        crashes=crash_items,
    )
