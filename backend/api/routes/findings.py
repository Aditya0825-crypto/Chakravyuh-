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

    # 3. Findings (Replaces Crash)
    from db.models import PatchCandidate, VerifiedPoV
    from core.finding import VulnerabilityFinding, EvidenceItem, PatchRef

    crash_stmt = select(Crash).where(Crash.scan_id == scan_uuid).order_by(Crash.confidence.desc())
    crash_records = list(db.scalars(crash_stmt).all())

    # Get patches
    patch_stmt = select(PatchCandidate).where(PatchCandidate.scan_id == scan_uuid)
    all_patches = list(db.scalars(patch_stmt).all())

    # Get PoVs
    pov_stmt = select(VerifiedPoV).where(VerifiedPoV.scan_id == scan_uuid)
    all_povs = {pov.crash_id: pov for pov in db.scalars(pov_stmt).all()}

    finding_items = []
    for c in crash_records:
        f = VulnerabilityFinding.from_crash_record(c, scan_id)
        
        # Hydrate verification status
        if c.status == "verified":
            f.verification_status = "VERIFIED"
            f.confidence = c.confidence
            pov = all_povs.get(c.id)
            if pov and pov.sanitizer_report:
                f.add_evidence(EvidenceItem(
                    evidence_type="verification_report",
                    description="Evidence from verification stage",
                    raw_data=pov.sanitizer_report,
                    verified=True
                ))
        elif c.status == "partial":
            f.verification_status = "PARTIAL"
        elif c.status == "rejected":
            f.verification_status = "REJECTED"
            
        # Hydrate patch candidates
        # Currently patches are just linked to scan_id in the DB. In a real system, they'd link to the specific finding.
        # We will attach all patches for this CWE.
        cwe_patches = [p for p in all_patches if (hasattr(p, 'cwe_id') and getattr(p, 'cwe_id') == c.cwe) or p.status == 'SELECTED']
        if not cwe_patches and all_patches:
             # Fallback if no specific CWE mapping
             cwe_patches = all_patches
             
        for p in cwe_patches[:3]:  # Cap at 3 for UI
             f.patch_candidates.append(PatchRef(
                 agent=p.agent,
                 name=p.name,
                 strategy=p.strategy,
                 diff=p.diff,
                 score_total=p.score_total,
                 status=p.status,
                 attacks_blocked=p.attacks_blocked,
                 attacks_total=p.attacks_total
             ))
             if p.status == "SELECTED":
                 f.score_total = p.score_total
                 f.score_security = p.score_security
                 f.score_regression = p.score_regression
                 f.score_performance = p.score_performance
                 f.score_rediscovery = p.score_rediscovery

        f.set_gate_status()
        finding_items.append(f.to_api_dict())

    return FindingsResponse(
        scan_id=scan_id,
        fuzzing_results=fuzz_schema,
        static_findings=static_items,
        findings=finding_items,
    )
