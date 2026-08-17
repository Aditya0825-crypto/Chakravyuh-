"""API router for patch candidates and winners."""

import uuid
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.schemas.patch import (
    AttacksSchema,
    PatchCandidateItem,
    PatchListResponse,
    PatchScoreSchema,
    RegressionTestsSchema,
)
from db.models import PatchCandidate, Scan
from db.session import get_db

router = APIRouter(prefix="/scans", tags=["patches"])


@router.get("/{scan_id}/patches", response_model=PatchListResponse)
def get_scan_patches(scan_id: str, db: Session = Depends(get_db)):
    try:
        scan_uuid = uuid.UUID(scan_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid scan ID")

    scan = db.get(Scan, scan_uuid)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    stmt = (
        select(PatchCandidate)
        .where(PatchCandidate.scan_id == scan_uuid)
        .order_by(PatchCandidate.score_total.desc())
    )
    records = list(db.scalars(stmt).all())

    items: list[PatchCandidateItem] = []
    winner_item: PatchCandidateItem | None = None

    for rec in records:
        item = PatchCandidateItem(
            id=f"patch-{str(rec.id)[:8]}",
            agent=rec.agent,
            name=rec.name,
            strategy=rec.strategy,
            score=PatchScoreSchema(
                security=rec.score_security,
                regression=rec.score_regression,
                performance=rec.score_performance,
                rediscovery=rec.score_rediscovery,
                total=rec.score_total,
            ),
            status=rec.status,
            rejectedReason=rec.rejected_reason,
            diff=rec.diff,
            linesChanged=rec.lines_changed,
            filesChanged=rec.files_changed,
            verificationPassed=rec.verification_passed,
            attacks=AttacksSchema(
                blocked=rec.attacks_blocked,
                total=rec.attacks_total,
            ),
            regressionTests=RegressionTestsSchema(
                passed=rec.regression_passed,
                total=rec.regression_total,
            ),
            performanceOverhead=rec.performance_overhead,
        )
        items.append(item)
        if rec.status == "SELECTED" and winner_item is None:
            winner_item = item

    return PatchListResponse(
        scan_id=scan_id,
        winner=winner_item,
        candidates=items,
    )
