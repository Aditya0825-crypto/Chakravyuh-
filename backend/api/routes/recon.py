"""Recon stage REST endpoint."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from api.schemas.recon import ReconResponse, ReconTargetOut, StaticFindingOut
from db.models import ReconTarget, Scan, StaticFinding
from db.session import get_db

router = APIRouter(prefix="/scans", tags=["recon"])


@router.get("/{scan_id}/recon", response_model=ReconResponse)
def get_scan_recon(scan_id: UUID, db: Annotated[Session, Depends(get_db)]):
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    targets = (
        db.query(ReconTarget)
        .filter(ReconTarget.scan_id == scan_id)
        .order_by(ReconTarget.rank.asc())
        .all()
    )
    findings = (
        db.query(StaticFinding)
        .filter(StaticFinding.scan_id == scan_id)
        .order_by(StaticFinding.line.asc())
        .all()
    )

    return ReconResponse(
        targets=[
            ReconTargetOut(
                id=str(t.id),
                function=t.function,
                file=t.file,
                line=t.line,
                risk=t.risk,
                reason=t.reason,
                sinks=t.sinks or [],
                callPath=t.call_path or "",
                inputSources=t.input_sources or [],
                score=t.score,
            )
            for t in targets
        ],
        staticFindings=[
            StaticFindingOut(
                id=str(f.id),
                rule=f.rule,
                file=f.file,
                line=f.line,
                severity=f.severity,
                message=f.message,
                code=f.code_snippet or "",
            )
            for f in findings
        ],
        meta={
            "scanId": str(scan_id),
            "targetCount": len(targets),
            "findingCount": len(findings),
            "status": scan.status.value if hasattr(scan.status, "value") else str(scan.status),
        },
    )
