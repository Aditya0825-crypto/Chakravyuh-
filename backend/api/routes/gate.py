"""Human Safety Gate API endpoint."""

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from api.schemas.report import GateDecisionRequest, GateDecisionResponse
from db.models import Scan
from db.session import get_db
from workers.report.task import submit_gate_decision_handler

router = APIRouter(prefix="/scans", tags=["gate"])


@router.post("/{scan_id}/gate", response_model=GateDecisionResponse)
def submit_gate_decision(
    scan_id: uuid.UUID,
    body: GateDecisionRequest,
    db: Annotated[Session, Depends(get_db)],
):
    """
    Record human decision on patch deployment (APPROVED | HOLD | REJECTED).
    Never auto-deploys patches to production.
    """
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    decision_clean = body.decision.upper()
    if decision_clean not in {"APPROVED", "HOLD", "REJECTED"}:
        raise HTTPException(status_code=400, detail="Decision must be APPROVED, HOLD, or REJECTED")

    result = submit_gate_decision_handler(
        scan_id=scan_id,
        decision=decision_clean,
        notes=body.notes,
        decided_by=body.decided_by or "Security Lead (Human Gate)",
    )

    return GateDecisionResponse(**result)
