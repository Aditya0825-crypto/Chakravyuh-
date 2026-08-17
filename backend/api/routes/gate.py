"""Human gate endpoint — stub for Phase 6."""

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from api.schemas.scan import GateDecisionRequest
from db.models import Scan, ScanStatus
from db.session import get_db

router = APIRouter(prefix="/scans", tags=["gate"])


@router.post("/{scan_id}/gate")
def submit_gate_decision(
    scan_id: uuid.UUID,
    body: GateDecisionRequest,
    db: Annotated[Session, Depends(get_db)],
):
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    decision_map = {
        "APPROVED": ScanStatus.APPROVED,
        "HOLD": ScanStatus.HOLD,
        "REJECTED": ScanStatus.REJECTED,
    }
    scan.status = decision_map[body.decision]
    db.commit()
    return {"scan_id": str(scan_id), "decision": body.decision, "notes": body.notes}
