"""Scan verified PoVs endpoint."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from api.schemas.pov import VerifiedPoVOut
from db.models import Scan
from db.session import get_db

router = APIRouter(prefix="/scans", tags=["povs"])


@router.get("/{scan_id}/povs", response_model=list[VerifiedPoVOut])
def list_scan_povs(scan_id: UUID, db: Annotated[Session, Depends(get_db)]):
    """
    Return verified PoVs for a scan.

    Phase 1: reads persisted JSON from scan artifact dir when present;
    otherwise returns empty list until Stage 2 produces crashes.
    """
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    from core.pov.storage import load_verified_povs

    povs = load_verified_povs(str(scan_id), scan.artifact_root)
    return [VerifiedPoVOut(**p.to_api_dict()) for p in povs]
