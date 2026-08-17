"""API router for Security Report endpoint."""

import uuid
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.schemas.report import SecurityReportResponse
from db.models import Report, Scan
from db.session import get_db

router = APIRouter(prefix="/scans", tags=["report"])


@router.get("/{scan_id}/report", response_model=SecurityReportResponse)
def get_scan_report(scan_id: str, db: Session = Depends(get_db)):
    try:
        scan_uuid = uuid.UUID(scan_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid scan ID")

    scan = db.get(Scan, scan_uuid)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    stmt = select(Report).where(Report.scan_id == scan_uuid).order_by(Report.created_at.desc())
    report_rec = db.scalars(stmt).first()

    if not report_rec or not report_rec.report_json:
        raise HTTPException(status_code=404, detail="Security report not yet generated for this scan")

    return SecurityReportResponse(**report_rec.report_json)
