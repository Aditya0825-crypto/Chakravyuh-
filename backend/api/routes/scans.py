"""Scan REST endpoints."""

import shutil
import uuid
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from sqlalchemy.orm import Session

from api.schemas.scan import ScanDetail, ScanSummary, ScanUploadResponse
from core.config import get_settings
from core.ingest import ingest_upload
from db.models import Scan, ScanStatus
from db.session import get_db
from orchestrator.pipeline import enqueue_pipeline
from orchestrator.state_machine import frontend_scan_status, frontend_stage

router = APIRouter(prefix="/scans", tags=["scans"])


def _to_summary(scan: Scan) -> ScanSummary:
    return ScanSummary(
        id=scan.id,
        target_name=scan.target_name,
        status=frontend_scan_status(scan.status),
        current_stage=frontend_stage(scan.status, scan.current_stage),
        started_at=scan.started_at,
        duration_sec=scan.duration_sec,
        file_count=scan.file_count,
        languages=scan.languages,
    )


def _to_detail(scan: Scan) -> ScanDetail:
    base = _to_summary(scan)
    return ScanDetail(
        **base.model_dump(),
        artifact_root=scan.artifact_root,
        completed_at=scan.completed_at,
        error_message=scan.error_message,
    )


@router.post("/upload", response_model=ScanUploadResponse)
async def upload_scan(
    db: Annotated[Session, Depends(get_db)],
    files: Annotated[list[UploadFile], File(...)],
):
    if not files:
        raise HTTPException(status_code=400, detail="No files uploaded")

    settings = get_settings()
    scan_id = uuid.uuid4()
    scan_dir = settings.scan_dir(str(scan_id))

    try:
        file_count, languages, target_name = await ingest_upload(files, scan_dir)
    except ValueError as exc:
        _cleanup_artifacts(scan_dir)
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        _cleanup_artifacts(scan_dir)
        raise HTTPException(status_code=500, detail=f"Ingest failed: {exc}") from exc

    scan = Scan(
        id=scan_id,
        target_name=target_name,
        status=ScanStatus.QUEUED,
        current_stage="recon",
        artifact_root=str(scan_dir),
        languages=languages,
        file_count=file_count,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    enqueue_pipeline(str(scan.id))

    return ScanUploadResponse(
        id=scan.id,
        target_name=scan.target_name,
        status=frontend_scan_status(scan.status),
    )


def _cleanup_artifacts(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path, ignore_errors=True)


@router.get("", response_model=list[ScanSummary])
def list_scans(db: Annotated[Session, Depends(get_db)]):
    scans = db.query(Scan).order_by(Scan.created_at.desc()).all()
    return [_to_summary(s) for s in scans]


@router.get("/{scan_id}", response_model=ScanDetail)
def get_scan(scan_id: uuid.UUID, db: Annotated[Session, Depends(get_db)]):
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return _to_detail(scan)
