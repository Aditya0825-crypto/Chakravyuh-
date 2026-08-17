"""Scan verified PoVs endpoint."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.schemas.pov import VerifiedPoVOut
from db.models import Crash, Scan, VerifiedPoV
from db.session import get_db

router = APIRouter(prefix="/scans", tags=["povs"])


@router.get("/{scan_id}/povs", response_model=list[VerifiedPoVOut])
def list_scan_povs(scan_id: UUID, db: Annotated[Session, Depends(get_db)]):
    """Return verified PoVs for a scan from database and artifact store."""
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # 1. Check database records
    stmt = (
        select(VerifiedPoV, Crash)
        .outerjoin(Crash, VerifiedPoV.crash_id == Crash.id)
        .where(VerifiedPoV.scan_id == scan_id)
    )
    results = db.execute(stmt).all()

    if results:
        out = []
        for pov, crash in results:
            out.append(
                VerifiedPoVOut(
                    id=f"pov-{str(pov.id)[:8]}",
                    status="verified",
                    type=crash.type if crash else "Memory Corruption",
                    cwe=pov.cwe,
                    file=crash.file if crash else "source.c",
                    line=crash.line if crash else 0,
                    function=crash.function if crash else "target",
                    severity=crash.severity if crash else "CRITICAL",
                    signal=crash.signal if crash else "SIGABRT",
                    returnCode=crash.return_code if crash else 134,
                    confidence=pov.confidence,
                    asanSummary=crash.asan_summary if crash else (pov.sanitizer_report or ""),
                    stackTrace=crash.stack_trace if (crash and crash.stack_trace) else [],
                    reproduced=pov.reproducible,
                    deduplicated=crash.deduplicated if crash else False,
                    crashInput=crash.crash_input if crash else "",
                    dedupHash=pov.dedup_hash or "",
                    sanitizerReport=pov.sanitizer_report or "",
                )
            )
        return out

    # 2. Fallback to filesystem
    from core.pov.storage import load_verified_povs

    file_povs = load_verified_povs(str(scan_id), scan.artifact_root)
    return [VerifiedPoVOut(**p.to_api_dict()) for p in file_povs]
