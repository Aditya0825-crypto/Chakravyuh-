"""Learning log API endpoint."""

from typing import Annotated
from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.schemas.report import LearningLogItem
from db.models import LearningLogEntry
from db.session import get_db

router = APIRouter(prefix="/learning-log", tags=["learning-log"])


@router.get("", response_model=list[LearningLogItem])
def get_learning_log(db: Annotated[Session, Depends(get_db)]):
    """Return historical scan entries and patch learnings from database."""
    stmt = select(LearningLogEntry).order_by(LearningLogEntry.created_at.desc())
    records = list(db.scalars(stmt).all())

    return [
        LearningLogItem(
            id=r.entry_id,
            date=r.date,
            target=r.target,
            cwe=r.cwe,
            crashType=r.crash_type,
            discoveryMethod=r.discovery_method,
            winningAgent=r.winning_agent,
            confidence=r.confidence,
            patchSuccess=r.patch_success,
            topCVE=r.top_cve,
            notes=r.notes,
        )
        for r in records
    ]
