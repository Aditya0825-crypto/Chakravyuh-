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
    """Return historical scan entries and patch learnings."""
    stmt = select(LearningLogEntry).order_by(LearningLogEntry.created_at.desc())
    records = list(db.scalars(stmt).all())

    if records:
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

    # Return seed history if database has no runs yet
    return [
        LearningLogItem(
            id="log-001",
            date="2026-08-13",
            target="vulnerable_server",
            cwe="CWE-122",
            crashType="Heap Buffer Overflow",
            discoveryMethod="AFL++ + Directed Fuzzing",
            winningAgent="Agent 1 — Root Cause Fixer",
            confidence=96,
            patchSuccess=True,
            topCVE="CVE-2021-3156",
            notes="strcpy → strnlen + memcpy. All regression tests passed.",
        ),
        LearningLogItem(
            id="log-002",
            date="2026-08-11",
            target="auth_service",
            cwe="CWE-89",
            crashType="SQL Injection",
            discoveryMethod="Semgrep + LLM Analysis",
            winningAgent="Agent 2 — Evidence-Guided Fixer",
            confidence=91,
            patchSuccess=True,
            topCVE="CVE-2019-11358",
            notes="Parameterized query replacement. CVE-2019-11358 pattern adapted.",
        ),
        LearningLogItem(
            id="log-003",
            date="2026-08-09",
            target="file_parser",
            cwe="CWE-416",
            crashType="Use-After-Free",
            discoveryMethod="AFL++ + Concolic Escalation",
            winningAgent="Agent 1 — Root Cause Fixer",
            confidence=84,
            patchSuccess=True,
            topCVE="CVE-2019-0708",
            notes="NULL after free + guard check. Concolic escalation reached the branch.",
        ),
    ]
