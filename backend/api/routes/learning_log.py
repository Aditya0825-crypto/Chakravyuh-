"""Learning log endpoint — stub for Phase 6."""

from fastapi import APIRouter

router = APIRouter(prefix="/learning-log", tags=["learning-log"])


@router.get("")
def get_learning_log():
    return []
