"""Pydantic schemas for scan API responses."""

from datetime import datetime
from uuid import UUID

from typing import Literal

from pydantic import BaseModel


class ScanSummary(BaseModel):
    id: UUID
    target_name: str
    status: str
    current_stage: str | None
    started_at: datetime | None
    duration_sec: int
    file_count: int
    languages: list[str] | None = None

    model_config = {"from_attributes": True}


class ScanDetail(ScanSummary):
    artifact_root: str | None
    completed_at: datetime | None = None
    error_message: str | None = None


class ScanUploadResponse(BaseModel):
    id: UUID
    target_name: str
    status: str
    message: str = "Scan queued — pipeline started"


class PipelineEventOut(BaseModel):
    id: UUID
    stage: str | None
    level: str
    message: str
    timestamp: datetime

    model_config = {"from_attributes": True}


class HealthResponse(BaseModel):
    status: str = "ok"
    service: str = "chakravyuh-api"


class GateDecisionRequest(BaseModel):
    decision: Literal["APPROVED", "HOLD", "REJECTED"]
    notes: str = ""
