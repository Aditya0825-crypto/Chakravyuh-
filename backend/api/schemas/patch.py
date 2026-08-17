"""Schemas for Patch Candidates and Patch Arena."""

from __future__ import annotations

from typing import Any
from pydantic import BaseModel, Field


class PatchScoreSchema(BaseModel):
    security: float = 0.0
    regression: float = 0.0
    performance: float = 0.0
    rediscovery: float = 0.0
    total: float = 0.0


class AttacksSchema(BaseModel):
    blocked: int = 0
    total: int = 9


class RegressionTestsSchema(BaseModel):
    passed: int = 0
    total: int = 0


class PatchCandidateItem(BaseModel):
    id: str
    agent: str
    name: str
    strategy: str
    score: PatchScoreSchema
    status: str
    rejectedReason: str | None = None
    diff: str
    linesChanged: int = 0
    filesChanged: int = 1
    verificationPassed: bool = False
    attacks: AttacksSchema
    regressionTests: RegressionTestsSchema
    performanceOverhead: str = "0.0%"


class PatchListResponse(BaseModel):
    scan_id: str
    winner: PatchCandidateItem | None = None
    candidates: list[PatchCandidateItem] = Field(default_factory=list)
