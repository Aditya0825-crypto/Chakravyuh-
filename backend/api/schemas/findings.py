"""Schemas for Bug Finding findings, fuzzing results, and crashes."""

from __future__ import annotations

from typing import Any
from pydantic import BaseModel, Field


class SemgrepFindingItem(BaseModel):
    id: str
    rule: str
    file: str
    line: int
    severity: str
    message: str
    code: str = ""


class FuzzingResultsSchema(BaseModel):
    status: str = "complete"
    runtime: str = "0s"
    execsPerSec: int = 0
    totalExecs: int = 0
    crashesFound: int = 0
    uniqueCrashes: int = 0
    coverage: float = 0.0
    coverageGain: list[int] = Field(default_factory=list)
    targetReached: bool = False
    escalated: bool = False
    seeds: int = 0


class EvidenceItemSchema(BaseModel):
    evidence_type: str
    description: str
    raw_data: str
    verified: bool

class PatchCandidateRefSchema(BaseModel):
    agent: str
    name: str
    strategy: str
    status: str
    score_total: float
    attacks_blocked: int
    attacks_total: int

class VulnerabilityFindingSchema(BaseModel):
    finding_id: str
    scan_id: str
    cwe_id: str
    category: str
    severity: str
    confidence: int
    source: str
    file: str
    line: int
    function: str
    root_cause: str
    trigger: str
    verification_method: str
    verification_status: str
    evidence: list[EvidenceItemSchema] = Field(default_factory=list)
    patch_candidates: list[PatchCandidateRefSchema] = Field(default_factory=list)
    adversarial_results: dict[str, Any] = Field(default_factory=dict)
    regression_results: dict[str, Any] = Field(default_factory=dict)
    score_security: float
    score_regression: float
    score_performance: float
    score_rediscovery: float
    score_total: float
    final_status: str
    created_at: str
    asan_summary: str | None = None
    stack_trace: list[str] = Field(default_factory=list)

class FindingsResponse(BaseModel):
    scan_id: str
    fuzzing_results: FuzzingResultsSchema
    static_findings: list[SemgrepFindingItem] = Field(default_factory=list)
    findings: list[VulnerabilityFindingSchema] = Field(default_factory=list)
