"""Schemas for Security Report, Human Gate, and Learning Log."""

from __future__ import annotations

from typing import Any
from pydantic import BaseModel, Field


class VulnerabilityReportItem(BaseModel):
    type: str
    cweId: str
    cweName: str
    location: str
    function: str
    severity: str
    cvssScore: float = 0.0


class VulnDNAMatchItem(BaseModel):
    cveId: str
    similarity: float


class HumanDecisionItem(BaseModel):
    decision: str
    decidedBy: str
    notes: str | None = None
    timestamp: str


class SecurityReportResponse(BaseModel):
    id: str
    timestamp: str
    target: str
    vulnerability: VulnerabilityReportItem
    rootCause: str
    selectedPatch: dict[str, Any] | None = None
    confidence: int = 0
    recommendation: str = "REVIEW"
    humanDecision: HumanDecisionItem | None = None
    vulnDNATopMatch: VulnDNAMatchItem | None = None
    numSimilarCVEs: int = 0


class GateDecisionRequest(BaseModel):
    decision: str = Field(..., description="APPROVED | HOLD | REJECTED")
    notes: str | None = None
    decided_by: str | None = "Security Lead (Human Gate)"


class GateDecisionResponse(BaseModel):
    scan_id: str
    decision: str
    decided_by: str
    notes: str | None = None
    status: str


class LearningLogItem(BaseModel):
    id: str
    date: str
    target: str
    cwe: str
    crashType: str
    discoveryMethod: str
    winningAgent: str
    confidence: int
    patchSuccess: bool
    topCVE: str | None = None
    notes: str
