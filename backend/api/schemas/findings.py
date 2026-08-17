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


class CrashItemSchema(BaseModel):
    id: str
    status: str = "verified"
    type: str
    cwe: str
    file: str
    line: int
    function: str
    severity: str = "CRITICAL"
    signal: str = "SIGABRT"
    returnCode: int = 134
    confidence: int = 90
    asanSummary: str = ""
    stackTrace: list[str] = Field(default_factory=list)
    reproduced: bool = True
    deduplicated: bool = False
    crashInput: str = ""
    discoveryMethod: str = "llm_directed"


class FindingsResponse(BaseModel):
    scan_id: str
    fuzzing_results: FuzzingResultsSchema
    static_findings: list[SemgrepFindingItem] = Field(default_factory=list)
    crashes: list[CrashItemSchema] = Field(default_factory=list)
