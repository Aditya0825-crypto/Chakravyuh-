"""Recon API schemas."""

from pydantic import BaseModel


class ReconTargetOut(BaseModel):
    id: str
    function: str
    file: str
    line: int
    risk: str
    reason: str
    sinks: list[str]
    callPath: str
    inputSources: list[str]
    score: int


class StaticFindingOut(BaseModel):
    id: str
    rule: str
    file: str
    line: int
    severity: str
    message: str
    code: str


class ReconResponse(BaseModel):
    targets: list[ReconTargetOut]
    staticFindings: list[StaticFindingOut]
    meta: dict
