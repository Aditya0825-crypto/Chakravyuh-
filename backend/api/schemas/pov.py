"""PoV verification API schemas."""

from pydantic import BaseModel, Field


class PoVVerifyRequest(BaseModel):
    crashing_input: str = Field(..., description="Raw or escaped crash input")
    binary_path: str = Field(..., description="Path to ASan-instrumented binary on server")
    static_finding_match: bool = False


class VerifiedPoVOut(BaseModel):
    id: str
    status: str
    type: str
    cwe: str
    file: str
    line: int
    function: str
    severity: str
    signal: str
    returnCode: int
    confidence: int
    asanSummary: str
    stackTrace: list[str]
    reproduced: bool
    deduplicated: bool = False
    crashInput: str
    dedupHash: str
    sanitizerReport: str = ""


class PoVVerifyResponse(BaseModel):
    verified: bool
    pov: VerifiedPoVOut | None = None
    message: str | None = None
