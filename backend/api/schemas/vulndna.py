"""VulnDNA API request/response schemas."""

from pydantic import BaseModel, Field


class VulnDNASearchRequest(BaseModel):
    crash_type: str = Field(..., examples=["heap-buffer-overflow"])
    cwe: str = Field(..., examples=["CWE-122"])
    function: str | None = None
    file: str | None = None
    asan_summary: str | None = None
    stack_trace: list[str] = Field(default_factory=list)
    n_results: int = Field(default=5, ge=1, le=20)
    min_similarity: float = Field(default=0.0, ge=0.0, le=100.0)


class VulnDNAMatch(BaseModel):
    cveId: str
    similarity: float
    cwe: str
    title: str
    project: str
    language: str
    function: str
    vulnerableCode: str
    patch: str
    fixPattern: str
    whyItWorks: str


class VulnDNASearchResponse(BaseModel):
    matches: list[VulnDNAMatch]
    query_ms: int
    corpus_size: int
    message: str | None = None


class VulnDNAStatusResponse(BaseModel):
    corpus_size: int
    collection: str
    chroma_path: str
    embed_model: str
