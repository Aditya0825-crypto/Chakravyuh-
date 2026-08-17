"""Verified PoV data model."""

from dataclasses import dataclass, field


@dataclass
class VerifiedPoV:
    id: str
    status: str
    type: str
    cwe: str
    file: str
    line: int
    function: str
    severity: str
    signal: str
    return_code: int
    confidence: int
    asan_summary: str
    stack_trace: list[str]
    reproduced: bool
    dedup_hash: str
    crash_input: str
    sanitizer_report: str = ""

    def to_api_dict(self) -> dict:
        return {
            "id": self.id,
            "status": self.status,
            "type": self.type,
            "cwe": self.cwe,
            "file": self.file,
            "line": self.line,
            "function": self.function,
            "severity": self.severity,
            "signal": self.signal,
            "returnCode": self.return_code,
            "confidence": self.confidence,
            "asanSummary": self.asan_summary,
            "stackTrace": self.stack_trace,
            "reproduced": self.reproduced,
            "deduplicated": False,
            "crashInput": self.crash_input,
            "dedupHash": self.dedup_hash,
            "sanitizerReport": self.sanitizer_report,
        }


@dataclass
class PoVVerifyOptions:
    static_finding_match: bool = False
    seen_hashes: set[str] = field(default_factory=set)
    timeout_sec: int = 30
    work_dir: str | None = None
