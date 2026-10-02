"""VulnDNA data types."""

from dataclasses import dataclass, field


@dataclass
class CorpusEntry:
    cve_id: str
    cwe: str
    title: str
    project: str
    language: str
    function: str
    description: str
    vulnerable_code: str
    patch: str
    fix_pattern: str
    doc_id: str = ""

    def __post_init__(self) -> None:
        if not self.doc_id:
            self.doc_id = self.cve_id

    def embed_text(self) -> str:
        """Text blob stored and embedded in ChromaDB."""
        return (
            f"CVE: {self.cve_id}\n"
            f"CWE: {self.cwe}\n"
            f"Title: {self.title}\n"
            f"Project: {self.project}\n"
            f"Language: {self.language}\n"
            f"Function: {self.function}\n"
            f"Description: {self.description}\n"
            f"Vulnerable code:\n{self.vulnerable_code}\n"
            f"Fix pattern: {self.fix_pattern}"
        )


@dataclass
class VulnDNAQuery:
    crash_type: str
    cwe: str
    function: str | None = None
    file: str | None = None
    asan_summary: str | None = None
    stack_trace: list[str] = field(default_factory=list)
    # Extended fields for non-crash CWEs
    code_pattern: str | None = None      # e.g. "MD5", "strcpy", "system("
    root_cause: str | None = None
    trigger: str | None = None           # input/condition that triggers the vuln
    verification_method: str | None = None  # e.g. "static_ast", "asan_runtime"

    def query_text(self) -> str:
        lines = [
            f"Crash type: {self.crash_type}",
            f"CWE: {self.cwe}",
        ]
        if self.function:
            lines.append(f"Function: {self.function}")
        if self.file:
            lines.append(f"File: {self.file}")
        if self.code_pattern:
            lines.append(f"Code pattern: {self.code_pattern}")
        if self.root_cause:
            lines.append(f"Root cause: {self.root_cause[:200]}")
        if self.asan_summary:
            lines.append(f"Sanitizer: {self.asan_summary[:800]}")
        if self.stack_trace:
            lines.append("Stack trace: " + " | ".join(self.stack_trace[:8]))
        if self.verification_method:
            lines.append(f"Verification method: {self.verification_method}")
        return "\n".join(lines)


@dataclass
class EvidencePackage:
    cve_id: str
    similarity: float
    cwe: str
    title: str
    project: str
    language: str
    function: str
    vulnerable_code: str
    patch: str
    fix_pattern: str
    why_it_works: str = ""

    def to_api_dict(self) -> dict:
        return {
            "cveId": self.cve_id,
            "similarity": round(self.similarity, 1),
            "cwe": self.cwe,
            "title": self.title,
            "project": self.project,
            "language": self.language,
            "function": self.function,
            "vulnerableCode": self.vulnerable_code,
            "patch": self.patch,
            "fixPattern": self.fix_pattern,
            "whyItWorks": self.why_it_works or self.fix_pattern,
        }


# Alias for EvidencePackage
VulnDNAMatch = EvidencePackage

