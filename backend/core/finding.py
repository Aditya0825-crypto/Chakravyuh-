"""
Normalized VulnerabilityFinding — the canonical representation for any
vulnerability regardless of its CWE class.

Discovery ≠ Verification.
An LLM / static analyzer / fuzzer creates a CANDIDATE.
Only the appropriate verifier can mark it VERIFIED.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from core.cwe_registry import CWEDescriptor, get_cwe


# ---------------------------------------------------------------------------
# Evidence types (verification-method agnostic)
# ---------------------------------------------------------------------------

@dataclass
class EvidenceItem:
    """One piece of machine-verifiable evidence for a finding."""
    evidence_type: str        # "asan_report" | "ubsan_report" | "sandbox_marker" |
                              # "static_pattern" | "resource_measurement" | "tsan_report"
    description: str
    raw_data: str             # raw output / content
    verified: bool = False

    def to_dict(self) -> dict:
        return {
            "evidence_type": self.evidence_type,
            "description": self.description,
            "raw_data": self.raw_data[:2000],  # truncate for storage
            "verified": self.verified,
        }


# ---------------------------------------------------------------------------
# Patch candidate reference (linked from finding)
# ---------------------------------------------------------------------------

@dataclass
class PatchRef:
    agent: str
    name: str
    strategy: str
    diff: str
    score_total: float
    status: str   # SELECTED | REJECTED | FAILED
    attacks_blocked: int = 0
    attacks_total: int = 0


# ---------------------------------------------------------------------------
# Core normalized finding
# ---------------------------------------------------------------------------

@dataclass
class VulnerabilityFinding:
    """
    Normalized representation of a C/C++ vulnerability.

    Fields align with the required schema:
    finding_id, cwe_id, category, severity, confidence, source,
    file, line, function, root_cause, trigger, verification_method,
    verification_status, evidence, patch_candidates, adversarial_results,
    regression_results, final_status
    """
    # Identity
    finding_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    scan_id: str = ""

    # Classification
    cwe_id: str = "CWE-Unknown"
    category: str = ""          # memory | pointer_type | integer | input_injection | concurrency | crypto_secrets | resource
    severity: str = "HIGH"      # CRITICAL | HIGH | MEDIUM | LOW
    confidence: int = 0         # 0–100

    # Location
    source: str = "static"      # static | fuzzer | llm | semgrep | manual
    file: str = ""
    line: int = 0
    function: str = ""

    # Vulnerability details
    root_cause: str = ""
    trigger: str = ""           # the input / condition that triggers the vuln

    # Verification
    verification_method: str = ""   # from CWEDescriptor.verification_method
    verification_status: str = "CANDIDATE"  # CANDIDATE | VERIFIED | REJECTED | PARTIAL

    # Evidence (structured)
    evidence: list[EvidenceItem] = field(default_factory=list)

    # Patch arena results
    patch_candidates: list[PatchRef] = field(default_factory=list)

    # Adversarial testing results
    adversarial_results: dict[str, Any] = field(default_factory=dict)
    # e.g. {"tests_run": 9, "blocked": 8, "variants": [...]}

    # Regression results
    regression_results: dict[str, Any] = field(default_factory=dict)
    # e.g. {"passed": 10, "total": 10, "build_ok": True}

    # Scoring (explicit formula)
    score_security: float = 0.0
    score_regression: float = 0.0
    score_performance: float = 0.0
    score_rediscovery: float = 0.0
    score_total: float = 0.0

    # Gate status
    final_status: str = "REVIEW"   # SAFE | REVIEW | HOLD

    # Metadata
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    # Optional legacy fields (only populated for ASan-class vulnerabilities)
    asan_summary: str | None = None
    stack_trace: list[str] = field(default_factory=list)
    signal: str | None = None
    return_code: int | None = None
    crash_input: str | None = None

    # -------------------------------------------------------------------------

    @classmethod
    def from_crash_record(cls, crash, scan_id: str) -> "VulnerabilityFinding":
        """Build a VulnerabilityFinding from an existing Crash DB record."""
        desc: CWEDescriptor | None = get_cwe(crash.cwe)
        return cls(
            scan_id=scan_id,
            cwe_id=crash.cwe,
            category=desc.category if desc else "memory",
            severity=crash.severity or "HIGH",
            confidence=crash.confidence or 0,
            source=crash.discovery_method or "static",
            file=crash.file or "",
            line=crash.line or 0,
            function=crash.function or "",
            root_cause=crash.type or "",
            trigger=crash.crash_input or "",
            verification_method=desc.verification_method if desc else "asan_runtime",
            verification_status="CANDIDATE",
            asan_summary=crash.asan_summary,
            stack_trace=crash.stack_trace or [],
            signal=crash.signal,
            return_code=crash.return_code,
            crash_input=crash.crash_input,
        )

    def add_evidence(self, item: EvidenceItem) -> None:
        self.evidence.append(item)

    def mark_verified(self) -> None:
        self.verification_status = "VERIFIED"

    def mark_rejected(self, reason: str = "") -> None:
        self.verification_status = "REJECTED"
        if reason and not self.root_cause:
            self.root_cause = reason

    def compute_score(self) -> float:
        """
        Score = Security × 0.50 + Regression × 0.25 + Performance × 0.15 + Rediscovery × 0.10

        All components are 0–100. Returns the composite total.
        """
        self.score_total = round(
            self.score_security * 0.50
            + self.score_regression * 0.25
            + self.score_performance * 0.15
            + self.score_rediscovery * 0.10,
            2,
        )
        return self.score_total

    def set_gate_status(self) -> str:
        """
        Derive SAFE / REVIEW / HOLD based on score and verification status.
        Human approval always required — no automatic merge.
        """
        if self.verification_status == "VERIFIED" and self.score_total >= 80:
            self.final_status = "SAFE"
        elif self.score_total < 50 or self.verification_status == "REJECTED":
            self.final_status = "HOLD"
        else:
            self.final_status = "REVIEW"
        return self.final_status

    def to_api_dict(self) -> dict:
        """Serialize to API-facing dictionary (no sensitive raw data in bulk output)."""
        masked_trigger = self._mask_sensitive(self.trigger or "")
        return {
            "finding_id": self.finding_id,
            "scan_id": self.scan_id,
            "cwe_id": self.cwe_id,
            "category": self.category,
            "severity": self.severity,
            "confidence": self.confidence,
            "source": self.source,
            "file": self.file,
            "line": self.line,
            "function": self.function,
            "root_cause": self.root_cause,
            "trigger": masked_trigger,
            "verification_method": self.verification_method,
            "verification_status": self.verification_status,
            "evidence": [e.to_dict() for e in self.evidence],
            "patch_candidates": [
                {
                    "agent": p.agent,
                    "name": p.name,
                    "strategy": p.strategy,
                    "status": p.status,
                    "score_total": p.score_total,
                    "attacks_blocked": p.attacks_blocked,
                    "attacks_total": p.attacks_total,
                }
                for p in self.patch_candidates
            ],
            "adversarial_results": self.adversarial_results,
            "regression_results": self.regression_results,
            "score_security": self.score_security,
            "score_regression": self.score_regression,
            "score_performance": self.score_performance,
            "score_rediscovery": self.score_rediscovery,
            "score_total": self.score_total,
            "final_status": self.final_status,
            "created_at": self.created_at,
            # ASan-specific (may be None for non-crash CWEs)
            "asan_summary": self.asan_summary,
            "stack_trace": self.stack_trace,
        }

    @staticmethod
    def _mask_sensitive(value: str) -> str:
        """Mask obvious secret patterns in trigger/evidence strings for report output."""
        import re
        # mask anything that looks like a credential/key value after = or :
        value = re.sub(
            r'(?i)(password|passwd|secret|api_?key|token|credential)\s*[=:]\s*\S+',
            r'\1=***MASKED***',
            value,
        )
        return value
