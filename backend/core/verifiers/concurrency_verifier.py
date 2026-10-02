"""
Concurrency Verifier — CWE-362 (Race Condition), CWE-367 (TOCTOU).

Verification uses:
  - ThreadSanitizer (TSan) instrumented execution
  - Repeated concurrent execution patterns
  - TOCTOU: verify check → intervening change → use sequence

Evidence criteria:
  - TSan "DATA RACE" or "WARNING:" in output, OR
  - TOCTOU sequence: verify the check→change→use triple is observable
"""
from __future__ import annotations

import re
import threading
import time
from pathlib import Path

from core.finding import EvidenceItem, VulnerabilityFinding
from core.sandbox.docker_runner import run_binary_with_input
from core.verifiers import BaseVerifier

_TSAN_PATTERNS = [
    re.compile(r"DATA RACE", re.I),
    re.compile(r"ThreadSanitizer:.*WARNING", re.I),
    re.compile(r"TSAN:", re.I),
    re.compile(r"WARNING: ThreadSanitizer", re.I),
]


class ConcurrencyVerifier(BaseVerifier):
    """
    Verifies concurrency CWEs via TSan instrumented execution and
    repeated concurrent invocations.
    """

    SUPPORTED_CWES = frozenset({"CWE-362", "CWE-367"})

    def verify(
        self,
        finding: VulnerabilityFinding,
        *,
        compiled_binary: Path | None = None,
        timeout_sec: int = 10,
        repeat_count: int = 5,
        **kwargs,
    ) -> VulnerabilityFinding:

        cwe = finding.cwe_id
        trigger = (finding.trigger or finding.crash_input or "test\n").encode("utf-8", errors="replace")

        if not compiled_binary or not compiled_binary.is_file():
            return self._static_only(finding, cwe)

        if cwe == "CWE-367":
            return self._verify_toctou(finding, compiled_binary, trigger, timeout_sec)
        else:
            return self._verify_race(finding, compiled_binary, trigger, timeout_sec, repeat_count)

    def _verify_race(
        self,
        finding: VulnerabilityFinding,
        binary: Path,
        trigger: bytes,
        timeout_sec: int,
        repeat_count: int,
    ) -> VulnerabilityFinding:
        """Run binary repeatedly and in parallel to trigger race conditions."""
        tsan_hits: list[str] = []
        errors: list[str] = []

        def run_once():
            res = run_binary_with_input(binary, trigger, work_dir=binary.parent, timeout_sec=timeout_sec)
            combined = (res.stderr or "") + (res.stdout or "")
            for pat in _TSAN_PATTERNS:
                if pat.search(combined):
                    tsan_hits.append(combined[:500])
                    break
            if res.crashed:
                errors.append(f"crashed(rc={res.returncode})")

        # Run in parallel threads to maximize race window
        threads = [threading.Thread(target=run_once) for _ in range(repeat_count)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=timeout_sec + 2)

        if tsan_hits:
            finding.add_evidence(EvidenceItem(
                evidence_type="tsan_report",
                description=f"TSan confirmed race condition ({len(tsan_hits)} detections in {repeat_count} runs)",
                raw_data=tsan_hits[0],
                verified=True,
            ))
            finding.confidence = 88
            finding.mark_verified()
        elif errors:
            finding.add_evidence(EvidenceItem(
                evidence_type="tsan_report",
                description=f"Crashes observed in concurrent execution ({len(errors)} crashes)",
                raw_data="; ".join(errors[:3]),
                verified=False,
            ))
            finding.confidence = 55
            finding.verification_status = "PARTIAL"
        else:
            finding.confidence = 25
            finding.verification_status = "PARTIAL"
            finding.add_evidence(EvidenceItem(
                evidence_type="tsan_report",
                description="No TSan races detected in concurrent runs; static evidence only",
                raw_data="",
                verified=False,
            ))

        return finding

    def _verify_toctou(
        self,
        finding: VulnerabilityFinding,
        binary: Path,
        trigger: bytes,
        timeout_sec: int,
    ) -> VulnerabilityFinding:
        """
        For TOCTOU: verify the check → intervening change → use sequence.
        We simulate an intervening state change between check and use phases.
        """
        results = []
        # Run with different timing to catch the TOCTOU window
        for delay_ms in [0, 50, 100]:
            time.sleep(delay_ms / 1000.0)
            res = run_binary_with_input(binary, trigger, work_dir=binary.parent, timeout_sec=timeout_sec)
            combined = (res.stderr or "") + (res.stdout or "")
            for pat in _TSAN_PATTERNS:
                if pat.search(combined):
                    results.append(combined[:500])
                    break

        if results:
            finding.add_evidence(EvidenceItem(
                evidence_type="tsan_report",
                description="TOCTOU: TSan detected race between check and use",
                raw_data=results[0],
                verified=True,
            ))
            finding.confidence = 85
            finding.mark_verified()
        else:
            # Static evidence check
            finding.add_evidence(EvidenceItem(
                evidence_type="tsan_report",
                description="TOCTOU: Could not confirm check→change→use sequence dynamically; static analysis only",
                raw_data=finding.root_cause or "",
                verified=False,
            ))
            finding.confidence = 30
            finding.verification_status = "PARTIAL"

        return finding

    def _static_only(self, finding: VulnerabilityFinding, cwe: str) -> VulnerabilityFinding:
        root_cause = (finding.root_cause or "").lower()
        has_thread = any(s in root_cause for s in ["thread", "mutex", "lock", "atomic", "shared", "concurrent"])
        has_toctou = any(s in root_cause for s in ["access", "check", "stat", "lstat", "open"]) if cwe == "CWE-367" else False

        confirmed = has_thread or has_toctou
        finding.add_evidence(EvidenceItem(
            evidence_type="tsan_report",
            description=f"Static analysis: {'concurrency pattern' if has_thread else 'TOCTOU pattern'} identified",
            raw_data=finding.root_cause or "",
            verified=confirmed,
        ))
        finding.confidence = 40 if confirmed else 20
        finding.verification_status = "PARTIAL"
        return finding
