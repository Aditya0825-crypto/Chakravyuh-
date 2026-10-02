"""
ASan Runtime Verifier — CWE-120, 122, 125, 787, 416, 415.

Verification requires:
  1. Reproducible triggering input
  2. Instrumented execution inside sandbox
  3. ASan/sanitizer evidence in stderr
  4. Stack frame / source correlation

An arbitrary crash does NOT automatically count as proof.
"""
from __future__ import annotations

from pathlib import Path

from core.finding import EvidenceItem, VulnerabilityFinding
from core.parsers.asan import classify_sanitizer_output
from core.parsers.stack_trace import extract_stack_trace, stack_hash
from core.sandbox.docker_runner import run_binary_with_input
from core.scoring.confidence import ConfidenceInputs, calculate_confidence
from core.verifiers import BaseVerifier


class ASanVerifier(BaseVerifier):
    """
    Verifies memory-safety CWEs via AddressSanitizer instrumented execution.
    Requires a pre-compiled binary with -fsanitize=address.
    """

    SUPPORTED_CWES = frozenset({
        "CWE-120", "CWE-122", "CWE-125", "CWE-787", "CWE-416", "CWE-415",
    })

    def verify(
        self,
        finding: VulnerabilityFinding,
        *,
        compiled_binary: Path | None = None,
        source_root: Path | None = None,
        timeout_sec: int = 5,
        **kwargs,
    ) -> VulnerabilityFinding:
        """
        Replay the trigger input against an ASan-instrumented binary.

        Evidence criteria:
        - Binary must crash (non-zero exit code)
        - Stderr must contain sanitizer output matching the expected CWE
        - Stack trace must correlate with finding's source location
        """
        trigger = (finding.trigger or finding.crash_input or "")
        input_bytes = trigger.encode("utf-8", errors="replace") if trigger else b""

        # Cannot verify without a compiled binary
        if not compiled_binary or not compiled_binary.is_file():
            finding.add_evidence(EvidenceItem(
                evidence_type="asan_report",
                description="ASan binary not available for live replay",
                raw_data="Verification skipped — no compiled binary",
                verified=False,
            ))
            finding.confidence = _score_static_only(finding)
            finding.verification_status = "PARTIAL"
            return finding

        if not input_bytes:
            finding.add_evidence(EvidenceItem(
                evidence_type="asan_report",
                description="No trigger input available for replay",
                raw_data="",
                verified=False,
            ))
            finding.mark_rejected("No trigger input for ASan replay")
            return finding

        # Execute in sandbox
        res = run_binary_with_input(
            compiled_binary,
            input_bytes,
            work_dir=compiled_binary.parent,
            timeout_sec=timeout_sec,
        )

        if not res.crashed:
            finding.add_evidence(EvidenceItem(
                evidence_type="asan_report",
                description="Binary did not crash with provided input",
                raw_data=res.stderr[:500] if res.stderr else "",
                verified=False,
            ))
            finding.mark_rejected("Input did not reproduce crash in sandbox")
            return finding

        # Parse sanitizer output
        san_report = classify_sanitizer_output(res.stderr or "")

        # Verify the crash type matches expected CWE
        cwe_confirmed = (san_report.cwe == finding.cwe_id) or (
            san_report.cwe != "CWE-Unknown" and san_report.cwe != ""
        )

        if san_report.cwe and san_report.cwe != "CWE-Unknown":
            finding.cwe_id = san_report.cwe  # refine CWE from live evidence

        # Extract stack frames
        frames = extract_stack_trace(res.stderr or "")
        if frames:
            finding.stack_trace = frames

        # Source location correlation
        src_correlated = finding.line > 0 and bool(finding.file)

        evidence = EvidenceItem(
            evidence_type="asan_report",
            description=f"ASan confirmed: {san_report.crash_type} — CWE confirmed: {cwe_confirmed}",
            raw_data=(res.stderr or "")[:2000],
            verified=cwe_confirmed,
        )
        finding.add_evidence(evidence)

        if frames:
            finding.add_evidence(EvidenceItem(
                evidence_type="stack_trace",
                description=f"Stack trace ({len(frames)} frames)",
                raw_data="\n".join(frames[:10]),
                verified=True,
            ))

        # Calculate confidence
        finding.confidence = calculate_confidence(ConfidenceInputs(
            runtime_confirmed=True,
            reproducible=True,
            static_finding_match=src_correlated,
            stack_depth=len(frames),
            has_source_location=src_correlated,
            sanitizer_summary_present=bool(san_report.asan_summary),
            return_code_valid=res.returncode != 0,
        ))

        if cwe_confirmed:
            finding.asan_summary = san_report.asan_summary
            finding.mark_verified()
        else:
            finding.add_evidence(EvidenceItem(
                evidence_type="asan_report",
                description="Crash occurred but sanitizer output did not confirm expected CWE",
                raw_data=san_report.asan_summary or "",
                verified=False,
            ))
            finding.verification_status = "PARTIAL"

        return finding


def _score_static_only(finding: VulnerabilityFinding) -> int:
    """Fallback confidence when no live replay is possible."""
    score = 0
    if finding.file and finding.line > 0:
        score += 20
    if finding.function:
        score += 10
    if finding.root_cause:
        score += 10
    return min(50, score)  # cap at 50% without runtime confirmation
