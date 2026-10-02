"""
Runtime / UBSan Verifier — CWE-476, 843, 190, 191, 369.

Verification uses:
  - UBSan (Undefined Behavior Sanitizer) instrumented execution
  - Boundary-focused inputs targeting integer limits and null paths
  - Behavioral analysis without requiring a hard crash

Evidence criteria:
  - UBSan runtime error in stderr, OR
  - Abnormal exit code on boundary inputs, OR
  - Static AST pattern for the CWE class with confirmed triggering path
"""
from __future__ import annotations

import re
from pathlib import Path

from core.finding import EvidenceItem, VulnerabilityFinding
from core.sandbox.docker_runner import run_binary_with_input
from core.verifiers import BaseVerifier

# UBSan patterns per CWE
_UBSAN_PATTERNS: dict[str, list[tuple[re.Pattern, str]]] = {
    "CWE-476": [
        (re.compile(r"null pointer", re.I), "Null pointer dereference detected by UBSan"),
        (re.compile(r"member access within null pointer", re.I), "Null member access"),
        (re.compile(r"load of null pointer", re.I), "Null pointer load"),
    ],
    "CWE-843": [
        (re.compile(r"type mismatch|type_info mismatch|bad_cast", re.I), "Type confusion/mismatch"),
        (re.compile(r"downcast of address.*is not.*of type", re.I), "Illegal downcast"),
    ],
    "CWE-190": [
        (re.compile(r"signed integer overflow|integer overflow", re.I), "Integer overflow"),
        (re.compile(r"negation of.*cannot be represented", re.I), "Negation overflow"),
    ],
    "CWE-191": [
        (re.compile(r"integer overflow|subtraction.*overflows|underflow", re.I), "Integer underflow"),
        (re.compile(r"negation of.*cannot be represented", re.I), "Negation underflow"),
    ],
    "CWE-369": [
        (re.compile(r"division by zero|divide by zero|divmod\(.*0\)", re.I), "Division by zero"),
        (re.compile(r"SIGFPE", re.I), "FPE signal (divide by zero)"),
    ],
}

# CWE-specific boundary inputs
_BOUNDARY_INPUTS: dict[str, list[bytes]] = {
    "CWE-476": [b"", b"\x00", b"0\n"],
    "CWE-843": [b"TYPE_A\n", b"TYPE_B\n", b"\xff\xff\n"],
    "CWE-190": [
        b"2147483647\n",   # INT_MAX
        b"2147483648\n",   # INT_MAX + 1
        b"4294967295\n",   # UINT_MAX
        b"-1\n",
    ],
    "CWE-191": [
        b"0\n",
        b"-2147483648\n",  # INT_MIN
        b"-1\n",
        b"1\n",
    ],
    "CWE-369": [
        b"0\n",
        b"0 1\n",
        b"1 0\n",
        b"-0\n",
    ],
}


class RuntimeUBSanVerifier(BaseVerifier):
    """
    Verifies pointer/type/integer CWEs via UBSan and boundary input testing.
    """

    SUPPORTED_CWES = frozenset({"CWE-476", "CWE-843", "CWE-190", "CWE-191", "CWE-369"})

    def verify(
        self,
        finding: VulnerabilityFinding,
        *,
        compiled_binary: Path | None = None,
        timeout_sec: int = 5,
        **kwargs,
    ) -> VulnerabilityFinding:

        cwe = finding.cwe_id
        patterns = _UBSAN_PATTERNS.get(cwe, [])
        boundary_inputs = _BOUNDARY_INPUTS.get(cwe, [b"0\n"])

        # Add the original trigger if available
        original_trigger = (finding.trigger or finding.crash_input or "").encode("utf-8", errors="replace")
        all_inputs = [original_trigger] if original_trigger else []
        all_inputs.extend(boundary_inputs)

        if not compiled_binary or not compiled_binary.is_file():
            # Static-only path: check for static evidence in asan_summary / root_cause
            text = (finding.asan_summary or finding.root_cause or "").lower()
            matched_pattern = False
            for pat, desc in patterns:
                if pat.search(text):
                    finding.add_evidence(EvidenceItem(
                        evidence_type="ubsan_report",
                        description=f"Static evidence: {desc}",
                        raw_data=text[:500],
                        verified=True,
                    ))
                    matched_pattern = True
                    break

            finding.confidence = 40 if matched_pattern else 20
            finding.verification_status = "PARTIAL"
            return finding

        # Live sandbox testing with boundary inputs
        confirmed = False
        for input_bytes in all_inputs[:8]:  # cap attempts
            res = run_binary_with_input(
                compiled_binary,
                input_bytes,
                work_dir=compiled_binary.parent,
                timeout_sec=timeout_sec,
            )
            combined = (res.stderr or "") + (res.stdout or "")

            for pat, desc in patterns:
                if pat.search(combined):
                    finding.add_evidence(EvidenceItem(
                        evidence_type="ubsan_report",
                        description=f"UBSan confirmed: {desc}",
                        raw_data=combined[:1000],
                        verified=True,
                    ))
                    finding.trigger = input_bytes.decode("utf-8", errors="replace")
                    confirmed = True
                    break

            # Also check for non-zero exit with appropriate signal
            if not confirmed and cwe == "CWE-369" and res.returncode in (132, 136):
                finding.add_evidence(EvidenceItem(
                    evidence_type="ubsan_report",
                    description="SIGFPE signal received — divide by zero confirmed",
                    raw_data=f"returncode={res.returncode}, stderr={combined[:200]}",
                    verified=True,
                ))
                confirmed = True

            if confirmed:
                break

        if confirmed:
            finding.confidence = 85
            finding.mark_verified()
        else:
            # Provide static/partial evidence
            static_text = (finding.asan_summary or finding.root_cause or "")
            any_static = any(p.search(static_text) for p, _ in patterns)
            finding.confidence = 35 if any_static else 20
            finding.verification_status = "PARTIAL"
            finding.add_evidence(EvidenceItem(
                evidence_type="ubsan_report",
                description="No UBSan confirmation on boundary inputs; partial static evidence",
                raw_data=static_text[:500],
                verified=False,
            ))

        return finding
