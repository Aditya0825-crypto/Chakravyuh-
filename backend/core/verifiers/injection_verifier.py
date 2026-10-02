"""
Injection / Sandbox Behavioral Verifier — CWE-20, 134, 78, 22.

Verification policy:
- CWE-78: Prove controlled attacker input reaches command execution using ONLY
  harmless sandbox marker sentinels. Never execute destructive commands.
- CWE-22: Use a synthetic sandbox filesystem. Prove traversal escapes
  the intended directory. Never access real host filesystem.
- CWE-134: Detect format string specifiers in output/behavior.
- CWE-20: Detect improper handling of boundary/malformed inputs.

Evidence types:
- "sandbox_marker" — controlled marker found in command/file output
- "format_string_evidence" — %x/%n behavior observed
- "path_traversal_evidence" — path escapes sandbox root
- "input_validation_evidence" — missing boundary/type check
"""
from __future__ import annotations

import os
import re
import tempfile
from pathlib import Path

from core.finding import EvidenceItem, VulnerabilityFinding
from core.sandbox.docker_runner import run_binary_with_input
from core.verifiers import BaseVerifier

# Harmless marker for CWE-78 proof-of-concept (never destructive)
_CMD_INJECTION_MARKER = "CHAKRAVYUH_MARKER_SAFE_7a3f"

# Format string patterns
_FMT_PATTERNS = [
    re.compile(r"%[0-9]*x", re.I),      # %x hex leak
    re.compile(r"0x[0-9a-f]{4,}", re.I),  # hex address in output
    re.compile(r"Segmentation fault", re.I),
    re.compile(r"\(null\)", re.I),
]


class InjectionSandboxVerifier(BaseVerifier):
    """
    Verifies input/injection CWEs through sandbox behavioral analysis.
    All test commands are strictly harmless.
    """

    SUPPORTED_CWES = frozenset({"CWE-20", "CWE-134", "CWE-78", "CWE-22"})

    def verify(
        self,
        finding: VulnerabilityFinding,
        *,
        compiled_binary: Path | None = None,
        timeout_sec: int = 5,
        **kwargs,
    ) -> VulnerabilityFinding:

        cwe = finding.cwe_id

        if cwe == "CWE-78":
            return self._verify_cmd_injection(finding, compiled_binary, timeout_sec)
        elif cwe == "CWE-22":
            return self._verify_path_traversal(finding, compiled_binary, timeout_sec)
        elif cwe == "CWE-134":
            return self._verify_format_string(finding, compiled_binary, timeout_sec)
        else:  # CWE-20
            return self._verify_input_validation(finding, compiled_binary, timeout_sec)

    # -------------------------------------------------------------------------
    # CWE-78: OS Command Injection
    # -------------------------------------------------------------------------

    def _verify_cmd_injection(
        self,
        finding: VulnerabilityFinding,
        binary: Path | None,
        timeout_sec: int,
    ) -> VulnerabilityFinding:
        """
        Prove attacker-controlled input reaches command execution using a
        harmless marker echo command. Never execute destructive commands.
        """
        # Harmless injection payloads — all they do is echo a marker
        injection_probes = [
            f"; echo {_CMD_INJECTION_MARKER}".encode(),
            f"| echo {_CMD_INJECTION_MARKER}".encode(),
            f"`echo {_CMD_INJECTION_MARKER}`".encode(),
            f"$(echo {_CMD_INJECTION_MARKER})".encode(),
            f"& echo {_CMD_INJECTION_MARKER}".encode(),
        ]

        if not binary or not binary.is_file():
            # Static-only verification using code pattern evidence
            root_cause_text = (finding.root_cause or "").lower()
            has_system_call = any(
                s in root_cause_text
                for s in ["system(", "popen(", "exec(", "execv", "shell=true"]
            )
            confirmed = has_system_call or "command injection" in root_cause_text
            finding.add_evidence(EvidenceItem(
                evidence_type="sandbox_marker",
                description="Static pattern: unvalidated input reaches OS command API",
                raw_data=finding.root_cause or "",
                verified=confirmed,
            ))
            finding.confidence = 60 if confirmed else 30
            finding.verification_status = "PARTIAL"
            return finding

        confirmed = False
        for probe in injection_probes:
            res = run_binary_with_input(binary, probe, work_dir=binary.parent, timeout_sec=timeout_sec)
            combined_output = (res.stdout or "") + (res.stderr or "")
            if _CMD_INJECTION_MARKER in combined_output:
                finding.add_evidence(EvidenceItem(
                    evidence_type="sandbox_marker",
                    description=(
                        f"CONFIRMED: Marker '{_CMD_INJECTION_MARKER}' appeared in command output. "
                        f"Attacker-controlled input reached OS command execution."
                    ),
                    raw_data=combined_output[:500],
                    verified=True,
                ))
                finding.trigger = probe.decode("utf-8", errors="replace")
                finding.confidence = 95
                finding.mark_verified()
                confirmed = True
                break

        if not confirmed:
            finding.add_evidence(EvidenceItem(
                evidence_type="sandbox_marker",
                description="Marker not observed in output; injection not confirmed by sandbox",
                raw_data="",
                verified=False,
            ))
            finding.confidence = 30
            finding.verification_status = "PARTIAL"

        return finding

    # -------------------------------------------------------------------------
    # CWE-22: Path Traversal
    # -------------------------------------------------------------------------

    def _verify_path_traversal(
        self,
        finding: VulnerabilityFinding,
        binary: Path | None,
        timeout_sec: int,
    ) -> VulnerabilityFinding:
        """
        Use a synthetic sandbox filesystem. Prove traversal escapes the
        intended directory. Never access real host filesystem.
        """
        # Traversal probes (all synthetic)
        traversal_probes = [
            b"../etc/passwd\n",
            b"../../etc/passwd\n",
            b"../../../etc/shadow\n",
            b"%2e%2e%2fetc%2fpasswd\n",
            b"....//....//etc/passwd\n",
            b"/etc/passwd\n",
        ]

        if not binary or not binary.is_file():
            root_cause = (finding.root_cause or "").lower()
            has_path_api = any(
                s in root_cause
                for s in ["fopen", "open(", "readfile", "path", "directory"]
            )
            finding.add_evidence(EvidenceItem(
                evidence_type="path_traversal_evidence",
                description="Static pattern: unvalidated path input passed to file API",
                raw_data=finding.root_cause or "",
                verified=has_path_api,
            ))
            finding.confidence = 55 if has_path_api else 25
            finding.verification_status = "PARTIAL"
            return finding

        # Create a synthetic sandbox working directory
        with tempfile.TemporaryDirectory(prefix="chakravyuh_path_sandbox_") as tmpdir:
            sandbox_root = Path(tmpdir) / "sandbox"
            sandbox_root.mkdir()
            (sandbox_root / "allowed.txt").write_text("SAFE_CONTENT\n")
            # Create a sentinel file outside intended dir
            outside_file = Path(tmpdir) / "SENSITIVE_OUTSIDE.txt"
            outside_file.write_text("TRAVERSAL_SUCCESS_MARKER\n")

            confirmed = False
            for probe in traversal_probes:
                res = run_binary_with_input(
                    binary, probe, work_dir=binary.parent, timeout_sec=timeout_sec
                )
                combined = (res.stdout or "") + (res.stderr or "")
                # Check if content from outside sandbox root appeared
                if "TRAVERSAL_SUCCESS_MARKER" in combined or (
                    "root:" in combined and "passwd" in probe.decode("utf-8", errors="replace")
                ):
                    finding.add_evidence(EvidenceItem(
                        evidence_type="path_traversal_evidence",
                        description="CONFIRMED: Path traversal escaped sandbox directory boundary",
                        raw_data=combined[:500],
                        verified=True,
                    ))
                    finding.trigger = probe.decode("utf-8", errors="replace")
                    finding.confidence = 92
                    finding.mark_verified()
                    confirmed = True
                    break

            if not confirmed:
                finding.add_evidence(EvidenceItem(
                    evidence_type="path_traversal_evidence",
                    description="Path traversal not confirmed; static evidence only",
                    raw_data="",
                    verified=False,
                ))
                finding.confidence = 35
                finding.verification_status = "PARTIAL"

        return finding

    # -------------------------------------------------------------------------
    # CWE-134: Format String
    # -------------------------------------------------------------------------

    def _verify_format_string(
        self,
        finding: VulnerabilityFinding,
        binary: Path | None,
        timeout_sec: int,
    ) -> VulnerabilityFinding:
        """Verify format string by sending specifiers and observing output."""
        fmt_probes = [
            b"%x %x %x %x\n",
            b"%s%s%s%s\n",
            b"%08x.%08x.%08x.%08x\n",
            b"AAAA%x%x%x\n",
        ]

        if not binary or not binary.is_file():
            root_cause = (finding.root_cause or "").lower()
            has_printf = any(s in root_cause for s in ["printf(", "fprintf(", "sprintf(", "format"])
            finding.add_evidence(EvidenceItem(
                evidence_type="format_string_evidence",
                description="Static: user input passed as printf format argument",
                raw_data=finding.root_cause or "",
                verified=has_printf,
            ))
            finding.confidence = 65 if has_printf else 25
            finding.verification_status = "PARTIAL"
            return finding

        confirmed = False
        for probe in fmt_probes:
            res = run_binary_with_input(binary, probe, work_dir=binary.parent, timeout_sec=timeout_sec)
            combined = (res.stdout or "") + (res.stderr or "")
            for pat in _FMT_PATTERNS:
                if pat.search(combined):
                    finding.add_evidence(EvidenceItem(
                        evidence_type="format_string_evidence",
                        description="CONFIRMED: Format specifiers produced memory leak / crash",
                        raw_data=combined[:800],
                        verified=True,
                    ))
                    finding.trigger = probe.decode("utf-8", errors="replace")
                    finding.confidence = 88
                    finding.mark_verified()
                    confirmed = True
                    break
            if confirmed:
                break

        if not confirmed:
            finding.confidence = 30
            finding.verification_status = "PARTIAL"
            finding.add_evidence(EvidenceItem(
                evidence_type="format_string_evidence",
                description="Format string behavior not observed in sandbox output",
                raw_data="",
                verified=False,
            ))

        return finding

    # -------------------------------------------------------------------------
    # CWE-20: Improper Input Validation
    # -------------------------------------------------------------------------

    def _verify_input_validation(
        self,
        finding: VulnerabilityFinding,
        binary: Path | None,
        timeout_sec: int,
    ) -> VulnerabilityFinding:
        """Verify missing input validation via boundary/malformed inputs."""
        validation_probes = [
            b"\n",                           # empty input
            b"A" * 10000 + b"\n",            # large input
            b"-1\n",                          # negative value
            b"0\n",                           # zero
            b"\xff\xfe\n",                   # invalid encoding
            b"' OR '1'='1\n",               # injection-style
            b"../\n",                         # path-like
            b"\x00\x00\x00\n",              # null bytes
        ]

        if not binary or not binary.is_file():
            finding.add_evidence(EvidenceItem(
                evidence_type="input_validation_evidence",
                description="Static: missing input bounds/type/range check identified",
                raw_data=finding.root_cause or "",
                verified=bool(finding.root_cause),
            ))
            finding.confidence = 50 if finding.root_cause else 20
            finding.verification_status = "PARTIAL"
            return finding

        abnormal_responses = 0
        for probe in validation_probes:
            res = run_binary_with_input(binary, probe, work_dir=binary.parent, timeout_sec=timeout_sec)
            if res.crashed or res.returncode not in (0, 1):
                abnormal_responses += 1

        confirmed = abnormal_responses >= 2
        finding.add_evidence(EvidenceItem(
            evidence_type="input_validation_evidence",
            description=f"Boundary probe results: {abnormal_responses}/{len(validation_probes)} inputs caused abnormal behavior",
            raw_data=f"abnormal_responses={abnormal_responses}",
            verified=confirmed,
        ))

        if confirmed:
            finding.confidence = 70
            finding.verification_status = "PARTIAL"  # boundary anomalies not definitive alone
        else:
            finding.confidence = 30
            finding.verification_status = "PARTIAL"

        return finding
