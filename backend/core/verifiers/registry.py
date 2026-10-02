"""
Verifier Registry — selects the appropriate verification strategy for a given CWE.

Usage:
    verifier = get_verifier("CWE-122")
    updated_finding = verifier.verify(finding, compiled_binary=bin_path)

Do NOT implement all verification logic as one giant conditional.
Each CWE class has its own dedicated strategy class.
"""
from __future__ import annotations

from core.cwe_registry import VerificationMethod, get_cwe, is_supported
from core.finding import VulnerabilityFinding
from core.verifiers import BaseVerifier


def get_verifier(cwe_id: str) -> BaseVerifier:
    """
    Return the appropriate verifier for a given CWE ID.

    Raises ValueError for unsupported CWEs.
    """
    if not is_supported(cwe_id):
        raise ValueError(
            f"CWE '{cwe_id}' is not in the supported list of 21 CWEs. "
            "Do not add CWEs to the official supported list without updating the full pipeline."
        )

    desc = get_cwe(cwe_id)
    method: VerificationMethod = desc.verification_method

    if method == "asan_runtime":
        from core.verifiers.asan_verifier import ASanVerifier
        return ASanVerifier()
    elif method == "ubsan_runtime":
        from core.verifiers.runtime_verifier import RuntimeUBSanVerifier
        return RuntimeUBSanVerifier()
    elif method == "injection_sandbox":
        from core.verifiers.injection_verifier import InjectionSandboxVerifier
        return InjectionSandboxVerifier()
    elif method == "tsan_concurrency":
        from core.verifiers.concurrency_verifier import ConcurrencyVerifier
        return ConcurrencyVerifier()
    elif method == "static_ast":
        from core.verifiers.crypto_verifier import CryptoSecretsVerifier
        return CryptoSecretsVerifier()
    elif method == "resource_monitor":
        from core.verifiers.resource_verifier import ResourceVerifier
        return ResourceVerifier()
    else:
        raise ValueError(f"No verifier registered for verification method '{method}'")


def verify_finding(
    finding: VulnerabilityFinding,
    **kwargs,
) -> VulnerabilityFinding:
    """
    High-level entry point: select the appropriate verifier and run it.

    For unsupported CWEs: marks finding as PARTIAL with an explanation.
    Never raises — always returns a finding with updated status.
    """
    try:
        verifier = get_verifier(finding.cwe_id)
    except ValueError as e:
        finding.add_evidence(
            __import__("core.finding", fromlist=["EvidenceItem"]).EvidenceItem(
                evidence_type="static_pattern",
                description=f"Unsupported CWE: {finding.cwe_id}",
                raw_data=str(e),
                verified=False,
            )
        )
        finding.verification_status = "PARTIAL"
        finding.confidence = 0
        return finding

    try:
        return verifier.verify(finding, **kwargs)
    except Exception as exc:
        from core.finding import EvidenceItem
        finding.add_evidence(EvidenceItem(
            evidence_type="static_pattern",
            description=f"Verifier raised exception: {exc}",
            raw_data=str(exc),
            verified=False,
        ))
        finding.verification_status = "PARTIAL"
        return finding


# ── Mapping table for documentation/reporting ─────────────────────────────────
VERIFICATION_METHOD_LABELS: dict[str, str] = {
    "asan_runtime": "AddressSanitizer Runtime (sandbox replay + stack correlation)",
    "ubsan_runtime": "UBSan / Behavioral Boundary Testing",
    "injection_sandbox": "Sandbox Behavioral Analysis (harmless markers only)",
    "tsan_concurrency": "ThreadSanitizer + Concurrent Execution",
    "static_ast": "Static AST / Data-Flow Analysis",
    "resource_monitor": "Isolated Resource-Limited Execution + Monitoring",
}
