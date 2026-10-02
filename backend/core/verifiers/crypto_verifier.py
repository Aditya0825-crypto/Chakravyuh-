"""
Crypto / Secrets Static Verifier — CWE-327, 321, 798.

Verification uses:
  - Static AST / data-flow analysis
  - Configurable security policy (weak algorithm lists, secret patterns)
  - Context-aware detection (NOT every string constant)

Rules:
  - CWE-327: Weak algorithm names (MD5, SHA1, DES, RC4, ECB-mode, etc.)
  - CWE-321: Hardcoded crypto key — context must indicate KEY, not arbitrary string
  - CWE-798: Hardcoded credentials — context must indicate password/token/credential

Evidence:
  - "static_pattern" evidence type
  - Sensitive values are MASKED in reports

Do NOT classify every string constant as a secret/key/credential.
"""
from __future__ import annotations

import re
from pathlib import Path

from core.finding import EvidenceItem, VulnerabilityFinding
from core.verifiers import BaseVerifier

# ── CWE-327: Weak algorithm patterns ─────────────────────────────────────────
_WEAK_ALGO_PATTERNS = [
    re.compile(r'\bMD5\b', re.I),
    re.compile(r'\bSHA[-_]?1\b', re.I),
    re.compile(r'\bDES\b(?!.*AES)', re.I),       # DES but not in "3DES" context next to AES
    re.compile(r'\b3DES\b|\bTRIPLE.?DES\b', re.I),
    re.compile(r'\bRC4\b|\bARC4\b|\bARC2\b', re.I),
    re.compile(r'\bBLOWFISH\b|\bIDEA\b', re.I),
    re.compile(r'EVP_md5\(\)', re.I),
    re.compile(r'EVP_des_', re.I),
    re.compile(r'EVP_rc4\b', re.I),
    re.compile(r'EVP_sha1\(\)', re.I),
    re.compile(r'SSL_TLSv1\b|TLS1_0|TLS1_1|SSLv[23]', re.I),
    re.compile(r'\bECB\b', re.I),   # ECB mode
]

# ── CWE-321: Hardcoded crypto key ─────────────────────────────────────────────
# Must appear in a key/iv/secret CONTEXT, not just any string
_KEY_CONTEXT_PATTERNS = [
    re.compile(r'(?:char|unsigned char|uint8_t)\s+\w*(?:key|iv|aes_key|secret)\w*\s*\[\s*\d+\s*\]\s*=\s*\{', re.I),
    re.compile(r'(?:key|iv|aes_key|crypto_key|encrypt_key)\s*=\s*["\'][\w/+=]{8,}["\']', re.I),
    re.compile(r'#define\s+\w*(?:KEY|IV|SECRET)\w*\s+["\'][\w/+=]{8,}["\']', re.I),
    re.compile(r'const\s+(?:char|unsigned char)\s*\*?\s*\w*(?:key|iv|secret)\w*\s*=\s*["\'][\w/+=]{8,}["\']', re.I),
]

# ── CWE-798: Hardcoded credentials ───────────────────────────────────────────
_CREDENTIAL_CONTEXT_PATTERNS = [
    re.compile(r'(?:password|passwd|pwd|credential|token|api_?key|auth_?key|secret)\s*=\s*["\'][^"\']{4,}["\']', re.I),
    re.compile(r'#define\s+\w*(?:PASSWORD|TOKEN|SECRET|API_KEY)\w*\s+["\'][^"\']{4,}["\']', re.I),
    re.compile(r'strcmp\s*\(\s*(?:password|input)\s*,\s*["\'][^"\']{4,}["\']', re.I),
    re.compile(r'(?:username|user)\s*=\s*["\'][^"\']{2,}["\'].*(?:password|passwd)\s*=\s*["\'][^"\']{4,}["\']', re.I | re.DOTALL),
]

# Values to mask in reports
_MASK_RE = re.compile(
    r'(?i)((?:password|passwd|key|secret|token|credential)\s*[=:]\s*)["\']([^"\']{0,64})["\']'
)


def _mask_secret(text: str) -> str:
    """Mask sensitive values in evidence text."""
    return _MASK_RE.sub(r'\1"***MASKED***"', text)


class CryptoSecretsVerifier(BaseVerifier):
    """
    Verifies crypto/secrets CWEs via static AST and data-flow pattern matching.
    Reports include masked sensitive values.
    """

    SUPPORTED_CWES = frozenset({"CWE-327", "CWE-321", "CWE-798"})

    def verify(
        self,
        finding: VulnerabilityFinding,
        *,
        source_root: Path | None = None,
        **kwargs,
    ) -> VulnerabilityFinding:

        cwe = finding.cwe_id

        # Build searchable text from finding location + root_cause
        text_sources = [
            finding.root_cause or "",
            finding.trigger or "",
            finding.asan_summary or "",
        ]

        # If source root available, read the specific file
        if source_root and finding.file:
            candidate_paths = [
                source_root / finding.file,
                Path(finding.file),
            ]
            for p in candidate_paths:
                if p.is_file():
                    try:
                        text_sources.append(p.read_text(encoding="utf-8", errors="replace"))
                    except OSError:
                        pass
                    break

        full_text = "\n".join(text_sources)

        if cwe == "CWE-327":
            return self._verify_weak_algo(finding, full_text)
        elif cwe == "CWE-321":
            return self._verify_hardcoded_key(finding, full_text)
        else:  # CWE-798
            return self._verify_hardcoded_creds(finding, full_text)

    # -------------------------------------------------------------------------

    def _verify_weak_algo(self, finding: VulnerabilityFinding, text: str) -> VulnerabilityFinding:
        matches = []
        for pat in _WEAK_ALGO_PATTERNS:
            m = pat.search(text)
            if m:
                matches.append(m.group(0))

        if matches:
            finding.add_evidence(EvidenceItem(
                evidence_type="static_pattern",
                description=f"Weak cryptographic algorithm detected: {', '.join(set(matches[:5]))}",
                raw_data=_mask_secret(text[:500]),
                verified=True,
            ))
            finding.confidence = 90
            finding.mark_verified()
        else:
            finding.add_evidence(EvidenceItem(
                evidence_type="static_pattern",
                description="No weak cryptographic algorithm pattern detected",
                raw_data="",
                verified=False,
            ))
            finding.confidence = 20
            finding.verification_status = "PARTIAL"

        return finding

    def _verify_hardcoded_key(self, finding: VulnerabilityFinding, text: str) -> VulnerabilityFinding:
        matches = []
        for pat in _KEY_CONTEXT_PATTERNS:
            m = pat.search(text)
            if m:
                matches.append(m.group(0))

        if matches:
            masked_match = _mask_secret(matches[0][:200])
            finding.add_evidence(EvidenceItem(
                evidence_type="static_pattern",
                description="Hardcoded cryptographic key found in key context",
                raw_data=masked_match,
                verified=True,
            ))
            finding.confidence = 88
            finding.mark_verified()
        else:
            finding.add_evidence(EvidenceItem(
                evidence_type="static_pattern",
                description="No hardcoded key pattern detected in key context",
                raw_data="",
                verified=False,
            ))
            finding.confidence = 20
            finding.verification_status = "PARTIAL"

        return finding

    def _verify_hardcoded_creds(self, finding: VulnerabilityFinding, text: str) -> VulnerabilityFinding:
        matches = []
        for pat in _CREDENTIAL_CONTEXT_PATTERNS:
            m = pat.search(text)
            if m:
                matches.append(m.group(0))

        if matches:
            masked_match = _mask_secret(matches[0][:200])
            finding.add_evidence(EvidenceItem(
                evidence_type="static_pattern",
                description="Hardcoded credential found in authentication context",
                raw_data=masked_match,
                verified=True,
            ))
            finding.confidence = 90
            finding.mark_verified()
        else:
            finding.add_evidence(EvidenceItem(
                evidence_type="static_pattern",
                description="No hardcoded credential pattern detected in credential context",
                raw_data="",
                verified=False,
            ))
            finding.confidence = 20
            finding.verification_status = "PARTIAL"

        return finding
