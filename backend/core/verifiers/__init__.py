"""Verifier interface — all CWE-specific verifiers implement this protocol."""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from core.finding import VulnerabilityFinding


class BaseVerifier(ABC):
    """
    Strategy interface for vulnerability-specific verification.

    Each implementation chooses the appropriate toolchain for its CWE class
    and must populate finding.evidence with machine-checkable evidence before
    calling finding.mark_verified() or finding.mark_rejected().
    """

    #: CWE IDs this verifier handles
    SUPPORTED_CWES: frozenset[str] = frozenset()

    @abstractmethod
    def verify(self, finding: "VulnerabilityFinding", **kwargs) -> "VulnerabilityFinding":
        """
        Run verification and return the updated finding.

        Contract:
        - Must NOT mark VERIFIED without at least one EvidenceItem.verified == True.
        - Must NOT leave finding.verification_status as CANDIDATE on return.
        - Must NOT execute destructive commands on the real host filesystem.
        - Must use sandbox/isolation for any code execution.
        """
        ...

    def supports(self, cwe_id: str) -> bool:
        return cwe_id in self.SUPPORTED_CWES
