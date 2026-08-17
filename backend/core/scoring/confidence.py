"""PoV confidence scoring — deterministic, not LLM-delegated."""

from dataclasses import dataclass


@dataclass
class ConfidenceInputs:
    runtime_confirmed: bool = False
    reproducible: bool = False
    static_finding_match: bool = False
    stack_depth: int = 0
    has_source_location: bool = False
    sanitizer_summary_present: bool = False
    return_code_valid: bool = False


def calculate_confidence(inputs: ConfidenceInputs) -> int:
    """
    Score 0–100 based on evidence quality.

    Weights aligned with plan: static + runtime + reproducibility.
    """
    score = 0

    if inputs.return_code_valid:
        score += 25
    if inputs.runtime_confirmed:
        score += 30
    if inputs.reproducible:
        score += 20
    if inputs.static_finding_match:
        score += 10
    if inputs.has_source_location:
        score += 10
    if inputs.sanitizer_summary_present:
        score += 5

    # Stack depth bonus (cap +5)
    if inputs.stack_depth >= 3:
        score += 5
    elif inputs.stack_depth >= 1:
        score += 2

    return min(100, max(0, score))


def severity_from_confidence(confidence: int, cwe: str) -> str:
    critical_cwes = {"CWE-122", "CWE-121", "CWE-787", "CWE-416", "CWE-415"}
    if confidence >= 90 and cwe in critical_cwes:
        return "CRITICAL"
    if confidence >= 75:
        return "HIGH"
    if confidence >= 55:
        return "MEDIUM"
    return "LOW"
