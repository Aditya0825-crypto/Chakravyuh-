"""Deterministic Recommendation Engine (SAFE / REVIEW / HOLD) per specification §9."""

from __future__ import annotations

from typing import Any


def compute_recommendation(
    has_verified_pov: bool,
    winner_patch: Any | None,
    rediscovery_failed: bool = False,
) -> str:
    """
    Deterministic rule engine for automated patch safety categorization:
    - HOLD: Missing verified PoV, no winner patch, score < 60, or rediscovery failed
    - SAFE: Score >= 85.0, 100% regression tests passed, and all attack variants blocked
    - REVIEW: Any other passing candidate requiring security engineer sign-off
    """
    if not has_verified_pov or not winner_patch:
        return "HOLD"

    score = getattr(winner_patch, "score_total", 0.0)
    if score < 60.0:
        return "HOLD"

    if rediscovery_failed:
        return "HOLD"

    attacks_blocked = getattr(winner_patch, "attacks_blocked", 0)
    attacks_total = getattr(winner_patch, "attacks_total", 9)
    all_attacks_blocked = (attacks_blocked == attacks_total) and (attacks_total > 0)

    reg_passed = getattr(winner_patch, "regression_passed", 0)
    reg_total = getattr(winner_patch, "regression_total", 0)
    reg_clean = (reg_total == 0) or (reg_passed == reg_total)

    if score >= 85.0 and all_attacks_blocked and reg_clean:
        return "SAFE"

    return "REVIEW"


def calculate_cvss_score(cwe: str, severity: str) -> float:
    """Calculate CVSS v3.1 base score based on CWE classification and severity."""
    cwe_upper = (cwe or "").upper()
    if "CWE-122" in cwe_upper or "CWE-121" in cwe_upper or "CWE-416" in cwe_upper:
        return 9.8  # Critical RCE / memory corruption
    if "CWE-78" in cwe_upper or "CWE-89" in cwe_upper:
        return 9.8  # Command / SQL Injection
    if "CWE-190" in cwe_upper or "CWE-476" in cwe_upper:
        return 7.5  # High Denial of Service / Crash
    if severity == "CRITICAL":
        return 9.8
    if severity == "HIGH":
        return 7.5
    if severity == "MEDIUM":
        return 5.3
    return 3.1
