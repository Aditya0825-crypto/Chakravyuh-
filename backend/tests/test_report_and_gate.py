"""Unit tests for Stage 6 Security Report, Recommendation Logic, and Human Gate."""

from dataclasses import dataclass
import pytest

from workers.report.recommendation import calculate_cvss_score, compute_recommendation


@dataclass
class MockPatch:
    score_total: float = 94.35
    attacks_blocked: int = 9
    attacks_total: int = 9
    regression_passed: int = 10
    regression_total: int = 10


def test_recommendation_hold_when_no_pov_or_patch():
    assert compute_recommendation(has_verified_pov=False, winner_patch=MockPatch()) == "HOLD"
    assert compute_recommendation(has_verified_pov=True, winner_patch=None) == "HOLD"


def test_recommendation_hold_when_score_low():
    patch = MockPatch(score_total=55.0)
    assert compute_recommendation(has_verified_pov=True, winner_patch=patch) == "HOLD"


def test_recommendation_hold_when_rediscovery_failed():
    patch = MockPatch(score_total=92.0)
    assert compute_recommendation(has_verified_pov=True, winner_patch=patch, rediscovery_failed=True) == "HOLD"


def test_recommendation_safe_when_high_score_and_all_blocked():
    patch = MockPatch(score_total=94.0, attacks_blocked=9, attacks_total=9, regression_passed=10, regression_total=10)
    assert compute_recommendation(has_verified_pov=True, winner_patch=patch) == "SAFE"


def test_recommendation_review_when_moderate_score():
    patch = MockPatch(score_total=75.0, attacks_blocked=9, attacks_total=9, regression_passed=10, regression_total=10)
    assert compute_recommendation(has_verified_pov=True, winner_patch=patch) == "REVIEW"


def test_recommendation_review_when_variant_missed():
    patch = MockPatch(score_total=88.0, attacks_blocked=8, attacks_total=9, regression_passed=10, regression_total=10)
    assert compute_recommendation(has_verified_pov=True, winner_patch=patch) == "REVIEW"


def test_cvss_score_calculation():
    assert calculate_cvss_score("CWE-122", "CRITICAL") == 9.8
    assert calculate_cvss_score("CWE-416", "CRITICAL") == 9.8
    assert calculate_cvss_score("CWE-190", "HIGH") == 7.5
    assert calculate_cvss_score("CWE-476", "HIGH") == 7.5
