"""
CWE-specific adversarial test variant generator.

Each vulnerability class gets appropriate hidden tests — separate from the
inputs used to generate the patch. Do NOT force crash-style payloads onto
crypto/secrets or concurrency vulnerabilities.

Patch evaluation must use hidden tests separate from generation inputs.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from workers.patch_engine.attack_variants import AttackVariant


@dataclass
class AdversarialSuite:
    """A set of adversarial tests for a specific CWE."""
    cwe_id: str
    variants: list[AttackVariant] = field(default_factory=list)
    policy_checks: list[dict[str, Any]] = field(default_factory=list)  # for static/policy CWEs
    concurrent_probes: int = 0  # for concurrency CWEs
    resource_sizes: list[int] = field(default_factory=list)  # for CWE-400


def generate_adversarial_suite(
    cwe_id: str,
    original_trigger: str | None = None,
) -> AdversarialSuite:
    """
    Generate CWE-appropriate hidden adversarial tests.

    These tests are HIDDEN from the patch generation agents — they are only
    used for patch evaluation (Section 9/10 of requirements).
    """
    suite = AdversarialSuite(cwe_id=cwe_id)

    # ── Memory CWEs ─────────────────────────────────────────────────────────
    if cwe_id in {"CWE-120", "CWE-122", "CWE-125", "CWE-787"}:
        suite.variants = _memory_overflow_variants(original_trigger)

    elif cwe_id in {"CWE-416", "CWE-415"}:
        suite.variants = _uaf_double_free_variants(original_trigger)

    # ── Pointer / Type ───────────────────────────────────────────────────────
    elif cwe_id == "CWE-476":
        suite.variants = _null_ptr_variants()

    elif cwe_id == "CWE-843":
        suite.variants = _type_confusion_variants()

    # ── Integer ─────────────────────────────────────────────────────────────
    elif cwe_id == "CWE-190":
        suite.variants = _integer_overflow_variants()

    elif cwe_id == "CWE-191":
        suite.variants = _integer_underflow_variants()

    elif cwe_id == "CWE-369":
        suite.variants = _divide_by_zero_variants()

    # ── Input / Injection ───────────────────────────────────────────────────
    elif cwe_id == "CWE-20":
        suite.variants = _input_validation_variants()

    elif cwe_id == "CWE-134":
        suite.variants = _format_string_variants()

    elif cwe_id == "CWE-78":
        suite.variants = _cmd_injection_variants()

    elif cwe_id == "CWE-22":
        suite.variants = _path_traversal_variants()

    # ── Concurrency ──────────────────────────────────────────────────────────
    elif cwe_id in {"CWE-362", "CWE-367"}:
        suite.concurrent_probes = 10
        suite.variants = _concurrency_variants(original_trigger)

    # ── Crypto / Secrets ────────────────────────────────────────────────────
    elif cwe_id == "CWE-327":
        suite.policy_checks = _weak_algo_policy_checks()

    elif cwe_id == "CWE-321":
        suite.policy_checks = _hardcoded_key_policy_checks()

    elif cwe_id == "CWE-798":
        suite.policy_checks = _hardcoded_cred_policy_checks()

    # ── Resource ────────────────────────────────────────────────────────────
    elif cwe_id == "CWE-400":
        suite.resource_sizes = [1_000, 10_000, 100_000, 1_000_000]
        suite.variants = _resource_exhaustion_variants()

    return suite


# ── Memory overflow variants ──────────────────────────────────────────────────

def _memory_overflow_variants(original: str | None) -> list[AttackVariant]:
    base = (original or ("A" * 256)).encode("utf-8", errors="replace")
    return [
        AttackVariant("mem_exact_boundary", "Exact buffer boundary", b"A" * 255 + b"\n"),
        AttackVariant("mem_off_by_one", "Off-by-one overflow", b"A" * 256 + b"\n"),
        AttackVariant("mem_double_boundary", "Double boundary overflow", b"A" * 512 + b"\n"),
        AttackVariant("mem_large_flood", "Large 64KB flood", b"A" * 65536 + b"\n"),
        AttackVariant("mem_null_prefix", "Null byte prefix", b"\x00" * 4 + b"A" * 252 + b"\n"),
        AttackVariant("mem_ff_fill", "0xFF high-byte fill", b"\xff" * 256 + b"\n"),
        AttackVariant("mem_original", "Original trigger", base + b"\n" if not base.endswith(b"\n") else base),
        AttackVariant("mem_alternating", "Alternating AABB pattern", b"AB" * 128 + b"\n"),
        AttackVariant("mem_unicode", "Wide unicode payload", ("A" * 128 + "\u4e2d" * 32 + "\n").encode("utf-8", errors="replace")),
    ]


def _uaf_double_free_variants(original: str | None) -> list[AttackVariant]:
    base = (original or "free_trigger").encode("utf-8", errors="replace")
    return [
        AttackVariant("uaf_alloc_free_access", "Alloc then free then access", base),
        AttackVariant("uaf_double_free", "Double free trigger", b"df\n"),
        AttackVariant("uaf_use_after_scope", "Use after scope exit", b"scope_exit\n"),
        AttackVariant("uaf_rapid_sequence", "Rapid alloc-free sequence", b"rapid\n" * 5),
        AttackVariant("uaf_null_after_free", "Null pointer after free", b"\x00\n"),
    ]


# ── Pointer / Type variants ───────────────────────────────────────────────────

def _null_ptr_variants() -> list[AttackVariant]:
    return [
        AttackVariant("null_empty", "Empty input (null trigger)", b""),
        AttackVariant("null_zero_len", "Zero length string", b"\x00\n"),
        AttackVariant("null_minimal", "Single char", b"0\n"),
        AttackVariant("null_negative", "Negative value", b"-1\n"),
        AttackVariant("null_whitespace", "Whitespace only", b"   \n"),
    ]


def _type_confusion_variants() -> list[AttackVariant]:
    return [
        AttackVariant("type_wrong_tag", "Wrong type tag input", b"TYPE_B\n"),
        AttackVariant("type_overflow_tag", "Overflow type tag", b"\xff\xff\xff\xff\n"),
        AttackVariant("type_zero_tag", "Zero type tag", b"\x00\x00\x00\x00\n"),
        AttackVariant("type_string_as_int", "String where int expected", b"hello\n"),
        AttackVariant("type_negative_index", "Negative union index", b"-1\n"),
    ]


# ── Integer variants ──────────────────────────────────────────────────────────

def _integer_overflow_variants() -> list[AttackVariant]:
    return [
        AttackVariant("int_max", "INT_MAX", b"2147483647\n"),
        AttackVariant("int_max_plus_one", "INT_MAX + 1", b"2147483648\n"),
        AttackVariant("int_uint_max", "UINT_MAX", b"4294967295\n"),
        AttackVariant("int_large_multiplier", "Large multiplier", b"1000000 2000\n"),
        AttackVariant("int_negative_one", "-1 as unsigned", b"-1\n"),
        AttackVariant("int_zero", "Zero", b"0\n"),
        AttackVariant("int_two_large", "Two large values summed", b"2000000000 2000000000\n"),
    ]


def _integer_underflow_variants() -> list[AttackVariant]:
    return [
        AttackVariant("uint_zero_minus_one", "0 - 1 underflow", b"0 1\n"),
        AttackVariant("int_min", "INT_MIN", b"-2147483648\n"),
        AttackVariant("uint_wrap", "Unsigned wrap-around", b"0\n"),
        AttackVariant("negative_size", "Negative size argument", b"-100\n"),
        AttackVariant("small_sub_large", "Small minus large", b"1 1000\n"),
    ]


def _divide_by_zero_variants() -> list[AttackVariant]:
    return [
        AttackVariant("div_zero", "Zero divisor", b"0\n"),
        AttackVariant("div_zero_pair", "Numerator/Denominator 1/0", b"1 0\n"),
        AttackVariant("div_neg_zero", "Negative zero", b"-0\n"),
        AttackVariant("div_computed_zero", "Expression that computes to zero", b"5 5\n"),
    ]


# ── Injection variants ────────────────────────────────────────────────────────

def _input_validation_variants() -> list[AttackVariant]:
    return [
        AttackVariant("val_empty", "Empty input", b"\n"),
        AttackVariant("val_huge", "100KB input", b"A" * 100_000 + b"\n"),
        AttackVariant("val_negative", "Negative value", b"-1\n"),
        AttackVariant("val_null_bytes", "Null bytes", b"\x00" * 10 + b"\n"),
        AttackVariant("val_utf8_invalid", "Invalid UTF-8", bytes([0xFF, 0xFE, 0x00, 0x41]) + b"\n"),
        AttackVariant("val_sql_injection", "SQL injection-style", b"' OR '1'='1\n"),
        AttackVariant("val_newline", "Embedded newlines", b"line1\nline2\nline3\n"),
    ]


def _format_string_variants() -> list[AttackVariant]:
    return [
        AttackVariant("fmt_percent_x", "%x read gadget", b"%x%x%x%x\n"),
        AttackVariant("fmt_percent_n", "%n write gadget", b"%n%n%n%n\n"),
        AttackVariant("fmt_percent_s", "%s dereference", b"%s%s%s%s\n"),
        AttackVariant("fmt_combined", "Combined specifiers", b"AAAA%x%x%x%n\n"),
        AttackVariant("fmt_wide", "Wide format specifiers", b"%1000d%n\n"),
        AttackVariant("fmt_literal_pct", "Literal percent (safe)", b"100%%\n"),
    ]


def _cmd_injection_variants() -> list[AttackVariant]:
    """All payloads use only a harmless echo marker — no destructive commands."""
    marker = b"CHAKRAVYUH_MARKER_SAFE_7a3f"
    return [
        AttackVariant("cmd_semicolon", "Semicolon separator", b"; echo " + marker + b"\n"),
        AttackVariant("cmd_pipe", "Pipe chaining", b"| echo " + marker + b"\n"),
        AttackVariant("cmd_backtick", "Backtick subshell", b"`echo " + marker + b"`\n"),
        AttackVariant("cmd_dollar_paren", "Dollar-paren subshell", b"$(echo " + marker + b")\n"),
        AttackVariant("cmd_ampersand", "Background execution", b"& echo " + marker + b"\n"),
        AttackVariant("cmd_double_ampersand", "Short-circuit AND", b"true && echo " + marker + b"\n"),
        AttackVariant("cmd_newline", "Newline separator", b"safe\necho " + marker + b"\n"),
    ]


def _path_traversal_variants() -> list[AttackVariant]:
    return [
        AttackVariant("path_double_dot", "Standard traversal", b"../secret\n"),
        AttackVariant("path_triple_dot", "Triple traversal", b"../../secret\n"),
        AttackVariant("path_deep", "Deep traversal", b"../../../etc/passwd\n"),
        AttackVariant("path_encoded", "URL-encoded traversal", b"%2e%2e%2fsecret\n"),
        AttackVariant("path_double_encoded", "Double-encoded", b"%252e%252e%252f\n"),
        AttackVariant("path_absolute", "Absolute path", b"/etc/passwd\n"),
        AttackVariant("path_dots_slash", "Dots-slash mix", b"....//secret\n"),
        AttackVariant("path_unicode_sep", "Unicode separator", b"..%c0%afsecret\n"),
    ]


# ── Concurrency variants ──────────────────────────────────────────────────────

def _concurrency_variants(original: str | None) -> list[AttackVariant]:
    base = (original or "concurrent_test").encode("utf-8", errors="replace")
    return [
        AttackVariant("race_concurrent_write", "Concurrent write probe", base),
        AttackVariant("race_rapid_access", "Rapid repeated access", base * 3),
        AttackVariant("race_interleaved", "Interleaved requests", b"A\nB\nC\n"),
        AttackVariant("race_long_running", "Long-running operation", b"slow\n"),
    ]


# ── Resource variants ─────────────────────────────────────────────────────────

def _resource_exhaustion_variants() -> list[AttackVariant]:
    return [
        AttackVariant("res_1k", "1KB stress", b"A" * 1_000 + b"\n"),
        AttackVariant("res_10k", "10KB stress", b"A" * 10_000 + b"\n"),
        AttackVariant("res_100k", "100KB stress", b"A" * 100_000 + b"\n"),
        AttackVariant("res_nested", "Nested structure", b"{" * 1000 + b"}" * 1000 + b"\n"),
        AttackVariant("res_repeated", "Repeated small items", b"item\n" * 10_000),
    ]


# ── Crypto / Secrets policy checks (non-binary) ────────────────────────────────

def _weak_algo_policy_checks() -> list[dict]:
    return [
        {"check": "algorithm_not_md5", "forbidden": ["MD5", "md5"], "description": "MD5 must not be used"},
        {"check": "algorithm_not_sha1", "forbidden": ["SHA1", "SHA-1", "sha1"], "description": "SHA-1 must not be used"},
        {"check": "algorithm_not_des", "forbidden": ["DES", "3DES"], "description": "DES/3DES must not be used"},
        {"check": "algorithm_not_rc4", "forbidden": ["RC4", "ARC4"], "description": "RC4/ARC4 must not be used"},
        {"check": "algorithm_not_ecb", "forbidden": ["ECB"], "description": "ECB mode must not be used"},
    ]


def _hardcoded_key_policy_checks() -> list[dict]:
    return [
        {"check": "no_hardcoded_key", "description": "No hardcoded key bytes in key context"},
        {"check": "key_from_env_or_kms", "description": "Key must be loaded from environment or KMS"},
    ]


def _hardcoded_cred_policy_checks() -> list[dict]:
    return [
        {"check": "no_hardcoded_password", "description": "No hardcoded password string"},
        {"check": "no_hardcoded_token", "description": "No hardcoded API token"},
        {"check": "cred_from_env", "description": "Credentials must come from environment or secrets store"},
    ]
