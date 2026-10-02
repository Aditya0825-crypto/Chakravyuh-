"""
CHAKRAVYUH CWE Registry — exactly the 21 supported CWEs.

Do not add CWEs outside this registry without updating the full pipeline.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

# ---------------------------------------------------------------------------
# CWE Category Groupings
# ---------------------------------------------------------------------------
CWECategory = Literal[
    "memory",
    "pointer_type",
    "integer",
    "input_injection",
    "concurrency",
    "crypto_secrets",
    "resource",
]

VerificationMethod = Literal[
    "asan_runtime",        # ASan + reproducible input + stack correlation
    "ubsan_runtime",       # UBSan / behavioral boundary tests
    "injection_sandbox",   # Sandbox behavioral verification (no real exec)
    "tsan_concurrency",    # ThreadSanitizer + race-aware testing
    "static_ast",          # Static / AST / data-flow analysis
    "resource_monitor",    # Isolated resource-limited execution + monitoring
]


@dataclass(frozen=True)
class CWEDescriptor:
    cwe_id: str                    # e.g. "CWE-120"
    cwe_number: int                # e.g. 120
    name: str                      # Human label
    category: CWECategory
    verification_method: VerificationMethod
    severity_default: str          # CRITICAL / HIGH / MEDIUM / LOW
    discovery_preferred: list[str] = field(default_factory=list)  # preferred discovery channels
    adversarial_strategy: str = ""
    patch_strategy: str = ""
    notes: str = ""

    @property
    def id(self) -> str:
        return self.cwe_id


# ---------------------------------------------------------------------------
# Registry: exactly 21 CWEs
# ---------------------------------------------------------------------------
_REGISTRY: dict[str, CWEDescriptor] = {}


def _reg(d: CWEDescriptor) -> CWEDescriptor:
    _REGISTRY[d.cwe_id] = d
    return d


# ── Memory ──────────────────────────────────────────────────────────────────
_reg(CWEDescriptor(
    cwe_id="CWE-120", cwe_number=120,
    name="Buffer Overflow (Classic)",
    category="memory",
    verification_method="asan_runtime",
    severity_default="HIGH",
    discovery_preferred=["semgrep", "ast", "afl"],
    adversarial_strategy="boundary/overflow inputs, off-by-one, large payloads",
    patch_strategy="bounds validation before copy, use safe string functions",
    notes="Covers strcpy/strcat without bounds check.",
))

_reg(CWEDescriptor(
    cwe_id="CWE-122", cwe_number=122,
    name="Heap Buffer Overflow",
    category="memory",
    verification_method="asan_runtime",
    severity_default="CRITICAL",
    discovery_preferred=["semgrep", "ast", "afl", "llm"],
    adversarial_strategy="heap spray, sized allocations slightly smaller than write",
    patch_strategy="size validation before heap write, use snprintf/memcpy with bounds",
))

_reg(CWEDescriptor(
    cwe_id="CWE-125", cwe_number=125,
    name="Out-of-Bounds Read",
    category="memory",
    verification_method="asan_runtime",
    severity_default="HIGH",
    discovery_preferred=["semgrep", "ast", "afl"],
    adversarial_strategy="under-allocated read targets, large index values",
    patch_strategy="index bounds check before array/pointer access",
))

_reg(CWEDescriptor(
    cwe_id="CWE-787", cwe_number=787,
    name="Out-of-Bounds Write",
    category="memory",
    verification_method="asan_runtime",
    severity_default="CRITICAL",
    discovery_preferred=["semgrep", "ast", "afl"],
    adversarial_strategy="off-by-one write, full overflow, controlled offset writes",
    patch_strategy="bounds check before write, validate destination capacity",
))

_reg(CWEDescriptor(
    cwe_id="CWE-416", cwe_number=416,
    name="Use-After-Free",
    category="memory",
    verification_method="asan_runtime",
    severity_default="CRITICAL",
    discovery_preferred=["ast", "semgrep", "afl"],
    adversarial_strategy="trigger free then access freed pointer, double-use patterns",
    patch_strategy="null pointer after free, ownership tracking, RAII patterns",
))

_reg(CWEDescriptor(
    cwe_id="CWE-415", cwe_number=415,
    name="Double Free",
    category="memory",
    verification_method="asan_runtime",
    severity_default="CRITICAL",
    discovery_preferred=["ast", "semgrep", "afl"],
    adversarial_strategy="trigger code path that calls free twice on same pointer",
    patch_strategy="null pointer after free, centralized deallocation ownership",
))

# ── Pointer / Type ───────────────────────────────────────────────────────────
_reg(CWEDescriptor(
    cwe_id="CWE-476", cwe_number=476,
    name="NULL Pointer Dereference",
    category="pointer_type",
    verification_method="ubsan_runtime",
    severity_default="HIGH",
    discovery_preferred=["semgrep", "ast", "afl"],
    adversarial_strategy="null or minimal allocation inputs that trigger dereference path",
    patch_strategy="null check before dereference, early return on null",
))

_reg(CWEDescriptor(
    cwe_id="CWE-843", cwe_number=843,
    name="Type Confusion",
    category="pointer_type",
    verification_method="ubsan_runtime",
    severity_default="HIGH",
    discovery_preferred=["ast", "semgrep", "llm"],
    adversarial_strategy="mismatched type cast inputs, union abuse sequences",
    patch_strategy="type assertions, tagged unions, dynamic_cast with error check",
))

# ── Integer ──────────────────────────────────────────────────────────────────
_reg(CWEDescriptor(
    cwe_id="CWE-190", cwe_number=190,
    name="Integer Overflow",
    category="integer",
    verification_method="ubsan_runtime",
    severity_default="HIGH",
    discovery_preferred=["semgrep", "ast", "afl"],
    adversarial_strategy="INT_MAX, INT_MAX-1, large multipliers, boundary arithmetic",
    patch_strategy="safe arithmetic checks, overflow-safe libraries, pre-condition guards",
))

_reg(CWEDescriptor(
    cwe_id="CWE-191", cwe_number=191,
    name="Integer Underflow",
    category="integer",
    verification_method="ubsan_runtime",
    severity_default="HIGH",
    discovery_preferred=["semgrep", "ast", "afl"],
    adversarial_strategy="INT_MIN, 0, -1, underflow triggering subtraction inputs",
    patch_strategy="underflow guards, unsigned arithmetic where appropriate",
))

_reg(CWEDescriptor(
    cwe_id="CWE-369", cwe_number=369,
    name="Divide by Zero",
    category="integer",
    verification_method="ubsan_runtime",
    severity_default="MEDIUM",
    discovery_preferred=["semgrep", "ast"],
    adversarial_strategy="zero denominator inputs, computed divisors that can be zero",
    patch_strategy="divisor check before division, guard clause",
))

# ── Input / Injection ────────────────────────────────────────────────────────
_reg(CWEDescriptor(
    cwe_id="CWE-20", cwe_number=20,
    name="Improper Input Validation",
    category="input_injection",
    verification_method="injection_sandbox",
    severity_default="MEDIUM",
    discovery_preferred=["semgrep", "ast", "llm"],
    adversarial_strategy="boundary values, type mismatches, missing/extra fields",
    patch_strategy="allowlist validation, strict type/length/range checks",
))

_reg(CWEDescriptor(
    cwe_id="CWE-134", cwe_number=134,
    name="Format String Vulnerability",
    category="input_injection",
    verification_method="injection_sandbox",
    severity_default="HIGH",
    discovery_preferred=["semgrep", "ast", "afl"],
    adversarial_strategy="%s%x%n format specifiers, %n write-primitive",
    patch_strategy="use literal format string, never pass user input as format arg",
))

_reg(CWEDescriptor(
    cwe_id="CWE-78", cwe_number=78,
    name="OS Command Injection",
    category="input_injection",
    verification_method="injection_sandbox",
    severity_default="CRITICAL",
    discovery_preferred=["semgrep", "ast", "llm"],
    adversarial_strategy="shell metacharacters (;|&`$), CHAKRAVYUH_MARKER sentinel probes",
    patch_strategy="use execv-family without shell, validated allowlist, avoid system()/popen()",
    notes="Sandbox-only: use harmless marker sentinel commands, no real shell execution.",
))

_reg(CWEDescriptor(
    cwe_id="CWE-22", cwe_number=22,
    name="Path Traversal",
    category="input_injection",
    verification_method="injection_sandbox",
    severity_default="HIGH",
    discovery_preferred=["semgrep", "ast", "llm"],
    adversarial_strategy="../ sequences, %2e%2e%2f encoded traversal, absolute paths",
    patch_strategy="canonical path check, chroot-style root enforcement",
    notes="Synthetic sandbox filesystem only; no real host filesystem access.",
))

# ── Concurrency ───────────────────────────────────────────────────────────────
_reg(CWEDescriptor(
    cwe_id="CWE-362", cwe_number=362,
    name="Race Condition",
    category="concurrency",
    verification_method="tsan_concurrency",
    severity_default="HIGH",
    discovery_preferred=["ast", "semgrep", "llm"],
    adversarial_strategy="concurrent access schedules, repeated interleaved execution",
    patch_strategy="mutex/lock guards around shared state, atomic operations",
))

_reg(CWEDescriptor(
    cwe_id="CWE-367", cwe_number=367,
    name="Time-of-Check to Time-of-Use (TOCTOU)",
    category="concurrency",
    verification_method="tsan_concurrency",
    severity_default="HIGH",
    discovery_preferred=["ast", "semgrep", "llm"],
    adversarial_strategy="inject change between check and use phase; verify check→change→use sequence",
    patch_strategy="atomic check-and-use, O_NOFOLLOW, fstat on open fd",
))

# ── Crypto / Secrets ──────────────────────────────────────────────────────────
_reg(CWEDescriptor(
    cwe_id="CWE-327", cwe_number=327,
    name="Use of Broken or Risky Cryptographic Algorithm",
    category="crypto_secrets",
    verification_method="static_ast",
    severity_default="HIGH",
    discovery_preferred=["semgrep", "ast", "llm"],
    adversarial_strategy="policy/algorithm name checks, weak-algorithm enumeration",
    patch_strategy="replace MD5/SHA1/DES/RC4 with AES-256-GCM/SHA-256+",
    notes="Static AST/data-flow analysis only. Not crash-based.",
))

_reg(CWEDescriptor(
    cwe_id="CWE-321", cwe_number=321,
    name="Use of Hard-coded Cryptographic Key",
    category="crypto_secrets",
    verification_method="static_ast",
    severity_default="CRITICAL",
    discovery_preferred=["semgrep", "ast", "llm"],
    adversarial_strategy="key-context pattern matching, entropy analysis",
    patch_strategy="load key from environment variable or secure key management system",
    notes="Must use context-aware detection, not every string constant.",
))

_reg(CWEDescriptor(
    cwe_id="CWE-798", cwe_number=798,
    name="Use of Hard-coded Credentials",
    category="crypto_secrets",
    verification_method="static_ast",
    severity_default="CRITICAL",
    discovery_preferred=["semgrep", "ast", "llm"],
    adversarial_strategy="credential pattern matching (password, token, secret, apikey)",
    patch_strategy="remove hardcoded values, use environment variables or secret store",
    notes="Must distinguish credential context from other string constants. Mask in reports.",
))

# ── Resource ──────────────────────────────────────────────────────────────────
_reg(CWEDescriptor(
    cwe_id="CWE-400", cwe_number=400,
    name="Uncontrolled Resource Consumption",
    category="resource",
    verification_method="resource_monitor",
    severity_default="HIGH",
    discovery_preferred=["semgrep", "ast", "llm", "afl"],
    adversarial_strategy="increasing/stress inputs, large allocations, rapid request sequences",
    patch_strategy="resource limits, rate limiting, bounded allocation",
    notes="Timeout alone is not sufficient proof. Must monitor CPU/memory/time.",
))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_cwe(cwe_id: str) -> CWEDescriptor | None:
    """Return descriptor for a CWE ID (e.g. 'CWE-120'), or None if unsupported."""
    return _REGISTRY.get(cwe_id)


def is_supported(cwe_id: str) -> bool:
    """Return True iff this CWE is in the official supported list."""
    return cwe_id in _REGISTRY


def all_cwes() -> list[CWEDescriptor]:
    """Return all 21 supported CWE descriptors sorted by CWE number."""
    return sorted(_REGISTRY.values(), key=lambda d: d.cwe_number)


def cwes_by_category(category: CWECategory) -> list[CWEDescriptor]:
    """Return descriptors filtered by category."""
    return [d for d in _REGISTRY.values() if d.category == category]


def cwes_by_verification_method(method: VerificationMethod) -> list[CWEDescriptor]:
    """Return descriptors that use a given verification method."""
    return [d for d in _REGISTRY.values() if d.verification_method == method]


SUPPORTED_CWE_IDS: frozenset[str] = frozenset(_REGISTRY.keys())

assert len(SUPPORTED_CWE_IDS) == 21, f"Expected 21 CWEs, got {len(SUPPORTED_CWE_IDS)}"
