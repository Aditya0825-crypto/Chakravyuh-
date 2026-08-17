"""AddressSanitizer / UBSan output parsing and CWE classification."""

import re
from dataclasses import dataclass

# ASan error type → human label + CWE
CRASH_TYPE_MAP: dict[str, tuple[str, str]] = {
    "heap-buffer-overflow": ("Heap Buffer Overflow", "CWE-122"),
    "stack-buffer-overflow": ("Stack Buffer Overflow", "CWE-121"),
    "global-buffer-overflow": ("Global Buffer Overflow", "CWE-122"),
    "heap-use-after-free": ("Use-After-Free", "CWE-416"),
    "attempting-double-free": ("Double Free", "CWE-415"),
    "stack-use-after-scope": ("Stack Use After Scope", "CWE-562"),
    "initialization-order-fiasco": ("Initialization Order Fiasco", "CWE-665"),
    "negative-size-param": ("Integer Overflow", "CWE-190"),
    "stack-overflow": ("Stack Overflow", "CWE-674"),
    "use-after-poison": ("Use After Poison", "CWE-416"),
    "dynamic-stack-buffer-overflow": ("Dynamic Stack Buffer Overflow", "CWE-121"),
}

# UBSan patterns
UBSAN_PATTERNS: list[tuple[re.Pattern[str], str, str]] = [
    (re.compile(r"runtime error:.*signed integer overflow", re.I), "Signed Integer Overflow", "CWE-190"),
    (re.compile(r"runtime error:.*shift exponent", re.I), "Undefined Shift", "CWE-682"),
    (re.compile(r"runtime error:.*null pointer", re.I), "Null Pointer Dereference", "CWE-476"),
    (re.compile(r"runtime error:.*misaligned address", re.I), "Misaligned Address", "CWE-119"),
    (re.compile(r"runtime error:.*load of.*misaligned", re.I), "Misaligned Load", "CWE-119"),
]

SIGNAL_MAP = {
    134: "SIGABRT",
    139: "SIGSEGV",
    136: "SIGFPE",
    132: "SIGILL",
    1: "EXIT_ERROR",
    77: "SANITIZER_ABORT",
}


@dataclass
class SanitizerReport:
    crash_type: str
    cwe: str
    asan_summary: str
    raw_error: str


def classify_sanitizer_output(stderr: str) -> SanitizerReport:
    """Parse ASan/UBSan stderr and classify the vulnerability."""
    text = stderr or ""

    for key, (label, cwe) in CRASH_TYPE_MAP.items():
        if key in text:
            summary = _extract_summary_line(text, key)
            return SanitizerReport(
                crash_type=label,
                cwe=cwe,
                asan_summary=summary,
                raw_error=key,
            )

    for pattern, label, cwe in UBSAN_PATTERNS:
        if pattern.search(text):
            line = _first_matching_line(text, pattern)
            return SanitizerReport(
                crash_type=label,
                cwe=cwe,
                asan_summary=line,
                raw_error=label,
            )

    if "AddressSanitizer" in text or "ERROR:" in text:
        summary = _first_error_line(text)
        return SanitizerReport(
            crash_type="Memory Safety Violation",
            cwe="CWE-119",
            asan_summary=summary,
            raw_error="unknown-asan",
        )

    return SanitizerReport(
        crash_type="Unknown",
        cwe="CWE-Unknown",
        asan_summary="",
        raw_error="unknown",
    )


def map_to_cwe(crash_type: str) -> str:
    """Map crash type label back to CWE."""
    for _key, (label, cwe) in CRASH_TYPE_MAP.items():
        if label.lower() == crash_type.lower():
            return cwe
    for _pat, label, cwe in UBSAN_PATTERNS:
        if label.lower() == crash_type.lower():
            return cwe
    fallback = {
        "heap buffer overflow": "CWE-122",
        "stack buffer overflow": "CWE-121",
        "use-after-free": "CWE-416",
        "double free": "CWE-415",
    }
    return fallback.get(crash_type.lower(), "CWE-Unknown")


def signal_for_return_code(returncode: int) -> str:
    return SIGNAL_MAP.get(returncode, f"EXIT_{returncode}")


def _extract_summary_line(text: str, error_key: str) -> str:
    for line in text.splitlines():
        if error_key in line and "ERROR:" in line:
            return line.strip()
    return _first_error_line(text)


def _first_error_line(text: str) -> str:
    for line in text.splitlines():
        if "ERROR:" in line or "runtime error:" in line:
            return line.strip()
    return text.splitlines()[0].strip() if text.splitlines() else ""


def _first_matching_line(text: str, pattern: re.Pattern[str]) -> str:
    for line in text.splitlines():
        if pattern.search(line):
            return line.strip()
    return ""
