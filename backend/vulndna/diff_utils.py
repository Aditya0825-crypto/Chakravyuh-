"""Patch diff and fix-pattern helpers."""

import difflib
import re


def unified_diff(before: str, after: str, filename: str = "file.c") -> str:
    before_lines = (before or "").splitlines()
    after_lines = (after or "").splitlines()
    diff_lines = difflib.unified_diff(
        before_lines,
        after_lines,
        fromfile=f"a/{filename}",
        tofile=f"b/{filename}",
        lineterm="",
    )
    return "\n".join(diff_lines)


def compact_patch(before: str, after: str, max_lines: int = 12) -> str:
    """Produce a short +/- patch snippet for UI display."""
    before_lines = (before or "").splitlines()
    after_lines = (after or "").splitlines()
    out: list[str] = []
    for i, (b, a) in enumerate(zip(before_lines, after_lines)):
        if b != a:
            out.append(f"- {b}")
            out.append(f"+ {a}")
        if len(out) >= max_lines:
            break
    if not out and before_lines != after_lines:
        if before_lines:
            out.append(f"- {before_lines[0][:120]}")
        if after_lines:
            out.append(f"+ {after_lines[0][:120]}")
    return "\n".join(out) if out else unified_diff(before, after)[:800]


def infer_fix_pattern(before: str, after: str, description: str = "") -> str:
    text = f"{before}\n{after}\n{description}".lower()
    rules = [
        (r"strcpy", "Replace strcpy with bounded copy (strlcpy/strncpy) + explicit length check"),
        (r"sprintf", "Replace sprintf with snprintf and bound format output"),
        (r"gets\s*\(", "Remove gets(); use fgets with explicit buffer size"),
        (r"memcpy", "Validate length before memcpy against destination size"),
        (r"strcat", "Replace strcat with strncat or bounded concatenation"),
        (r"alloca|malloc|realloc", "Validate allocation size and handle overflow/null"),
        (r"free\s*\(", "Ensure pointer nullification / remove use-after-free path"),
        (r"snprintf|strlcpy|strnlen", "Enforce bounds-checked write before memory access"),
    ]
    for pattern, fix in rules:
        if re.search(pattern, text):
            return fix
    if before.strip() and after.strip() and before.strip() != after.strip():
        return "Add input validation and bounds checking at vulnerable sink"
    return "Apply minimal patch validated against sanitizer crash path"


def extract_function_name(method_name: str | None, code: str) -> str:
    if method_name:
        return method_name if method_name.endswith(")") else f"{method_name}()"
    match = re.search(r"(\w+)\s*\([^)]*\)\s*\{", code or "")
    return f"{match.group(1)}()" if match else "unknown()"


def truncate_code(code: str, max_len: int = 600) -> str:
    code = (code or "").strip()
    if len(code) <= max_len:
        return code
    return code[: max_len - 3] + "..."
