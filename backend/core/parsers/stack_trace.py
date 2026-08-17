"""Stack trace extraction and deduplication hashing."""

import hashlib
import re

# ASan native: #1 0xADDR in handle_request server.c:8
FRAME_RE_ASAN = re.compile(
    r"#(\d+)\s+(?:0x[0-9a-fA-F]+\s+)?in\s+(\S+)\s+(\S+\.(?:c|cpp|cc|cxx|h|hpp):(\d+))",
)
# Parenthesized: #1 0xADDR in func (file:line) or func (/lib/...)
FRAME_RE_PARENS = re.compile(
    r"#(\d+)\s+(?:0x[0-9a-fA-F]+\s+)?(?:in\s+)?(\S+)\s+\(([^)]+)\)",
)
# file:line anywhere
FILE_LINE_RE = re.compile(r"(\S+\.(?:c|cpp|cc|cxx|h|hpp)):(\d+)")
# SUMMARY: AddressSanitizer: heap-buffer-overflow server.c:8 in handle_request
SUMMARY_RE = re.compile(
    r"SUMMARY:.*?(\S+\.(?:c|cpp|cc|cxx|h|hpp):(\d+))\s+in\s+(\S+)",
)


def extract_stack_trace(stderr: str) -> list[str]:
    """Extract human-readable stack frames from sanitizer output."""
    frames: list[str] = []
    seen: set[str] = set()

    for line in stderr.splitlines():
        line = line.strip()
        if not line.startswith("#"):
            continue

        label = _parse_frame_line(line)
        if label and label not in seen:
            seen.add(label)
            frames.append(label)

    if not frames:
        for line in stderr.splitlines():
            for match in FILE_LINE_RE.finditer(line):
                label = f"{match.group(1)}:{match.group(2)}"
                if label not in seen:
                    seen.add(label)
                    frames.append(label)

    return frames


def parse_primary_location(stack_trace: list[str], stderr: str) -> tuple[str, int, str]:
    """Return (file, line, function) from stack trace or stderr."""
    for frame in stack_trace:
        func, file, line = _parse_frame(frame)
        if file and line:
            return file, line, func

    summary = SUMMARY_RE.search(stderr)
    if summary:
        file_line = summary.group(1)
        func = summary.group(3)
        m = FILE_LINE_RE.match(file_line)
        if m:
            fn = func if func.endswith(")") else f"{func}()"
            return m.group(1), int(m.group(2)), fn

    for line in stderr.splitlines():
        m = FILE_LINE_RE.search(line)
        if m and "SUMMARY" not in line:
            return m.group(1), int(m.group(2)), "unknown()"

    return "unknown.c", 0, "unknown()"


def normalize_stack_trace(stack_trace: list[str]) -> str:
    """Normalize stack for dedup — strip ASan/runtime frames and addresses."""
    cleaned: list[str] = []
    skip_prefixes = ("__asan", "__interceptor", "_start", "__libc")

    for frame in stack_trace:
        func, file, line = _parse_frame(frame)
        if any(func.startswith(p) for p in skip_prefixes):
            continue
        if "libasan" in frame or "libc.so" in frame:
            continue
        loc = f"{file}:{line}" if file and line else ""
        cleaned.append(f"{func}|{loc}")

    return "|".join(cleaned)


def stack_hash(stack_trace: list[str]) -> str:
    normalized = normalize_stack_trace(stack_trace)
    return hashlib.sha256(normalized.encode()).hexdigest()[:16]


def _parse_frame_line(line: str) -> str | None:
    m = FRAME_RE_ASAN.search(line)
    if m:
        func, file, line_no = m.group(2), m.group(3).rsplit(":", 1)[0], m.group(4)
        if not func.startswith("__asan"):
            return f"{func} ({file}:{line_no})"

    m = FRAME_RE_PARENS.match(line)
    if m:
        func, loc = m.group(2), m.group(3)
        if func.startswith("__asan") or func.startswith("__interceptor"):
            return f"{func} ({loc})"
        if FILE_LINE_RE.search(loc):
            return f"{func} ({loc})"
        return func

    return None


def _parse_frame(frame: str) -> tuple[str, str, int]:
    func = frame.split("(")[0].strip()
    loc = ""
    if "(" in frame and ")" in frame:
        loc = frame.split("(", 1)[1].rsplit(")", 1)[0]

    m = FILE_LINE_RE.search(loc or frame)
    if m:
        fn = func if func.endswith(")") else f"{func}()"
        return fn, m.group(1), int(m.group(2))

    return func if func.endswith(")") else f"{func}()", "", 0
