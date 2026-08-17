"""Semgrep integration + regex fallback for static findings."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass
class StaticFindingResult:
    rule: str
    file: str
    line: int
    severity: str
    message: str
    code_snippet: str


FALLBACK_PATTERNS: list[tuple[str, str, str, re.Pattern[str]]] = [
    (
        "c.lang.security.insecure-use-strcpy",
        "ERROR",
        "Dangerous use of strcpy() — buffer overflow possible",
        re.compile(r"\bstrcpy\s*\("),
    ),
    (
        "c.lang.security.insecure-use-sprintf",
        "ERROR",
        "sprintf() with potentially unbounded output",
        re.compile(r"\bsprintf\s*\("),
    ),
    (
        "c.lang.security.insecure-use-gets",
        "ERROR",
        "gets() is always unsafe",
        re.compile(r"\bgets\s*\("),
    ),
    (
        "c.lang.security.system-call",
        "WARNING",
        "system() called — command injection risk",
        re.compile(r"\bsystem\s*\("),
    ),
    (
        "c.lang.security.insecure-use-memcpy",
        "WARNING",
        "memcpy() — verify bounds on length argument",
        re.compile(r"\bmemcpy\s*\("),
    ),
]

SOURCE_EXTS = {".c", ".h", ".cpp", ".cc", ".cxx", ".hpp"}


def run_semgrep(target_dir: Path) -> list[StaticFindingResult]:
    """Run Semgrep security-audit rules; fall back to regex if unavailable."""
    if shutil.which("semgrep"):
        results = _run_semgrep_cli(target_dir)
        if results is not None:
            return results
    return _regex_fallback_scan(target_dir)


def _run_semgrep_cli(target_dir: Path) -> list[StaticFindingResult] | None:
    cmd = [
        "semgrep",
        "--config=p/security-audit",
        "--config=p/owasp-top-ten",
        "--json",
        "--quiet",
        str(target_dir),
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None

    if proc.returncode not in (0, 1):
        return None

    try:
        data = json.loads(proc.stdout or "{}")
    except json.JSONError:
        return None

    findings: list[StaticFindingResult] = []
    for item in data.get("results", []):
        extra = item.get("extra", {})
        findings.append(
            StaticFindingResult(
                rule=item.get("check_id", "semgrep.unknown"),
                file=_normalize_path(item.get("path", ""), target_dir),
                line=item.get("start", {}).get("line", 0),
                severity=extra.get("severity", "WARNING").upper(),
                message=extra.get("message", item.get("check_id", "")),
                code_snippet=(extra.get("lines", "") or "").strip(),
            )
        )
    return findings


def _regex_fallback_scan(target_dir: Path) -> list[StaticFindingResult]:
    findings: list[StaticFindingResult] = []
    for path in sorted(target_dir.rglob("*")):
        if path.suffix.lower() not in SOURCE_EXTS or not path.is_file():
            continue
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        rel = _normalize_path(str(path), target_dir)
        for i, line in enumerate(lines, start=1):
            for rule, severity, message, pattern in FALLBACK_PATTERNS:
                if pattern.search(line):
                    findings.append(
                        StaticFindingResult(
                            rule=rule,
                            file=rel,
                            line=i,
                            severity=severity,
                            message=message,
                            code_snippet=line.strip(),
                        )
                    )
    return findings


def _normalize_path(path_str: str, root: Path) -> str:
    p = Path(path_str)
    try:
        return str(p.relative_to(root)).replace("\\", "/")
    except ValueError:
        return p.name
