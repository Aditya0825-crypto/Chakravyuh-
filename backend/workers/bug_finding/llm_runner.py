"""LLM-directed vulnerability researcher and PoC exploit runner."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from core.llm.client import generate, ollama_available
from core.llm.prompts import BUG_FINDING_EXPLOIT_PROMPT, BUG_FINDING_EXPLOIT_SYSTEM
from core.parsers.asan import classify_sanitizer_output, signal_for_return_code
from core.parsers.stack_trace import extract_stack_trace, stack_hash
from core.sandbox.docker_runner import SandboxResult, run_binary_with_input
from core.scoring.confidence import ConfidenceInputs, calculate_confidence
from workers.bug_finding.static_runner import TargetCandidate


@dataclass
class CandidateCrashResult:
    crash_type: str
    cwe: str
    file: str
    line: int
    function: str
    severity: str
    signal: str
    return_code: int
    confidence: int
    asan_summary: str
    stack_trace: list[str]
    stack_hash: str
    crash_input: str
    discovery_method: str = "llm_directed"
    stderr: str = ""


def generate_and_test_candidate_pocs(
    candidate: TargetCandidate,
    asan_binary: Path,
    work_dir: Path,
    timeout_sec: int = 10,
) -> list[CandidateCrashResult]:
    """
    Generate PoC inputs targeting a candidate function/sink and execute them against
    the ASan-instrumented binary. Returns all verified crashes produced.
    """
    crashes: list[CandidateCrashResult] = []
    payloads = _generate_poc_payloads(candidate)

    for p_name, p_bytes, p_str in payloads:
        res: SandboxResult = run_binary_with_input(
            asan_binary,
            p_bytes,
            work_dir=work_dir,
            timeout_sec=timeout_sec,
        )

        if res.crashed and res.stderr:
            crash = _process_sandbox_crash(res, candidate, p_str, discovery_method="llm_directed")
            if crash:
                crashes.append(crash)

    return crashes


def _generate_poc_payloads(candidate: TargetCandidate) -> list[tuple[str, bytes, str]]:
    """
    Returns a list of tuples: (name, payload_bytes, payload_str_representation).
    Tries Ollama first if available, then supplements with heuristic payloads.
    """
    payloads: list[tuple[str, bytes, str]] = []

    # 1. Try Ollama LLM generation if available
    if ollama_available():
        llm_payloads = _try_llm_payload_gen(candidate)
        payloads.extend(llm_payloads)

    # 2. Add boundary & pattern heuristic payloads
    heuristic_payloads = _generate_heuristic_payloads(candidate)
    payloads.extend(heuristic_payloads)

    return payloads


def _try_llm_payload_gen(candidate: TargetCandidate) -> list[tuple[str, bytes, str]]:
    prompt = BUG_FINDING_EXPLOIT_PROMPT.format(
        function_name=candidate.function,
        sinks=", ".join(candidate.sinks) if candidate.sinks else "none",
        rule=candidate.rule,
        code_snippet=candidate.code_snippet or "(no code snippet available)",
        call_path=candidate.call_path or "main -> " + candidate.function,
    )
    try:
        raw_resp = generate(prompt, system=BUG_FINDING_EXPLOIT_SYSTEM, temperature=0.2)
        # Clean potential markdown wrapping
        cleaned = raw_resp.strip()
        if cleaned.startswith("```json"):
            cleaned = cleaned[7:]
        if cleaned.startswith("```"):
            cleaned = cleaned[3:]
        if cleaned.endswith("```"):
            cleaned = cleaned[:-3]
        cleaned = cleaned.strip()

        data = json.loads(cleaned)
        if isinstance(data, list):
            results = []
            for item in data:
                name = item.get("payload_name", "llm_payload")
                p_type = item.get("payload_type", "text")
                prefix = item.get("prefix", "")
                suffix = item.get("suffix", "\n")

                if p_type == "repeated":
                    char = item.get("char", "A")
                    count = int(item.get("count", 512))
                    content = prefix + (char * count) + suffix
                else:
                    raw_content = item.get("payload_content", item.get("content", ""))
                    content = prefix + str(raw_content) + suffix

                b_content = content.encode("utf-8", errors="replace")
                results.append((name, b_content, content))
            return results
    except Exception:
        pass
    return []


def _generate_heuristic_payloads(candidate: TargetCandidate) -> list[tuple[str, bytes, str]]:
    """Generate high-yield boundary and memory safety trigger payloads."""
    results: list[tuple[str, bytes, str]] = []
    sinks_lower = [s.lower() for s in candidate.sinks]

    # Large buffer overflow payloads (for strcpy, strcat, gets, sprintf, memcpy, etc.)
    if any(s in sinks_lower for s in ["strcpy", "strcat", "gets", "sprintf", "vsprintf", "memcpy", "read", "getline"]):
        for size in [256, 512, 1024, 4096]:
            content = "A" * size + "\n"
            results.append((f"overflow_{size}b", content.encode("ascii"), content))

        # With HTTP or command prefixes
        for size in [256, 512]:
            content = f"POST /api/v1 HTTP/1.1\r\nContent-Length: {size}\r\n\r\n" + ("A" * size) + "\n"
            results.append((f"http_overflow_{size}b", content.encode("ascii"), content))

        # Off-by-one / null byte variations
        results.append(("null_prefix_long", b"\x00" + b"A" * 512 + b"\n", "\\x00" + "A" * 512 + "\\n"))

    # Format string probes
    if any(s in sinks_lower for s in ["printf", "fprintf", "sprintf", "snprintf", "syslog"]):
        for pattern in ["%s%s%s%s%s%s%s%s\n", "%x%x%x%x%x%x%x%x\n", "%n%n%n%n\n"]:
            results.append(("format_probe", pattern.encode("ascii"), pattern))

    # Command injection probes
    if any(s in sinks_lower for s in ["system", "popen", "exec", "execl", "execve"]):
        for cmd in ["; /bin/sh -c 'exit 134'\n", "| sleep 0\n", "`id`\n"]:
            results.append(("cmd_probe", cmd.encode("ascii"), cmd))

    # Standard fallback boundary probes for any C target
    if not results:
        results.append(("standard_overflow_512b", (b"A" * 512) + b"\n", "A" * 512 + "\n"))
        results.append(("standard_boundary_large", (b"B" * 2048) + b"\n", "B" * 2048 + "\n"))

    return results


def _process_sandbox_crash(
    res: SandboxResult,
    candidate: TargetCandidate,
    crash_input_str: str,
    discovery_method: str,
) -> CandidateCrashResult | None:
    san_report = classify_sanitizer_output(res.stderr)
    stack_frames = extract_stack_trace(res.stderr)
    shash = stack_hash(stack_frames)
    sig = signal_for_return_code(res.returncode)

    file_loc = candidate.file_path
    line_loc = candidate.line
    func_loc = candidate.function

    # Try to extract exact source location from stack frames if available
    for frame in stack_frames:
        if ":" in frame and "(" in frame:
            parts = frame.split("(")
            if len(parts) > 1:
                loc = parts[1].rstrip(")")
                if ":" in loc:
                    f_name, l_num = loc.split(":", 1)
                    if l_num.isdigit():
                        file_loc = f_name.strip()
                        line_loc = int(l_num)
                        func_loc = parts[0].strip()
                        break

    confidence = calculate_confidence(
        ConfidenceInputs(
            runtime_confirmed=True,
            reproducible=True,
            static_finding_match=bool(candidate.sinks),
            stack_depth=len(stack_frames),
            has_source_location=line_loc > 0,
            sanitizer_summary_present=bool(san_report.asan_summary),
            return_code_valid=res.crashed,
        )
    )

    return CandidateCrashResult(
        crash_type=san_report.crash_type,
        cwe=san_report.cwe,
        file=file_loc,
        line=line_loc,
        function=func_loc,
        severity="CRITICAL" if "Buffer Overflow" in san_report.crash_type or "Use-After-Free" in san_report.crash_type else "HIGH",
        signal=sig,
        return_code=res.returncode,
        confidence=confidence,
        asan_summary=san_report.asan_summary or f"{san_report.crash_type} detected",
        stack_trace=stack_frames,
        stack_hash=shash,
        crash_input=crash_input_str,
        discovery_method=discovery_method,
        stderr=res.stderr,
    )
