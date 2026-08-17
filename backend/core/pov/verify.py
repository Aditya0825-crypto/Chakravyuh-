"""PoV verification — replay crash input against ASan binary."""

from __future__ import annotations

import uuid
from pathlib import Path

from core.parsers.asan import classify_sanitizer_output, signal_for_return_code
from core.parsers.stack_trace import (
    extract_stack_trace,
    parse_primary_location,
    stack_hash,
)
from core.pov.models import PoVVerifyOptions, VerifiedPoV
from core.sandbox.docker_runner import CRASH_RETURN_CODES, run_binary_with_input
from core.scoring.confidence import ConfidenceInputs, calculate_confidence, severity_from_confidence


def verify_pov(
    crashing_input: bytes | str,
    target_binary: Path | str,
    *,
    options: PoVVerifyOptions | None = None,
) -> VerifiedPoV | None:
    """
    Replay crashing input against an ASan-instrumented binary.

    Returns VerifiedPoV on confirmed sanitizer crash, else None.
    """
    opts = options or PoVVerifyOptions()
    binary = Path(target_binary)
    work_dir = Path(opts.work_dir) if opts.work_dir else binary.parent

    if isinstance(crashing_input, str):
        input_bytes = crashing_input.encode("utf-8", errors="surrogateescape")
    else:
        input_bytes = crashing_input

    result = run_binary_with_input(
        binary,
        input_bytes,
        work_dir=work_dir,
        timeout_sec=opts.timeout_sec,
    )

    if result.timed_out or result.returncode not in CRASH_RETURN_CODES:
        return None

    report = classify_sanitizer_output(result.stderr)
    stack_trace = extract_stack_trace(result.stderr)
    dedup = stack_hash(stack_trace)

    if dedup in opts.seen_hashes:
        return None

    file, line, function = parse_primary_location(stack_trace, result.stderr)

    confidence = calculate_confidence(
        ConfidenceInputs(
            runtime_confirmed=True,
            reproducible=True,
            static_finding_match=opts.static_finding_match,
            stack_depth=len(stack_trace),
            has_source_location=line > 0,
            sanitizer_summary_present=bool(report.asan_summary),
            return_code_valid=True,
        )
    )

    pov_id = f"crash-{uuid.uuid4().hex[:8]}"
    return VerifiedPoV(
        id=pov_id,
        status="verified",
        type=report.crash_type,
        cwe=report.cwe,
        file=file,
        line=line,
        function=function,
        severity=severity_from_confidence(confidence, report.cwe),
        signal=signal_for_return_code(result.returncode),
        return_code=result.returncode,
        confidence=confidence,
        asan_summary=report.asan_summary,
        stack_trace=stack_trace,
        reproduced=True,
        dedup_hash=dedup,
        crash_input=crashing_input if isinstance(crashing_input, str) else crashing_input.decode(
            "utf-8", errors="replace"
        ),
        sanitizer_report=result.stderr[:8000],
    )


def verify_pov_from_stderr(
    stderr: str,
    *,
    return_code: int = 134,
    crashing_input: str = "",
    static_finding_match: bool = False,
) -> VerifiedPoV | None:
    """Build VerifiedPoV from captured ASan stderr (unit tests / offline triage)."""
    if return_code not in CRASH_RETURN_CODES:
        return None

    report = classify_sanitizer_output(stderr)
    stack_trace = extract_stack_trace(stderr)
    if not stack_trace and report.crash_type == "Unknown":
        return None

    file, line, function = parse_primary_location(stack_trace, stderr)
    dedup = stack_hash(stack_trace)
    confidence = calculate_confidence(
        ConfidenceInputs(
            runtime_confirmed=True,
            reproducible=True,
            static_finding_match=static_finding_match,
            stack_depth=len(stack_trace),
            has_source_location=line > 0,
            sanitizer_summary_present=bool(report.asan_summary),
            return_code_valid=True,
        )
    )

    return VerifiedPoV(
        id=f"crash-{uuid.uuid4().hex[:8]}",
        status="verified",
        type=report.crash_type,
        cwe=report.cwe,
        file=file,
        line=line,
        function=function,
        severity=severity_from_confidence(confidence, report.cwe),
        signal=signal_for_return_code(return_code),
        return_code=return_code,
        confidence=confidence,
        asan_summary=report.asan_summary,
        stack_trace=stack_trace,
        reproduced=True,
        dedup_hash=dedup,
        crash_input=crashing_input,
        sanitizer_report=stderr[:8000],
    )
