"""Static analysis runner for Bug Finding — gathers Recon targets and Semgrep findings."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Sequence
import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from db.models import ReconTarget, StaticFinding


@dataclass
class TargetCandidate:
    function: str
    file_path: str
    line: int
    risk: str
    sinks: list[str] = field(default_factory=list)
    rule: str = ""
    code_snippet: str = ""
    call_path: str = ""
    input_sources: list[str] = field(default_factory=list)
    score: int = 0


def collect_target_candidates(db: Session, scan_id: str, source_root: Path) -> list[TargetCandidate]:
    """
    Read ReconTarget and StaticFinding records from DB for the given scan_id
    and pair them with code snippets from the source tree.
    """
    scan_uuid = uuid.UUID(scan_id)

    # 1. Fetch recon targets
    recon_stmt = (
        select(ReconTarget)
        .where(ReconTarget.scan_id == scan_uuid)
        .order_by(ReconTarget.score.desc(), ReconTarget.rank.asc())
    )
    recon_targets = list(db.scalars(recon_stmt).all())

    # 2. Fetch static findings
    static_stmt = (
        select(StaticFinding)
        .where(StaticFinding.scan_id == scan_uuid)
    )
    static_findings = list(db.scalars(static_stmt).all())

    findings_by_file: dict[str, list[StaticFinding]] = {}
    for f in static_findings:
        findings_by_file.setdefault(Path(f.file).name, []).append(f)

    candidates: list[TargetCandidate] = []

    for rt in recon_targets:
        file_name = Path(rt.file).name
        matched_finding = None
        for f in findings_by_file.get(file_name, []):
            if abs(f.line - rt.line) <= 15 or any(sink in f.rule.lower() for sink in (rt.sinks or [])):
                matched_finding = f
                break

        snippet = ""
        if matched_finding and matched_finding.code_snippet:
            snippet = matched_finding.code_snippet
        else:
            # Extract snippet around line from disk
            resolved_file = _find_file(source_root, rt.file)
            if resolved_file and resolved_file.is_file():
                snippet = _extract_file_snippet(resolved_file, rt.line)

        candidates.append(
            TargetCandidate(
                function=rt.function,
                file_path=rt.file,
                line=rt.line,
                risk=rt.risk,
                sinks=rt.sinks or [],
                rule=matched_finding.rule if matched_finding else "heuristic.recon.sink",
                code_snippet=snippet,
                call_path=rt.call_path or "",
                input_sources=rt.input_sources or [],
                score=rt.score,
            )
        )

    return candidates


def _find_file(source_root: Path, file_path_str: str) -> Path | None:
    candidate = source_root / file_path_str
    if candidate.is_file():
        return candidate

    # Search by basename
    base_name = Path(file_path_str).name
    matches = list(source_root.glob(f"**/{base_name}"))
    if matches:
        return matches[0]
    return None


def _extract_file_snippet(file_path: Path, center_line: int, window: int = 10) -> str:
    try:
        lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
        start = max(0, center_line - window - 1)
        end = min(len(lines), center_line + window)
        return "\n".join(lines[start:end])
    except Exception:
        return ""
