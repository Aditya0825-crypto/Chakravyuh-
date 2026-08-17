"""Stage 1 Recon Engine orchestrator."""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from pathlib import Path

from core.parsers.semgrep import run_semgrep
from db.models import ReconTarget, StaticFinding
from db.session import SessionLocal
from recon.call_graph import extract_call_graph
from recon.path_map import build_path_map
from recon.ranker import RankedTarget, rank_targets


@dataclass
class ReconResult:
    targets: list[RankedTarget]
    findings_count: int
    functions_mapped: int
    files_parsed: int
    duration_sec: float


def run_recon(scan_id: str, source_dir: Path) -> ReconResult:
    """Execute full recon pipeline and persist results."""
    start = time.perf_counter()
    source_dir = source_dir.resolve()

    functions = extract_call_graph(source_dir)
    findings = run_semgrep(source_dir)
    path_entries = build_path_map(functions)
    ranked = rank_targets(path_entries, findings)

    # Include low-risk functions not in path map for completeness
    ranked_names = {t.function for t in ranked}
    for name, info in functions.items():
        if name not in ranked_names and not info.sinks:
            ranked.append(
                RankedTarget(
                    function=name,
                    file=info.file,
                    line=info.line,
                    risk="LOW",
                    reason="no dangerous patterns",
                    score=15,
                    sinks=[],
                    call_path=f"{name}()",
                    input_sources=sorted(info.input_sources) or ["none"],
                )
            )

    ranked = sorted(ranked, key=lambda t: t.score, reverse=True)
    duration = time.perf_counter() - start

    _persist(scan_id, ranked, findings)

    files_parsed = len({f.file for f in functions.values()})
    return ReconResult(
        targets=ranked,
        findings_count=len(findings),
        functions_mapped=len(functions),
        files_parsed=files_parsed,
        duration_sec=duration,
    )


def _persist(scan_id: str, targets: list[RankedTarget], findings) -> None:
    db = SessionLocal()
    try:
        scan_uuid = uuid.UUID(scan_id)
        db.query(ReconTarget).filter(ReconTarget.scan_id == scan_uuid).delete()
        db.query(StaticFinding).filter(StaticFinding.scan_id == scan_uuid).delete()

        for rank, t in enumerate(targets, start=1):
            db.add(
                ReconTarget(
                    scan_id=scan_uuid,
                    function=f"{t.function}()" if not t.function.endswith(")") else t.function,
                    file=t.file,
                    line=t.line,
                    risk=t.risk,
                    reason=t.reason,
                    sinks=t.sinks,
                    call_path=t.call_path,
                    input_sources=t.input_sources,
                    score=t.score,
                    rank=rank,
                )
            )

        for f in findings:
            db.add(
                StaticFinding(
                    scan_id=scan_uuid,
                    rule=f.rule,
                    file=f.file,
                    line=f.line,
                    severity=f.severity,
                    message=f.message,
                    code_snippet=f.code_snippet,
                )
            )

        db.commit()
    finally:
        db.close()
