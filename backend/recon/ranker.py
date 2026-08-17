"""Risk ranking — LLM via Ollama with heuristic fallback."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

from core.llm.client import OllamaError, generate, ollama_available
from core.llm.prompts import RECON_RANK_PROMPT, RECON_RANK_SYSTEM
from core.parsers.semgrep import StaticFindingResult
from recon.path_map import PathMapEntry


@dataclass
class RankedTarget:
    function: str
    file: str
    line: int
    risk: str
    reason: str
    score: int
    sinks: list[str]
    call_path: str
    input_sources: list[str]


SEVERITY_SCORE = {"ERROR": 30, "WARNING": 15, "INFO": 5}
RISK_FROM_SCORE = [(85, "CRITICAL"), (65, "HIGH"), (40, "MEDIUM"), (0, "LOW")]


def rank_targets(
    path_entries: list[PathMapEntry],
    findings: list[StaticFindingResult],
) -> list[RankedTarget]:
    """Rank recon targets — LLM if available, else heuristic."""
    if not path_entries:
        return _rank_all_functions_heuristic(findings)

    if ollama_available():
        try:
            return _rank_with_llm(path_entries, findings)
        except OllamaError:
            pass

    return _rank_heuristic(path_entries, findings)


def _rank_with_llm(
    path_entries: list[PathMapEntry],
    findings: list[StaticFindingResult],
) -> list[RankedTarget]:
    payload = [
        {
            "function": e.function,
            "file": e.file,
            "line": e.line,
            "sinks": e.sinks,
            "call_path": e.call_path,
            "input_sources": e.input_sources,
            "semgrep_hits": sum(1 for f in findings if e.function in f.file or _fn_in_snippet(e.function, f)),
        }
        for e in path_entries
    ]
    prompt = RECON_RANK_PROMPT.format(targets_json=json.dumps(payload, indent=2))
    raw = generate(prompt, system=RECON_RANK_SYSTEM)
    parsed = _parse_llm_json(raw)

    ranked: list[RankedTarget] = []
    entry_map = {e.function: e for e in path_entries}
    for item in parsed:
        fn = item.get("function", "")
        entry = entry_map.get(fn)
        if not entry:
            continue
        ranked.append(
            RankedTarget(
                function=fn,
                file=entry.file,
                line=entry.line,
                risk=item.get("risk", "MEDIUM").upper(),
                reason=item.get("reason", "LLM ranked"),
                score=int(item.get("score", 50)),
                sinks=entry.sinks,
                call_path=entry.call_path,
                input_sources=entry.input_sources,
            )
        )

    if ranked:
        return sorted(ranked, key=lambda t: t.score, reverse=True)
    return _rank_heuristic(path_entries, findings)


def _rank_heuristic(
    path_entries: list[PathMapEntry],
    findings: list[StaticFindingResult],
) -> list[RankedTarget]:
    ranked: list[RankedTarget] = []
    for entry in path_entries:
        score = _heuristic_score(entry, findings)
        risk = _score_to_risk(score)
        reason = _heuristic_reason(entry, findings)
        ranked.append(
            RankedTarget(
                function=entry.function,
                file=entry.file,
                line=entry.line,
                risk=risk,
                reason=reason,
                score=score,
                sinks=entry.sinks,
                call_path=entry.call_path,
                input_sources=entry.input_sources,
            )
        )
    return sorted(ranked, key=lambda t: t.score, reverse=True)


def _rank_all_functions_heuristic(findings: list[StaticFindingResult]) -> list[RankedTarget]:
    """When no sinks in call graph, rank from semgrep findings only."""
    by_fn: dict[str, list[StaticFindingResult]] = {}
    for f in findings:
        key = f.file
        by_fn.setdefault(key, []).append(f)

    ranked: list[RankedTarget] = []
    for file, file_findings in by_fn.items():
        score = sum(SEVERITY_SCORE.get(f.severity, 10) for f in file_findings)
        score = min(100, score + 20)
        ranked.append(
            RankedTarget(
                function=file.split("/")[-1],
                file=file,
                line=file_findings[0].line,
                risk=_score_to_risk(score),
                reason=file_findings[0].message,
                score=score,
                sinks=_sinks_from_findings(file_findings),
                call_path="unknown",
                input_sources=["unknown input"],
            )
        )
    return sorted(ranked, key=lambda t: t.score, reverse=True)


def _heuristic_score(entry: PathMapEntry, findings: list[StaticFindingResult]) -> int:
    score = len(entry.sinks) * 20
    if entry.reachable_from_main:
        score += 15
    if entry.input_sources and entry.input_sources != ["unknown input"]:
        score += 15
    for f in findings:
        if f.file == entry.file or entry.function in (f.code_snippet or ""):
            score += SEVERITY_SCORE.get(f.severity, 10)
    critical_sinks = {"strcpy", "gets", "sprintf", "system"}
    if critical_sinks & set(entry.sinks):
        score += 20
    return min(100, max(10, score))


def _heuristic_reason(entry: PathMapEntry, findings: list[StaticFindingResult]) -> str:
    parts: list[str] = []
    if entry.sinks:
        parts.append(" + ".join(entry.sinks))
    if entry.input_sources and entry.input_sources != ["unknown input"]:
        parts.append(" + ".join(entry.input_sources))
    if entry.reachable_from_main:
        parts.append("reachable sink")
    file_findings = [f for f in findings if f.file == entry.file]
    if file_findings:
        parts.append(file_findings[0].message.split("—")[0].strip())
    return " + ".join(parts) if parts else "no dangerous patterns"


def _score_to_risk(score: int) -> str:
    for threshold, risk in RISK_FROM_SCORE:
        if score >= threshold:
            return risk
    return "LOW"


def _sinks_from_findings(findings: list[StaticFindingResult]) -> list[str]:
    sinks: set[str] = set()
    for f in findings:
        for sink in ("strcpy", "sprintf", "gets", "system", "memcpy"):
            if sink in f.code_snippet or sink in f.rule:
                sinks.add(sink)
    return sorted(sinks)


def _fn_in_snippet(fn: str, finding: StaticFindingResult) -> bool:
    return fn in (finding.code_snippet or "")


def _parse_llm_json(raw: str) -> list[dict]:
    match = re.search(r"\[[\s\S]*\]", raw)
    if not match:
        return []
    try:
        data = json.loads(match.group())
        return data if isinstance(data, list) else []
    except json.JSONDecodeError:
        return []
