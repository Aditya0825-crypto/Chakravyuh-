"""Recon Engine Phase 3 tests."""

from pathlib import Path

import pytest

from core.parsers.semgrep import run_semgrep
from recon.call_graph import extract_call_graph
from recon.engine import run_recon
from recon.path_map import build_path_map
from recon.ranker import rank_targets

FIXTURES = Path(__file__).parent / "fixtures"
VULN_SERVER = FIXTURES / "vulnerable_server"
CLEAN_HELLO = FIXTURES / "clean_hello"


def test_call_graph_extracts_functions():
    functions = extract_call_graph(VULN_SERVER)
    assert "handle_request" in functions
    assert "main" in functions
    assert "strcpy" in functions["handle_request"].sinks


def test_call_graph_detects_input_sources():
    functions = extract_call_graph(VULN_SERVER)
    assert "getline" in functions["main"].calls
    assert any("stdin" in s for s in functions["main"].input_sources)


def test_semgrep_fallback_finds_strcpy():
    findings = run_semgrep(VULN_SERVER)
    assert len(findings) >= 1
    assert any("strcpy" in f.code_snippet or "strcpy" in f.rule for f in findings)


def test_path_map_main_to_handle_request():
    functions = extract_call_graph(VULN_SERVER)
    entries = build_path_map(functions)
    hr = next(e for e in entries if e.function == "handle_request")
    assert "strcpy" in hr.sinks
    assert "main" in hr.call_path
    assert hr.reachable_from_main


def test_ranker_prioritizes_handle_request():
    functions = extract_call_graph(VULN_SERVER)
    entries = build_path_map(functions)
    findings = run_semgrep(VULN_SERVER)
    ranked = rank_targets(entries, findings)
    assert ranked[0].function == "handle_request"
    assert ranked[0].score >= 60
    assert ranked[0].risk in ("CRITICAL", "HIGH")


def test_clean_hello_no_critical_targets():
    functions = extract_call_graph(CLEAN_HELLO)
    entries = build_path_map(functions)
    findings = run_semgrep(CLEAN_HELLO)
    ranked = rank_targets(entries, findings)
    critical = [t for t in ranked if t.risk in ("CRITICAL", "HIGH")]
    assert len(critical) == 0


@pytest.mark.integration
def test_run_recon_persists(tmp_path):
    """Full recon run — requires PostgreSQL (run in WSL)."""
    import sqlalchemy
    from core.config import get_settings
    from db.models import Base, ReconTarget, Scan, ScanStatus, StaticFinding
    from db.session import SessionLocal, engine

    try:
        with engine.connect() as conn:
            conn.execute(sqlalchemy.text("SELECT 1"))
    except Exception:
        pytest.skip("PostgreSQL not available")

    import shutil

    source = tmp_path / "source"
    shutil.copytree(VULN_SERVER, source)

    db = SessionLocal()
    scan = Scan(
        target_name="vulnerable_server",
        status=ScanStatus.QUEUED,
        artifact_root=str(tmp_path),
        file_count=1,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    try:
        result = run_recon(str(scan.id), source)
        assert result.functions_mapped >= 2
        assert result.findings_count >= 1
        assert result.targets[0].function == "handle_request"

        targets = db.query(ReconTarget).filter(ReconTarget.scan_id == scan.id).all()
        findings = db.query(StaticFinding).filter(StaticFinding.scan_id == scan.id).all()
        assert len(targets) >= 2
        assert len(findings) >= 1
    finally:
        db.query(ReconTarget).filter(ReconTarget.scan_id == scan.id).delete()
        db.query(StaticFinding).filter(StaticFinding.scan_id == scan.id).delete()
        db.query(Scan).filter(Scan.id == scan.id).delete()
        db.commit()
        db.close()
