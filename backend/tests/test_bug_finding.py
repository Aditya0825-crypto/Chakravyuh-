"""Bug Finding Engine Stage 2 & PoV Verifier Stage 3 tests."""

import shutil
from pathlib import Path
import pytest

from workers.bug_finding.fuzz_runner import FuzzExecutionStats, _generate_initial_seeds, _mutate_seed
from workers.bug_finding.llm_runner import _generate_heuristic_payloads, CandidateCrashResult
from workers.bug_finding.static_runner import TargetCandidate, _extract_file_snippet

FIXTURES = Path(__file__).parent / "fixtures"
VULN_SERVER = FIXTURES / "vulnerable_server"
CLEAN_HELLO = FIXTURES / "clean_hello"


def test_extract_snippet_from_c_file():
    server_c = VULN_SERVER / "server.c"
    snippet = _extract_file_snippet(server_c, 8, window=4)
    assert "handle_request" in snippet
    assert "strcpy" in snippet


def test_generate_heuristic_payloads_for_strcpy():
    candidate = TargetCandidate(
        function="handle_request",
        file_path="src/server.c",
        line=8,
        risk="CRITICAL",
        sinks=["strcpy"],
    )
    payloads = _generate_heuristic_payloads(candidate)
    assert len(payloads) >= 4
    # Ensure buffer overflow payload exists
    names = [p[0] for p in payloads]
    assert any("overflow_512b" in n for n in names)
    assert any(len(p[1]) >= 512 for p in payloads)


def test_generate_heuristic_payloads_for_format_string():
    candidate = TargetCandidate(
        function="log_message",
        file_path="src/log.c",
        line=20,
        risk="HIGH",
        sinks=["sprintf"],
    )
    payloads = _generate_heuristic_payloads(candidate)
    assert any("format_probe" in p[0] or "overflow" in p[0] for p in payloads)


def test_fuzz_seed_generation_and_mutation():
    seeds = _generate_initial_seeds([])
    assert len(seeds) >= 5
    assert any(b"POST" in s or b"GET" in s for s in seeds)

    base = b"AAAA" * 8
    mutated = _mutate_seed(base)
    assert isinstance(mutated, bytes)
    assert len(mutated) > 0


@pytest.mark.integration
def test_end_to_end_bug_finding_and_pov_verification(tmp_path):
    """
    Test full Stage 2 Bug Finding + Stage 3 PoV Verification on vulnerable_server fixture.
    Requires Clang on host or container.
    """
    if not shutil.which("clang"):
        pytest.skip("clang compiler not available on host")

    import sqlalchemy
    from db.models import Base, Crash, FuzzRun, Scan, ScanStatus, VerifiedPoV
    from db.session import SessionLocal, engine
    from workers.bug_finding.orchestrator import run_bug_finding
    from workers.pov_verifier.task import run_pov_verifier

    try:
        with engine.connect() as conn:
            conn.execute(sqlalchemy.text("SELECT 1"))
    except Exception:
        pytest.skip("PostgreSQL not available")

    # Create tables
    Base.metadata.create_all(bind=engine)

    # Set up source workspace
    source_dir = tmp_path / "source"
    shutil.copytree(VULN_SERVER, source_dir)

    db = SessionLocal()
    scan = Scan(
        target_name="vulnerable_server",
        status=ScanStatus.RUNNING,
        artifact_root=str(tmp_path),
        file_count=1,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    scan_id = str(scan.id)

    try:
        # 1. Run Bug Finding (Stage 2)
        bf_res = run_bug_finding(scan_id, source_dir)
        assert bf_res.compiled_binary is not None
        assert len(bf_res.crashes) >= 1
        assert any("Heap Buffer Overflow" in c.crash_type or "CWE-122" in c.cwe for c in bf_res.crashes)

        # Verify DB records
        crashes_in_db = list(db.scalars(sqlalchemy.select(Crash).where(Crash.scan_id == scan.id)).all())
        assert len(crashes_in_db) >= 1
        fuzz_in_db = db.scalars(sqlalchemy.select(FuzzRun).where(FuzzRun.scan_id == scan.id)).first()
        assert fuzz_in_db is not None
        assert fuzz_in_db.crashes_found >= 1

        # 2. Run PoV Verification (Stage 3)
        pov_res = run_pov_verifier(scan_id, source_dir)
        assert pov_res.verified_count >= 1

        # Verify VerifiedPoV records
        povs_in_db = list(db.scalars(sqlalchemy.select(VerifiedPoV).where(VerifiedPoV.scan_id == scan.id)).all())
        assert len(povs_in_db) >= 1
        assert povs_in_db[0].cwe in ("CWE-122", "CWE-121", "CWE-416")
        assert povs_in_db[0].confidence >= 60

    finally:
        db.close()
