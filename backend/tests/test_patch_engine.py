"""Patch Engine Stage 5 tests — 3-Agent Arena, Attack Variants & Multi-Metric Scoring."""

import shutil
from pathlib import Path
import pytest

from vulndna.models import VulnDNAMatch
from workers.patch_engine.agents import generate_candidate_patches
from workers.patch_engine.attack_variants import generate_attack_variants
from workers.patch_engine.selector import evaluate_and_select_winner

FIXTURES = Path(__file__).parent / "fixtures"
VULN_SERVER = FIXTURES / "vulnerable_server"


def test_generate_attack_variants_count_and_types():
    variants = generate_attack_variants("A" * 512 + "\n")
    assert len(variants) == 9
    names = [v.name for v in variants]
    assert "original_poc" in names
    assert "truncated_half" in names
    assert "boundary_plus_one" in names
    assert "extreme_10k_buffer" in names
    assert "null_byte_probe" in names
    assert "ff_fill_buffer" in names
    assert "format_string_probe" in names
    assert "doubled_payload" in names
    assert "newline_burst" in names


def test_generate_3_patch_agents():
    matches = [
        VulnDNAMatch(
            cve_id="CVE-2021-3156",
            similarity=94.2,
            cwe="CWE-122",
            title="Sudo Baron Samedit",
            project="sudo",
            language="C",
            function="handle_request",
            vulnerable_code="strcpy(dst, src);",
            patch="strlcpy(dst, src, sizeof(dst));",
            fix_pattern="Bounded copy with length validation",
            why_it_works="Prevents buffer overflow",
        )
    ]
    candidates = generate_candidate_patches(
        source_root=VULN_SERVER,
        cwe="CWE-122",
        function_name="handle_request",
        file_rel_path="server.c",
        vulndna_matches=matches,
    )
    assert len(candidates) == 3
    agents = [c.agent for c in candidates]
    assert "Agent 1" in agents
    assert "Agent 2" in agents
    assert "Agent 3" in agents

    # Validate diff headers
    for c in candidates:
        assert "--- a/server.c" in c.diff
        assert "+++ b/server.c" in c.diff


@pytest.mark.integration
def test_patch_application_compilation_and_winner_selection(tmp_path):
    """
    Test patch sandbox application, compilation, attack variant replay,
    and winner selection against vulnerable_server fixture.
    Requires Clang on host.
    """
    if not shutil.which("clang"):
        pytest.skip("clang compiler not available on host")

    import sqlalchemy
    from db.models import Base, PatchCandidate, Scan, ScanStatus
    from db.session import SessionLocal, engine
    from workers.patch_engine.task import run_patch_engine_stage

    try:
        with engine.connect() as conn:
            conn.execute(sqlalchemy.text("SELECT 1"))
    except Exception:
        pytest.skip("PostgreSQL not available")

    Base.metadata.create_all(bind=engine)

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
        res = run_patch_engine_stage(scan_id, source_dir)
        assert len(res.candidates) == 3
        assert res.winner is not None
        assert res.winner.status == "SELECTED"
        assert res.winner.score_total >= 60.0
        assert res.winner.verification_passed is True
        assert res.winner.attacks_blocked == 9

        # Verify DB records
        patches_in_db = list(db.scalars(sqlalchemy.select(PatchCandidate).where(PatchCandidate.scan_id == scan.id)).all())
        assert len(patches_in_db) == 3
        winner_in_db = next((p for p in patches_in_db if p.status == "SELECTED"), None)
        assert winner_in_db is not None
        assert winner_in_db.score_total >= 60.0
        assert winner_in_db.attacks_blocked == 9

    finally:
        db.close()
