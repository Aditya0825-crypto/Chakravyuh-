"""VulnDNA Phase 2 tests."""

import json
from pathlib import Path

import pytest

from vulndna.diff_utils import infer_fix_pattern, unified_diff
from vulndna.ingest_cvefixes import ingest_seed, load_seed_entries
from vulndna.models import VulnDNAQuery
from vulndna.query import search_vulndna

FIXTURE = Path(__file__).parent / "fixtures" / "known_cve_sample" / "heap_overflow_pov.json"


def test_seed_corpus_loads():
    entries = load_seed_entries()
    assert len(entries) >= 10
    assert any(e.cve_id == "CVE-2021-3156" for e in entries)


def test_infer_fix_pattern_strcpy():
    before = "strcpy(dst, src);"
    after = "strlcpy(dst, src, sizeof(dst));"
    pattern = infer_fix_pattern(before, after)
    assert "strcpy" in pattern.lower() or "bounded" in pattern.lower()


def test_unified_diff():
    diff = unified_diff("a\n", "b\n", "test.c")
    assert "- a" in diff
    assert "+ b" in diff


def test_search_empty_corpus_graceful(tmp_path, monkeypatch):
    monkeypatch.setenv("CHROMA_PATH", str(tmp_path / "empty_chroma"))
    from core.config import get_settings

    get_settings.cache_clear()

    query = VulnDNAQuery(crash_type="heap-buffer-overflow", cwe="CWE-122")
    matches, meta = search_vulndna(query)
    assert matches == []
    assert meta["corpus_size"] == 0
    assert "empty" in (meta.get("message") or "").lower()

    get_settings.cache_clear()


@pytest.mark.integration
def test_seed_ingest_and_heap_overflow_retrieval(tmp_path, monkeypatch):
    """Golden path: seed corpus → CWE-122 heap overflow → top CVE match."""
    monkeypatch.setenv("CHROMA_PATH", str(tmp_path / "vulndna_db"))
    from core.config import get_settings

    get_settings.cache_clear()

    count = ingest_seed(recreate=True)
    assert count >= 10

    pov = json.loads(FIXTURE.read_text(encoding="utf-8"))
    query = VulnDNAQuery(
        crash_type=pov["crash_type"],
        cwe=pov["cwe"],
        function=pov["function"],
        file=pov["file"],
        asan_summary=pov["asan_summary"],
        stack_trace=pov["stack_trace"],
    )
    matches, meta = search_vulndna(query, n_results=5)

    assert meta["corpus_size"] >= 10
    assert len(matches) >= 1
    assert matches[0].similarity >= pov["min_similarity"]
    assert matches[0].cve_id == pov["expected_top_cve"]
    assert matches[0].patch
    assert matches[0].fix_pattern

    get_settings.cache_clear()
