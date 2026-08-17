"""Celery task for Stage 4 VulnDNA — wired in Phase 3+ pipeline."""

from workers.celery_app import celery_app


@celery_app.task(name="chakravyuh.vulndna", bind=True, max_retries=0)
def task_vulndna(self, scan_id: str) -> dict:
    """Search VulnDNA corpus for verified PoVs (stub until Stage 3 output exists)."""
    from vulndna.models import VulnDNAQuery
    from vulndna.query import search_vulndna

    query = VulnDNAQuery(
        crash_type="heap-buffer-overflow",
        cwe="CWE-122",
    )
    matches, meta = search_vulndna(query)
    return {
        "scan_id": scan_id,
        "match_count": len(matches),
        "top_cve": matches[0].cve_id if matches else None,
        "corpus_size": meta["corpus_size"],
    }
