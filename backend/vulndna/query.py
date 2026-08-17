"""Runtime VulnDNA similarity search."""

import time

from vulndna.chroma_store import collection_count, get_collection
from vulndna.embeddings import embed_query
from vulndna.models import EvidencePackage, VulnDNAQuery


def _distance_to_similarity(distance: float) -> float:
    """Convert cosine distance (Chroma) to 0–100 similarity score."""
    # cosine distance = 1 - cosine_similarity for normalized vectors
    similarity = max(0.0, 1.0 - distance)
    return similarity * 100.0


def search_vulndna(
    query: VulnDNAQuery,
    *,
    n_results: int = 5,
    min_similarity: float = 0.0,
) -> tuple[list[EvidencePackage], dict]:
    """
    Search ChromaDB for CVE-patch evidence packages.

    Returns (matches, meta) where meta includes query_ms and corpus_size.
    Gracefully returns empty list when corpus is empty or no matches.
    """
    start = time.perf_counter()
    corpus_size = collection_count()

    if corpus_size == 0:
        return [], {
            "query_ms": 0,
            "corpus_size": 0,
            "message": "VulnDNA corpus empty — run ingest_cvefixes --seed",
        }

    collection = get_collection()
    query_embedding = embed_query(query.query_text())

    raw = collection.query(
        query_embeddings=[query_embedding],
        n_results=min(n_results, corpus_size),
        include=["metadatas", "distances", "documents"],
    )

    packages: list[EvidencePackage] = []
    metadatas = (raw.get("metadatas") or [[]])[0]
    distances = (raw.get("distances") or [[]])[0]

    for meta, distance in zip(metadatas, distances):
        similarity = _distance_to_similarity(float(distance))
        if similarity < min_similarity:
            continue
        packages.append(
            EvidencePackage(
                cve_id=meta.get("cve_id", "UNKNOWN"),
                similarity=similarity,
                cwe=meta.get("cwe", query.cwe),
                title=meta.get("title", ""),
                project=meta.get("project", ""),
                language=meta.get("language", ""),
                function=meta.get("function", ""),
                vulnerable_code=meta.get("vulnerable_code", ""),
                patch=meta.get("patch", ""),
                fix_pattern=meta.get("fix_pattern", ""),
                why_it_works=meta.get("fix_pattern", ""),
            )
        )

    elapsed_ms = int((time.perf_counter() - start) * 1000)
    return packages, {
        "query_ms": elapsed_ms,
        "corpus_size": corpus_size,
        "message": None if packages else "No matches above threshold",
    }
