"""VulnDNA search and corpus status endpoints."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from api.schemas.vulndna import (
    VulnDNAMatch,
    VulnDNASearchRequest,
    VulnDNASearchResponse,
    VulnDNAStatusResponse,
)
from core.config import get_settings
from db.models import Scan
from db.session import get_db
from vulndna.chroma_store import collection_count
from vulndna.models import VulnDNAQuery
from vulndna.query import search_vulndna

router = APIRouter(tags=["vulndna"])


@router.get("/vulndna/status", response_model=VulnDNAStatusResponse)
def vulndna_status():
    settings = get_settings()
    return VulnDNAStatusResponse(
        corpus_size=collection_count(),
        collection=settings.vulndna_collection,
        chroma_path=str(settings.chroma_dir()),
        embed_model=settings.embed_model,
    )


@router.post("/vulndna/search", response_model=VulnDNASearchResponse)
def vulndna_search(body: VulnDNASearchRequest):
    query = VulnDNAQuery(
        crash_type=body.crash_type,
        cwe=body.cwe,
        function=body.function,
        file=body.file,
        asan_summary=body.asan_summary,
        stack_trace=body.stack_trace,
    )
    matches, meta = search_vulndna(
        query,
        n_results=body.n_results,
        min_similarity=body.min_similarity,
    )
    return VulnDNASearchResponse(
        matches=[VulnDNAMatch(**m.to_api_dict()) for m in matches],
        query_ms=meta["query_ms"],
        corpus_size=meta["corpus_size"],
        message=meta.get("message"),
    )


@router.get("/scans/{scan_id}/vulndna", response_model=VulnDNASearchResponse)
def scan_vulndna(
    scan_id: UUID,
    db: Annotated[Session, Depends(get_db)],
    cwe: str = "CWE-122",
    crash_type: str = "heap-buffer-overflow",
):
    """
    Return VulnDNA matches for a scan.

    Phase 2: uses query params as PoV fingerprint until verified_povs table is wired.
    """
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    query = VulnDNAQuery(
        crash_type=crash_type,
        cwe=cwe,
        function=f"{scan.target_name}()",
        file=scan.target_name,
    )
    matches, meta = search_vulndna(query)
    return VulnDNASearchResponse(
        matches=[VulnDNAMatch(**m.to_api_dict()) for m in matches],
        query_ms=meta["query_ms"],
        corpus_size=meta["corpus_size"],
        message=meta.get("message"),
    )
