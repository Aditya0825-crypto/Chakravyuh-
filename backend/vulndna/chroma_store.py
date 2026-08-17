"""ChromaDB persistent store for CVE-patch corpus."""

import chromadb
from chromadb.api.models.Collection import Collection

from core.config import get_settings
from vulndna.models import CorpusEntry


def get_chroma_client() -> chromadb.PersistentClient:
    settings = get_settings()
    settings.chroma_dir().mkdir(parents=True, exist_ok=True)
    return chromadb.PersistentClient(path=str(settings.chroma_dir()))


def get_collection(*, recreate: bool = False) -> Collection:
    settings = get_settings()
    client = get_chroma_client()
    name = settings.vulndna_collection

    if recreate:
        try:
            client.delete_collection(name)
        except (ValueError, chromadb.errors.NotFoundError):
            pass

    return client.get_or_create_collection(
        name=name,
        metadata={"hnsw:space": "cosine"},
    )


def collection_count() -> int:
    try:
        return get_collection().count()
    except Exception:
        return 0


def upsert_entries(entries: list[CorpusEntry], *, batch_size: int = 64) -> int:
    """Embed and upsert corpus entries. Returns number of documents written."""
    from vulndna.embeddings import embed_documents

    if not entries:
        return 0

    collection = get_collection()
    written = 0

    for i in range(0, len(entries), batch_size):
        batch = entries[i : i + batch_size]
        ids = [e.doc_id for e in batch]
        documents = [e.embed_text() for e in batch]
        embeddings = embed_documents(documents)
        metadatas = [
            {
                "cve_id": e.cve_id,
                "cwe": e.cwe,
                "title": e.title[:500],
                "project": e.project[:200],
                "language": e.language,
                "function": e.function[:200],
                "vulnerable_code": e.vulnerable_code[:2000],
                "patch": e.patch[:4000],
                "fix_pattern": e.fix_pattern[:500],
                "description": e.description[:1000],
            }
            for e in batch
        ]
        collection.upsert(
            ids=ids,
            documents=documents,
            embeddings=embeddings,
            metadatas=metadatas,
        )
        written += len(batch)

    return written
