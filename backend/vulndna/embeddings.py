"""Nomic embedding model wrapper for VulnDNA."""

from functools import lru_cache

from sentence_transformers import SentenceTransformer

from core.config import get_settings

DOCUMENT_PREFIX = "search_document: "
QUERY_PREFIX = "search_query: "


def _get_device() -> str:
    try:
        import torch
        if torch.cuda.is_available():
            # Verify CUDA driver is actually functional
            torch.zeros(1, device="cuda")
            return "cuda"
    except Exception:
        pass
    return "cpu"


@lru_cache
def get_embed_model() -> SentenceTransformer:
    settings = get_settings()
    device = _get_device()
    return SentenceTransformer(settings.embed_model, trust_remote_code=True, device=device)


def embed_documents(texts: list[str]) -> list[list[float]]:
    model = get_embed_model()
    prefixed = [DOCUMENT_PREFIX + t for t in texts]
    vectors = model.encode(prefixed, normalize_embeddings=True)
    return vectors.tolist()


def embed_query(text: str) -> list[float]:
    model = get_embed_model()
    vector = model.encode(QUERY_PREFIX + text, normalize_embeddings=True)
    return vector.tolist()
