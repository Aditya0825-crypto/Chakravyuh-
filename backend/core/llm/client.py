"""Ollama LLM client — calls Windows host from WSL."""

from __future__ import annotations

import httpx

from core.config import get_settings


class OllamaError(Exception):
    pass


def ollama_available() -> bool:
    settings = get_settings()
    try:
        resp = httpx.get(f"{settings.ollama_host.rstrip('/')}/api/tags", timeout=3.0)
        return resp.status_code == 200
    except httpx.HTTPError:
        return False


def generate(prompt: str, *, system: str = "", temperature: float = 0.1) -> str:
    """Send a completion request to Ollama."""
    settings = get_settings()
    url = f"{settings.ollama_host.rstrip('/')}/api/generate"
    payload = {
        "model": settings.ollama_model,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": temperature},
    }
    if system:
        payload["system"] = system

    try:
        resp = httpx.post(url, json=payload, timeout=120.0)
        resp.raise_for_status()
        data = resp.json()
        return data.get("response", "").strip()
    except httpx.HTTPError as exc:
        raise OllamaError(str(exc)) from exc
