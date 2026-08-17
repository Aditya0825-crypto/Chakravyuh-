"""Application configuration loaded from environment variables."""

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    database_url: str = "postgresql://chakravyuh:password@localhost:5432/chakravyuh"
    redis_url: str = "redis://localhost:6379/0"

    ollama_host: str = "http://127.0.0.1:11434"
    ollama_model: str = "qwen2.5-coder"
    chroma_path: str = "./data/vulndna_db"
    cvefixes_db_path: str = ""
    embed_model: str = "nomic-ai/nomic-embed-text-v1.5"
    vulndna_collection: str = "cve_patches"
    scan_data_root: str = "./data/scans"
    sandbox_image: str = "chakravyuh-sandbox:latest"
    sandbox_mode: str = "local"  # local | docker

    symcc_enabled: bool = False
    codeql_enabled: bool = False

    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"
    pipeline_stage_delay_sec: float = 3.0

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    def scan_dir(self, scan_id: str) -> Path:
        return Path(self.scan_data_root) / scan_id

    def scan_source_dir(self, scan_id: str) -> Path:
        return self.scan_dir(scan_id) / "source"

    def chroma_dir(self) -> Path:
        return Path(self.chroma_path)


@lru_cache
def get_settings() -> Settings:
    return Settings()
