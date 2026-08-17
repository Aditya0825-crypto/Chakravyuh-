"""CHAKRAVYUH FastAPI application entry point."""

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.routes import gate, learning_log, pov, povs, recon, scans, vulndna
from api.schemas.scan import HealthResponse
from api.websocket import scan_stream
from core.config import get_settings
from db.models import Base
from db.session import engine


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    Path(settings.scan_data_root).mkdir(parents=True, exist_ok=True)
    Base.metadata.create_all(bind=engine)
    yield


def create_app() -> FastAPI:
    settings = get_settings()

    app = FastAPI(
        title="CHAKRAVYUH API",
        version="0.1.0",
        description="Autonomous security pipeline backend",
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    api = FastAPI()
    api.include_router(scans.router)
    api.include_router(gate.router)
    api.include_router(learning_log.router)
    api.include_router(recon.router)
    api.include_router(vulndna.router)
    api.include_router(pov.router)
    api.include_router(povs.router)
    api.include_router(scan_stream.router)

    @api.get("/health", response_model=HealthResponse)
    def health():
        return HealthResponse()

    app.mount("/api", api)
    return app


app = create_app()
