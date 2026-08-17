# CHAKRAVYUH Backend

Not yet built — reserved for the FastAPI + Celery/Redis + Postgres + ChromaDB
service described in the architecture discussion.

Planned layout (subject to change once implementation starts):

```
backend/
├── api/            # FastAPI app: routes, websocket, request/response schemas
├── workers/         # Celery tasks — one module per pipeline stage
│   ├── recon/
│   ├── bug_finding/
│   ├── pov_verifier/
│   ├── vulndna/
│   ├── patch_engine/
│   └── report/
├── db/               # SQLAlchemy models + migrations (Postgres)
├── vulndna/          # ChromaDB ingestion scripts + curated CVE corpus
├── sandbox/          # Per-scan Docker sandbox orchestration
├── docker-compose.yml
├── Dockerfile
└── requirements.txt
```

See the project's architecture discussion for the full tech stack and build
order.
