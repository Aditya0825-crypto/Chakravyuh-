# CHAKRAVYUH Backend — Phase 0 Foundation

FastAPI + Celery + Redis + PostgreSQL backend for the autonomous security pipeline.

## Quick start (WSL Ubuntu)

```bash
cd backend
bash scripts/setup_wsl.sh

source .venv/bin/activate
cp .env.example .env   # edit DATABASE_URL / paths if needed
alembic upgrade head

# Terminal 1 — API
uvicorn api.main:app --reload --host 0.0.0.0 --port 8000

# Terminal 2 — Celery worker
celery -A workers.celery_app worker --loglevel=info
```

Frontend (Windows):

```bash
cd frontend
npm run dev
```

Open http://localhost:5173/console/upload — upload a zip or source files. The stub pipeline advances through all stages with live WebSocket events.

## Phase 0 deliverables

| Component | Status |
|-----------|--------|
| FastAPI (`/api/health`, `/api/scans/upload`, list/get) | Done |
| PostgreSQL models (`scans`, `pipeline_events`) | Done |
| Alembic migration `001_initial` | Done |
| Celery stub pipeline (6 stages) | Done |
| WebSocket `/api/scans/{id}/stream` via Redis pub/sub | Done |
| Frontend upload → API + scan context | Done |

## Layout

```
backend/
├── api/              # FastAPI routes + WebSocket
├── core/             # config, ingest, events
├── db/               # SQLAlchemy models + Alembic
├── orchestrator/     # pipeline + state machine
├── workers/          # Celery app + tasks
├── scripts/          # WSL setup
├── alembic.ini
├── requirements.txt
└── .env.example
```

## Environment variables

See `.env.example`. Key vars:

- `DATABASE_URL` — PostgreSQL connection string
- `REDIS_URL` — Celery broker + pub/sub
- `SCAN_DATA_ROOT` — uploaded target storage (default `./data/scans` for local dev)
- `PIPELINE_STAGE_DELAY_SEC` — stub stage duration (default 3s)

## Ollama (Windows host)

From WSL, point at Windows Ollama:

```bash
export OLLAMA_HOST=http://$(grep nameserver /etc/resolv.conf | awk '{print $2}'):11434
```

Used in later phases for LLM stages.

## Next phases

1. **Phase 3–7** — Recon, Bug Finding, Patch, Report, full frontend wiring

See [IMPLEMENTATION_PLAN.md](../IMPLEMENTATION_PLAN.md) for the full spec.

---

## Phase 1 — PoV Verifier

### Build sandbox image (WSL)

```bash
bash scripts/build_sandbox.sh
# Set SANDBOX_MODE=docker in .env for container isolation
```

Local dev uses `SANDBOX_MODE=local` (default) — runs ASan binaries directly without Docker.

### Verify API

```bash
# Offline triage from captured ASan stderr
curl -X POST "http://localhost:8000/api/pov/verify-stderr?return_code=134" \
  -H "Content-Type: text/plain" \
  --data-binary @tests/fixtures/asan_samples/heap_overflow.txt

# Live replay (requires compiled ASan binary on server)
curl -X POST http://localhost:8000/api/pov/verify \
  -H "Content-Type: application/json" \
  -d '{"crashing_input":"'"$(python -c 'print("A"*512)')"'","binary_path":"/path/to/server"}'
```

### Tests

```bash
pytest tests/test_pov_verifier.py -m "not integration"   # parser + stderr tests
pytest tests/test_pov_verifier.py -m integration         # requires clang
```

Golden fixture: `tests/fixtures/vulnerable_server/server.c` — strcpy heap overflow → CWE-122.

---

## Phase 3 — Recon Engine

Upload a C project → pipeline runs real recon on Stage 1 → ranked targets persisted.

```bash
# After upload + pipeline run
curl http://localhost:8000/api/scans/{scan_id}/recon
```

### What it does

1. **tree-sitter** — extract functions, calls, dangerous sinks
2. **Semgrep** — `p/security-audit` (+ regex fallback if Semgrep not installed)
3. **Path map** — sink → callers → input sources (stdin/network/file)
4. **Ranking** — Ollama LLM if available, else heuristic scoring

### Tests

```bash
pytest tests/test_recon.py -m "not integration"
```

---

## Phase 2 — VulnDNA

### Seed corpus (instant, no CVEfixes download)

```bash
cd backend && source .venv/bin/activate
python -m vulndna.ingest_cvefixes --seed --reset
python -m vulndna.ingest_cvefixes --status
```

### Full CVEfixes ingest (WSL)

```bash
bash scripts/download_cvefixes.sh ./data/cvefixes
python -m vulndna.ingest_cvefixes --db ./data/cvefixes/CVEfixes.db --limit 5000 --reset
```

### Search API

```bash
curl -X POST http://localhost:8000/api/vulndna/search \
  -H "Content-Type: application/json" \
  -d '{"crash_type":"heap-buffer-overflow","cwe":"CWE-122","asan_summary":"strcpy overflow"}'
```

```bash
curl http://localhost:8000/api/vulndna/status
```

### Tests

```bash
pytest tests/test_vulndna.py -m "not integration"   # fast unit tests
pytest tests/test_vulndna.py -m integration         # requires embedding model
```
