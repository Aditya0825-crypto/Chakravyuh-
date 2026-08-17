# CHAKRAVYUH v4.1 — Final Implementation Plan

> **Single source of truth** for backend build. Supersedes `implementation_plan_02.md`.  
> **Last updated:** 2026-08-17  
> **Status:** Frontend complete · Backend not started

---

## Table of Contents

0. [Current Project State](#0-current-project-state)
1. [Architecture Overview](#1-architecture-overview)
2. [Design Decisions](#2-design-decisions)
3. [Development Environment (WSL + Windows)](#3-development-environment-wsl--windows)
4. [Repository Layout](#4-repository-layout)
5. [Data Model (Postgres)](#5-data-model-postgres)
6. [API Contract](#6-api-contract)
7. [Pipeline Orchestration](#7-pipeline-orchestration)
8. [Stage Specifications](#8-stage-specifications)
9. [Recommendation Logic (SAFE / REVIEW / HOLD)](#9-recommendation-logic-safe--review--hold)
10. [Infrastructure & Tooling](#10-infrastructure--tooling)
11. [Build Phases](#11-build-phases)
12. [MVP vs Full Spec](#12-mvp-vs-full-spec)
13. [Test Fixtures & Validation](#13-test-fixtures--validation)
14. [Risk Register](#14-risk-register)
15. [Master Task Checklist](#15-master-task-checklist)
16. [Recommended Start Order](#16-recommended-start-order)

---

## 0. Current Project State

### 0.1 What exists today

```
CHAKRAVYUH/
├── frontend/          ✅ COMPLETE — React 19 + Vite 8 console + landing page
├── backend/           🚧 Phase 0 — FastAPI + Celery + WS foundation
├── IMPLEMENTATION_PLAN.md        ← this document
└── implementation_plan_02.md     ← superseded; merged here
```

### 0.2 Frontend (built)

| Route | Page | Data source today |
|-------|------|-------------------|
| `/` | Landing page | `landing/` components, `criteria.js`, `stages.js` |
| `/console` | Dashboard | `mockData.js` — pipeline overview, finding hero, VulnDNA, patch winner |
| `/console/upload` | Upload Target | Local file staging; **simulated** 1.4s ingest → navigate to recon |
| `/console/recon` | Recon Engine | `mockData.reconTargets`, `semgrepFindings` |
| `/console/bugfinding` | Bug Finding | `mockData.fuzzingResults`, `crashes`, `semgrepFindings` |
| `/console/verifier` | PoV Verifier | `mockData.crashes` (verified subset) |
| `/console/vulndna` | VulnDNA | `mockData.vulnDNAResults` |
| `/console/patch` | Patch Engine | `mockData.patchCandidates` |
| `/console/report` | Security Report + Human Gate | `mockData.securityReport`; local approve/reject state only |
| `/console/learning` | Learning Log | `mockData.learningLog` |

**Frontend stack:** React 19, Vite 8, React Router 7, Framer Motion, Recharts, Tailwind 4, Lucide, react-hot-toast.

**Key mock files the backend must mirror:**

- `frontend/src/data/mockData.js` — crashes, patches, VulnDNA, report, learning log
- `frontend/src/data/scans.js` — scan history, gate statuses, findings per scan

**No API integration yet** — no `fetch`, axios, or WebSocket calls anywhere in the frontend.

### 0.3 Backend (not built)

Planned stack per architecture:

- FastAPI (REST + WebSocket)
- Celery + Redis (job queue)
- PostgreSQL (persistence)
- ChromaDB (VulnDNA corpus)
- Docker (ephemeral scan sandbox only)
- Qwen2.5-Coder via Ollama on Windows host (GPU)

### 0.4 Product constraints (from judge criteria)

- VulnDNA is the key differentiator — CVE precedent, not raw LLM guessing
- Runs on commodity hardware (~8 GB VRAM, no cloud dependency)
- Human safety gate is mandatory — **never auto-deploy patches**
- C/C++ first for v1 pipeline

---

## 1. Architecture Overview

```text
┌──────────────────────┐
│   React + Vite UI    │  ← Windows / browser (npm run dev)
│  CHAKRAVYUH Console  │
└──────────┬───────────┘
           │  REST + WebSocket
┌──────────▼───────────┐
│       FastAPI        │  ← WSL (native Python)
│      API Server      │
└──────────┬───────────┘
           │
┌──────────▼───────────┐
│   Celery + Redis     │  ← WSL (Redis native)
│    Job Management    │
└──────────┬───────────┘
           │
┌──────────▼───────────┐
│ Pipeline Orchestrator│  ← Python asyncio in Celery workers
│     Python/asyncio   │
└──────────┬───────────┘
           │
     ┌─────┴─────┬─────────┬─────────┬─────────┬─────────┐
     ▼           ▼         ▼         ▼         ▼         ▼
  Stage 1    Stage 2   Stage 3   Stage 4   Stage 5   Stage 6
   Recon    Bug Find   PoV Ver   VulnDNA  Patch Arena Report+Gate
     │           │         │         │         │         │
     └───────────┴─────────┴────┬────┴─────────┴─────────┘
                                │
                    ┌───────────▼───────────┐
                    │  Docker Sandbox       │  ← ephemeral per scan/job
                    │  (compile, fuzz, run) │
                    └───────────────────────┘

External:
  Ollama (Qwen2.5-Coder)  ← Windows host, GPU
  ChromaDB                ← WSL local persistent store
  PostgreSQL              ← WSL native
```

**Core flow:**

1. User uploads target via React console
2. FastAPI creates `Scan`, stores files, enqueues Celery pipeline
3. Orchestrator runs stages 1→6 sequentially (Stage 2 parallel internally)
4. WebSocket streams stage events + logs to UI
5. Report generated with SAFE / REVIEW / HOLD recommendation
6. Human approves, rejects, or holds — no automatic patch deployment

---

## 2. Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Unit of work | One `Scan` per upload | Matches UI scan model (`scans.js`) |
| Orchestration | Celery chain + Redis pub/sub for WS | Long-running stages, async jobs |
| Dev environment | **WSL2 (Ubuntu)** | AFL++, SymCC, clang, Linux tooling |
| API / workers | Native Python on WSL | Direct access to local Postgres, Redis, ChromaDB |
| Primary LLM | **Qwen2.5-Coder via Ollama on Windows host** | GPU access from Windows; API called from WSL |
| Patch LLM fallback | DeepSeek-Coder or Gemini Flash | Optional cloud fallback |
| Database | **PostgreSQL native on WSL** | Not Dockerized — direct local performance |
| Job queue | **Redis native on WSL** | Not Dockerized |
| VulnDNA store | **ChromaDB persistent on WSL** | `./vulndna_db` or dedicated path |
| Target sandbox | **Docker container per scan/job** | ASan replay, AFL, compile isolation only |
| Blob storage | WSL filesystem `/data/scans/{id}/` | Crash inputs, diffs, sanitizer logs, source |
| VulnDNA corpus | Pre-built from CVEfixes (offline ingest) | ~5,300 CVE-patch pairs |
| Language scope v1 | **C/C++ first** | tree-sitter + AFL + ASan clearest path |
| SymCC | Optional per-scan flag | Escalation layer, not MVP blocker |
| CodeQL | Optional v1 (`--with-codeql`) | Heavy setup; Semgrep-only MVP path |
| No auto-deploy | Human gate mandatory | Product + competition requirement |

---

## 3. Development Environment (WSL + Windows)

### 3.1 Host layout

| Component | Where it runs | Notes |
|-----------|---------------|-------|
| React frontend | Windows | `cd frontend && npm run dev` → port 5173 |
| FastAPI | WSL | port 8000 |
| Celery worker | WSL | same codebase as API |
| PostgreSQL | WSL native | port 5432 |
| Redis | WSL native | port 6379 |
| ChromaDB | WSL (embedded PersistentClient) | local path, no separate service required for MVP |
| Ollama + Qwen2.5-Coder | **Windows host** | `http://host.docker.internal:11434` or WSL gateway IP |
| Docker Engine | WSL2 backend | sandbox containers only |

### 3.2 WSL setup checklist

```bash
# System packages (Ubuntu WSL)
sudo apt update && sudo apt install -y \
  postgresql redis-server docker.io \
  clang llvm build-essential git patch \
  python3.11 python3.11-venv python3-pip

# Semgrep, AFL++ — install per official docs or build from source
# Enable services
sudo service postgresql start
sudo service redis-server start
```

### 3.3 Ollama on Windows (LLM)

- Install Ollama on Windows, pull `qwen2.5-coder` (or appropriate quant)
- From WSL, call Ollama at Windows host IP:
  - `export OLLAMA_HOST=http://$(grep nameserver /etc/resolv.conf | awk '{print $2}'):11434`
- Backend `core/llm/client.py` reads `OLLAMA_HOST` env var

### 3.4 Project paths (WSL)

```text
/mnt/c/Users/Aditya/Downloads/CHAKRAVYUH/   ← repo root
/data/chakravyuh/scans/                      ← scan workspaces (create on setup)
/data/chakravyuh/vulndna_db/                 ← ChromaDB persistent store
```

### 3.5 What is NOT Dockerized

- PostgreSQL
- Redis
- FastAPI
- Celery workers
- ChromaDB (embedded)

### 3.6 What IS Dockerized

- **Sandbox worker image only** — ephemeral Ubuntu 22.04 containers for:
  - ASan/UBSan compile + run
  - AFL++ fuzzing sessions
  - PoV replay
  - Patch compile + verification

`backend/Dockerfile` defines the sandbox image (clang, AFL++, semgrep inside container). API/worker processes invoke `docker run` — they do not run inside Docker themselves.

---

## 4. Repository Layout

```text
backend/
├── api/
│   ├── main.py
│   ├── routes/
│   │   ├── scans.py
│   │   ├── gate.py
│   │   └── learning_log.py
│   ├── websocket/
│   │   └── scan_stream.py
│   └── schemas/
│       ├── scan.py
│       ├── recon.py
│       ├── findings.py
│       ├── pov.py
│       ├── vulndna.py
│       ├── patch.py
│       └── report.py
├── orchestrator/
│   ├── pipeline.py
│   └── state_machine.py
├── workers/
│   ├── celery_app.py
│   ├── recon/
│   │   └── task.py
│   ├── bug_finding/
│   │   ├── task.py
│   │   ├── static_runner.py
│   │   ├── fuzz_runner.py
│   │   ├── llm_runner.py
│   │   └── orchestrator.py
│   ├── pov_verifier/
│   │   └── task.py
│   ├── vulndna/
│   │   └── task.py
│   ├── patch_engine/
│   │   ├── task.py
│   │   ├── agents.py
│   │   ├── selector.py
│   │   └── attack_variants.py
│   └── report/
│       └── task.py
├── core/
│   ├── llm/
│   │   ├── client.py           # Ollama wrapper (Windows host)
│   │   └── prompts.py
│   ├── sandbox/
│   │   ├── docker_runner.py    # docker run wrapper
│   │   └── compile.py
│   ├── parsers/
│   │   ├── asan.py
│   │   ├── semgrep.py
│   │   └── stack_trace.py
│   └── scoring/
│       └── confidence.py
├── db/
│   ├── models.py
│   ├── session.py
│   ├── migrations/
│   └── repositories/
├── vulndna/
│   ├── ingest_cvefixes.py
│   └── query.py
├── tests/
│   └── fixtures/
│       ├── vulnerable_server/
│       ├── clean_hello/
│       └── known_cve_sample/
├── .env.example
├── Dockerfile                  # sandbox image ONLY
├── requirements.txt
└── README.md
```

---

## 5. Data Model (Postgres)

### 5.1 Core tables

| Table | Key fields | Frontend mapping |
|-------|------------|------------------|
| `scans` | id, target_name, status, current_stage, started_at, duration_sec, artifact_root | Dashboard, Sidebar |
| `recon_targets` | scan_id, function, file, line, risk, reason, sinks[], call_path, input_sources[], score | `mockData.reconTargets` |
| `static_findings` | scan_id, rule, file, line, severity, message, code_snippet | `mockData.semgrepFindings` |
| `fuzz_runs` | scan_id, status, runtime, execs_per_sec, total_execs, crashes_found, coverage | `mockData.fuzzingResults` |
| `crashes` | scan_id, status, type, cwe, file, line, function, signal, confidence, asan_summary, stack_trace[], crash_input | `mockData.crashes` |
| `verified_povs` | scan_id, crash_id, confidence, cwe, sanitizer_report, dedup_hash | Stage 3 → Stage 4 input |
| `vulndna_matches` | scan_id, cve_id, similarity, cwe, title, project, function, vulnerable_code, patch, fix_pattern | `mockData.vulnDNAResults` |
| `patch_candidates` | scan_id, agent, name, strategy, diff, scores{}, status, rejected_reason | `mockData.patchCandidates` |
| `reports` | scan_id, report_json, recommendation, confidence | `mockData.securityReport` |
| `gate_decisions` | scan_id, decision, decided_by, decided_at, notes | SecurityReport human gate |
| `learning_log_entries` | scan_id, target, cwe, crash_type, discovery_method, winning_agent, patch_success, top_cve, notes | `mockData.learningLog` |
| `pipeline_events` | scan_id, stage, timestamp, level, message | BugFinding timeline |

Large blobs (crash inputs, diffs, logs) stored on filesystem; Postgres holds metadata + JSON pointers.

### 5.2 Scan status state machine

```text
queued
  → running
    → stage_recon        (pending → running → complete | failed)
    → stage_bugfinding
    → stage_pov
    → stage_vulndna
    → stage_patch
    → stage_report
  → awaiting_gate
    → approved | rejected | hold
  → completed | failed
```

---

## 6. API Contract

### 6.1 REST endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/health` | Health check |
| `POST` | `/api/scans/upload` | Multipart upload (zip or files) → create scan, enqueue pipeline |
| `GET` | `/api/scans` | List all scans |
| `GET` | `/api/scans/{id}` | Scan summary + current stage + status |
| `GET` | `/api/scans/{id}/recon` | Recon targets + static findings |
| `GET` | `/api/scans/{id}/findings` | Static + fuzz results + raw crashes |
| `GET` | `/api/scans/{id}/povs` | Verified PoVs (post Stage 3) |
| `GET` | `/api/scans/{id}/vulndna` | VulnDNA evidence packages |
| `GET` | `/api/scans/{id}/patches` | All patch candidates + winner |
| `GET` | `/api/scans/{id}/report` | Final security report |
| `POST` | `/api/scans/{id}/gate` | `{ "decision": "APPROVED" \| "HOLD" \| "REJECTED", "notes": "..." }` |
| `GET` | `/api/learning-log` | Historical scan entries |

### 6.2 WebSocket

**Endpoint:** `WS /api/scans/{id}/stream`

```json
{ "type": "stage_started",   "stage": "recon",       "timestamp": "..." }
{ "type": "stage_completed", "stage": "recon",       "duration_sec": 12 }
{ "type": "stage_failed",    "stage": "bugfinding",  "error": "..." }
{ "type": "log",             "stage": "bugfinding",  "message": "CRASH #1 — heap-buffer-overflow..." }
{ "type": "artifact",        "stage": "vulndna",     "payload": { } }
{ "type": "scan_complete",   "recommendation": "REVIEW" }
```

### 6.3 Frontend integration (Phase 7)

| File | Change |
|------|--------|
| `frontend/src/pages/UploadTarget.jsx` | Replace `setTimeout` with `POST /api/scans/upload` |
| New: `frontend/src/api/client.js` | REST + WS helpers |
| All console pages | Fetch by `scanId` instead of `mockData.js` |
| `frontend/src/components/layout/Sidebar.jsx` | Live stage status from WebSocket |
| `frontend/vite.config.js` | Proxy `/api` → `localhost:8000` in dev |

---

## 7. Pipeline Orchestration

### 7.1 Celery task chain

```text
upload_complete
  → task_recon
    → task_bug_finding          # internal parallel: static | fuzz | llm
      → task_pov_verifier
        → task_vulndna
          → task_patch_arena
            → task_report
              → status = awaiting_gate
```

### 7.2 Orchestrator rules

- Each task reads prior stage artifacts from DB + filesystem
- Each task writes its own artifact JSON + updates `scans.current_stage`
- Each task publishes WebSocket events via Redis pub/sub
- On failure: mark scan `failed`, persist partial artifacts, emit `stage_failed`
- Bug Finding uses internal parallelism (asyncio inside Celery task)

### 7.3 Stage 2 reasoning loop

```text
while time_budget_remaining:
    if static_finding and not runtime_confirmed:
        → run targeted AFLGo toward suspicious sink

    if fuzz_stuck(near_sink) and symcc_enabled:
        → symcc_solve(branch_condition)
        → feed input back to AFL++

    if llm_generated_poc:
        → run against ASan-instrumented binary in Docker sandbox

    if verified_crash:
        → break
```

LLM selects from a **fixed action menu** — never invent arbitrary tools.

---

## 8. Stage Specifications

### Stage 0 — Target Ingestion

**Tools:** FastAPI multipart, zip extraction

**Responsibilities:**
- Accept `.zip` or individual source files (extensions match `UploadTarget.jsx`)
- Extract to `/data/chakravyuh/scans/{scan_id}/source/`
- Detect languages from extensions
- Create `Scan` with status `queued`, enqueue pipeline

**Maps to UI:** `UploadTarget.jsx`

---

### Stage 1 — Recon Engine

**Tools:** tree-sitter, Semgrep, CodeQL (optional), Qwen2.5-Coder

**Responsibilities:**
- Parse code structure (functions, params, call relationships)
- Semgrep sink detection: `semgrep --config=p/security-audit --json target/`
- CodeQL taint analysis if DB available (optional)
- Build input-to-sink path map
- LLM risk ranking → priority queue

**Steps:**
1. tree-sitter: functions, parameters, call edges
2. Semgrep: security-audit rules
3. Path map: sinks → callers → input sources (network/file/argv)
4. LLM prompt: rank by user-input + dangerous calls + reachable paths
5. Persist `recon_targets[]` + `static_findings[]`

**Example output:**
```python
[
  ("handle_request", "CRITICAL", "strcpy + user input + reachable sink"),
  ("parse_header",   "HIGH",     "sprintf + network data"),
  ("render_page",    "LOW",      "no dangerous patterns"),
]
```

**Effort:** 2–3 days · **Difficulty:** Easy  
**Maps to UI:** `ReconEngine.jsx`

---

### Stage 2 — Bug Finding Engine

**Tools:** Semgrep, CodeQL, AFL++, AFLGo, ASan/UBSan, Qwen2.5-Coder, SymCC (optional)

**Responsibilities:**
- Parallel static + fuzz + LLM analysis
- LLM fuzz harness generation (LLM_FUZZ_DATA_PROVIDER pattern)
- LLM boundary-aware seed generation
- Directed fuzzing (AFLGo) toward Semgrep sinks
- SymCC escalation when stuck
- Orchestrator feedback loop

**Method 1 — Static:**
```bash
semgrep --config=p/security-audit --config=p/owasp-top-ten --json target/
codeql database create target-db --language=cpp --source-root=target/   # optional
codeql database analyze target-db codeql/cpp-queries:Security --format=sarif
```

**Method 2 — Fuzzing:**
1. LLM generates C harness per high-risk function
2. Compile: `clang -fsanitize=address,undefined harness.c target.c -o fuzzer`
3. LLM seeds + AFL dictionaries
4. AFL++ normal or AFLGo directed
5. If stuck → SymCC → feed input back to AFL++

**Method 3 — LLM code review:**
- Send function + callers/callees to LLM
- Generate triggering input → run in sandbox
- Crash → candidate PoV

**Effort:** 6–7 days · **Difficulty:** Medium-High  
**Maps to UI:** `BugFinding.jsx`

---

### Stage 3 — PoV Verifier

**Tools:** Python, ASan, UBSan, Docker sandbox

**Responsibilities:**
- Replay crashes in isolated container
- Validate sanitizer evidence (return codes: 1, 77, 134, 139)
- Classify vulnerability from ASan/UBSan output
- Extract + normalize stack traces
- Deduplicate by stack hash
- Map to CWE
- Calculate confidence (static + runtime + reproducibility)

```python
def verify_pov(crashing_input, target_binary):
    result = run_with_sanitizers(target_binary, crashing_input)
    if result.returncode not in [1, 77, 134, 139]:
        return None
    crash_type = classify_sanitizer_output(result.stderr)
    stack_trace = extract_stack_trace(result.stderr)
    crash_id = hash(normalize_stack_trace(stack_trace))
    if crash_id in seen_crashes:
        return None
    cwe = map_to_cwe(crash_type)
    confidence = calculate_confidence(...)
    return VerifiedPoV(...)
```

**Build early** — Stages 2 and 5 depend on this.  
**Effort:** 2 days · **Difficulty:** Easy  
**Maps to UI:** `PovVerifier.jsx`

---

### Stage 4 — VulnDNA Evidence Engine

**Tools:** ChromaDB, Nomic-Embed-Text v1.5, CVEfixes dataset

**Responsibilities:**
- Fingerprint verified PoV
- Embed + search 5,000+ CVE-patch corpus
- Return top-5 evidence packages
- Graceful fallback when no match

**Offline ingest (start Day 1, parallel track):**
```python
# https://github.com/secureIT-project/CVEfixes
model = SentenceTransformer("nomic-ai/nomic-embed-text-v1.5")
client = chromadb.PersistentClient(path="/data/chakravyuh/vulndna_db")
collection = client.create_collection("cve_patches")
# embed: CVE id, CWE, description, vulnerable code, patch diff, function, language
```

**Runtime query:**
```python
def search_vulndna(verified_pov):
    query_text = f"Crash type: {pov.crash_type}\nCWE: {pov.cwe}\n..."
    results = collection.query(query_texts=[query_text], n_results=5)
    return evidence_packages  # cve_id, similarity, patch, fix_pattern
```

**Effort:** 4–5 days (runtime); ingest runs in parallel · **Difficulty:** Medium  
**Maps to UI:** `VulnDNA.jsx`

---

### Stage 5 — Patch Engine (3-Agent Arena)

**Tools:** Qwen2.5-Coder, Python patch tools, AFL re-discovery

**Three agents:**

| Agent | Strategy |
|-------|----------|
| Agent 1 — Root Cause Fixer | Trace taint flow, fix root cause, minimal diff |
| Agent 2 — Evidence-Guided Fixer | Adapt VulnDNA historical fix patterns |
| Agent 3 — Direct Fixer | Minimal surgical fix at crash site, no history |

**Patch Selector scoring:**

| Metric | Weight | Test |
|--------|--------|------|
| Security | 50% | Original PoV blocked + attack variants blocked |
| Regression | 25% | Test suite pass rate (100% if no tests) |
| Performance | 15% | Benchmark overhead penalty |
| Re-discovery | 10% | Targeted fuzz finds no crash at same location |

**Threshold:** Winner score > 60 or no patch selected.

**Feedback loop:** All fail → structured failure evidence → LLM retry → verify again.

**Attack variants:** truncated, null-terminated, doubled, null bytes, 0xff fill, format strings, 10k 'A's, half/single-byte truncation.

**Effort:** 5–6 days · **Difficulty:** Medium  
**Maps to UI:** `PatchEngine.jsx`

---

### Stage 6 — Report + Human Gate

**Responsibilities:**
- Assemble report from all stage artifacts
- Assign SAFE / REVIEW / HOLD (deterministic rules — see §9)
- Wait for human decision — **never auto-deploy**
- Record gate decision + learning log entry

**Report sections:**
- Vulnerability summary (CWE, location, severity, CVSS)
- Root cause explanation
- Discovery evidence (static + dynamic + PoV)
- VulnDNA evidence
- Patch candidates (winner + rejected with reasons)
- Verification results
- Confidence + recommendation

**Effort:** 2–3 days · **Difficulty:** Easy  
**Maps to UI:** `SecurityReport.jsx`, `LearningLog.jsx`

---

## 9. Recommendation Logic (SAFE / REVIEW / HOLD)

Deterministic — do not delegate to LLM:

```python
def compute_recommendation(scan) -> str:
    if not scan.verified_povs or not scan.selected_patch:
        return "HOLD"
    if scan.selected_patch.score < 60:
        return "HOLD"
    if scan.selected_patch.rediscovery_failed:
        return "HOLD"
    if (
        scan.selected_patch.score >= 85
        and scan.selected_patch.regression_pass_rate == 1.0
        and scan.selected_patch.all_variants_blocked
    ):
        return "SAFE"
    return "REVIEW"
```

Human gate: `APPROVED`, `REJECTED`, or `HOLD` — system never writes patches to production.

---

## 10. Infrastructure & Tooling

### 10.1 Service map

| Component | Technology | Location |
|-----------|------------|----------|
| API / orchestration | FastAPI + Python asyncio | WSL native |
| Job queue | Celery + Redis | Redis on WSL native |
| Database | PostgreSQL | WSL native |
| Primary LLM | Qwen2.5-Coder via Ollama | Windows host (GPU) |
| Embeddings | Nomic-Embed-Text v1.5 | WSL (sentence-transformers) |
| VulnDNA store | ChromaDB PersistentClient | WSL `/data/chakravyuh/vulndna_db` |
| Target sandbox | Docker (Ubuntu 22.04) | Ephemeral, network-isolated |
| Frontend | React + Vite | Windows, port 5173 |

### 10.2 Sandbox Docker image must include

| Tool | Purpose |
|------|---------|
| clang + llvm | ASan/UBSan compile |
| Semgrep | Static analysis inside container |
| AFL++ | Fuzzing |
| AFLGo | Directed fuzzing |
| git, patch | Patch apply |
| Python 3.11+ | Harness scripts |

Optional: CodeQL CLI, SymCC (separate image variant).

### 10.3 Environment variables (`.env.example`)

```bash
DATABASE_URL=postgresql://chakravyuh:password@localhost:5432/chakravyuh
REDIS_URL=redis://localhost:6379/0
OLLAMA_HOST=http://<windows-host-ip>:11434
OLLAMA_MODEL=qwen2.5-coder
CHROMA_PATH=/data/chakravyuh/vulndna_db
SCAN_DATA_ROOT=/data/chakravyuh/scans
SANDBOX_IMAGE=chakravyuh-sandbox:latest
SYmCC_ENABLED=false
CODEQL_ENABLED=false
```

---

## 11. Build Phases

### Phase 0 — Foundation (Week 1)

**Goal:** Upload → scan record → stage progression visible in UI

- [ ] WSL environment setup (Postgres, Redis, Docker) — script: `backend/scripts/setup_wsl.sh`
- [x] `backend/requirements.txt` + Python venv
- [x] FastAPI scaffold — health, CORS, upload endpoint
- [x] Alembic migrations — `scans`, `pipeline_events`
- [x] Celery app + dummy task advancing stages
- [x] WebSocket scan stream via Redis pub/sub
- [x] `.env.example` + config module
- [x] Minimal frontend hook — upload → API, console reads `scanId`

**Exit criteria:** Upload zip → live stage progression (stub stages OK)

---

### Phase 1 — PoV Verifier Primitives (Days 2–4)

**Goal:** Reliable crash validation (build before full Bug Finding)

- [x] `backend/Dockerfile` — sandbox image
- [x] `core/sandbox/docker_runner.py`
- [x] `core/parsers/asan.py`
- [x] `core/parsers/stack_trace.py`
- [x] CWE mapping + confidence scoring
- [x] Unit tests with known ASan output samples

**Exit criteria:** Crash input + binary → `VerifiedPoV` with CWE + confidence

---

### Phase 2 — VulnDNA Corpus (Parallel from Day 1)

**Goal:** Queryable ChromaDB with CVEfixes

- [ ] Download + clean CVEfixes — `scripts/download_cvefixes.sh`
- [x] Filter C/C++ + valid patch diffs — `vulndna/ingest_cvefixes.py`
- [x] `vulndna/ingest_cvefixes.py`
- [x] `vulndna/query.py`
- [x] Validate on 10 known CVE samples — seed corpus + integration test
- [x] Graceful empty-result handling

**Exit criteria:** Heap overflow PoV → top CVE match with similarity + patch diff

---

### Phase 3 — Stage 1 Recon (Days 4–7)

**Goal:** Real ranked attack targets for C/C++ projects

- [x] tree-sitter function/call extraction
- [x] Semgrep integration (+ regex fallback)
- [x] Path map (sink → callers → inputs)
- [x] LLM risk ranking via Ollama (+ heuristic fallback)
- [x] `GET /api/scans/{id}/recon`
- [x] Persist `recon_targets` + `static_findings`

**Exit criteria:** Upload C project → recon page shows ranked functions

---

### Phase 4 — Stage 2 Bug Finding MVP (Days 7–17)

**Goal:** ≥1 real confirmed crash end-to-end

- [x] **4a** Static — Semgrep feeds orchestrator
- [x] **4b** LLM harness generation
- [x] **4c** Compile + AFL++ with ASan, LLM seeds, time budget
- [x] **4d** LLM code review → test inputs → run
- [x] **4e** Bounded mutation fuzz runner
- [x] **4f** Stage 3 PoV Verifier integration

**Exit criteria:** Scan → crash → PoV confirmed → visible on Bug Finding page

---

### Phase 5 — Stage 5 Patch Arena (Days 17–24)

**Goal:** 3 patches generated, scored, one selected

- [x] Agent 1/2/3 prompts + diff parser
- [x] `apply_and_compile()` in sandbox
- [x] Patch Selector (5-test scoring)
- [x] Attack variant generator
- [x] `GET /api/scans/{id}/patches`
- [x] Stage 4 VulnDNA integration

**Exit criteria:** Winning patch blocks PoV; score in UI

---

### Phase 6 — Stage 6 Report + Gate (Days 24–27)

**Goal:** Full report + human gate

- [x] Report assembler
- [x] Recommendation logic
- [x] `GET /api/scans/{id}/report`
- [x] `POST /api/scans/{id}/gate`
- [x] Learning log on gate decision

**Exit criteria:** Full pipeline → report populated → gate decision persists

---

### Phase 7 — Frontend Integration (finalize last)

**Goal:** Live backend-connected console with graceful mock fallbacks

- [x] `frontend/src/api/client.js`
- [x] Vite proxy for `/api`
- [x] Scan context (`scanId` in context + local storage)
- [x] Wire all console pages to live API + WS (`ReconEngine`, `BugFinding`, `PovVerifier`, `VulnDNA`, `PatchEngine`, `SecurityReport`, `LearningLog`, `Dashboard`, `UploadTarget`)
- [x] Sidebar live stage status
- [x] Loading + error states

**Exit criteria:** Full end-to-end interactive dashboard connected to live API endpoints & WebSocket events

---

## 12. MVP vs Full Spec

| Capability | MVP (demo-ready) | Full spec |
|------------|------------------|-----------|
| Environment | WSL + native DB/Redis + Ollama Windows | Same |
| Languages | C/C++ only | Python, Java, Go, etc. |
| Static analysis | Semgrep only | Semgrep + CodeQL |
| Fuzzing | LLM harness + basic AFL++ | AFL++ + AFLGo + SymCC |
| VulnDNA | Top-5 query, subset corpus | Full 5k+ CVEfixes |
| Patch agents | 3 agents, basic selector | Full rediscovery + feedback loop |
| Report | JSON + gate | + PDF export |
| SymCC | Disabled | Optional escalation |

**Golden demo path:** Upload `vulnerable_server` fixture → CWE-122 → CVE match >80% → patch blocks PoV → REVIEW or SAFE.

---

## 13. Test Fixtures & Validation

```text
backend/tests/fixtures/
├── vulnerable_server/    # strcpy heap overflow — golden path
├── clean_hello/          # no crashes — HOLD or no findings
└── known_cve_sample/     # VulnDNA retrieval check
```

**Golden integration test:**
```text
Upload vulnerable_server
  → CWE-122 detected
  → VulnDNA top match similarity > 80%
  → Selected patch blocks original PoV
  → Recommendation REVIEW or SAFE
  → Human gate records decision
```

| Stage | Unit test |
|-------|-----------|
| Recon | Known C file → correct sink + ranking |
| Bug Finding | Known vuln function → crash produced |
| PoV Verifier | Known ASan stderr → CWE + dedup |
| VulnDNA | Known CVE → correct top match |
| Patch Arena | Known diff → compile + PoV blocked |
| Report | Artifacts → JSON matches frontend shape |

---

## 14. Risk Register

| Risk | Impact | Mitigation |
|------|--------|------------|
| WSL ↔ Windows Ollama networking | High | Document `OLLAMA_HOST` via resolv.conf gateway IP |
| AFL setup complexity | High | Time-box fuzz budget; LLM PoV fallback for MVP |
| CodeQL DB heavy | Medium | Optional flag; Semgrep-only path |
| LLM invalid diffs | High | Unified-diff parser; compile gate rejects bad patches |
| CVEfixes noisy data | Medium | Filter language + CWE + valid patch on ingest |
| Long scan times (30+ min) | Medium | Live WS logs; async UI already designed for this |
| SymCC build | Low | Flag-gated; skip MVP |
| Docker socket in WSL | Medium | Use WSL2 Docker integration; test early in Phase 1 |

---

## 15. Master Task Checklist

### Environment & infrastructure

- [ ] WSL2 Ubuntu setup
- [ ] PostgreSQL installed + `chakravyuh` database created
- [ ] Redis installed + running
- [ ] Docker installed in WSL
- [ ] Ollama on Windows + Qwen2.5-Coder pulled
- [ ] `/data/chakravyuh/` directories created
- [ ] `backend/requirements.txt`
- [ ] `backend/Dockerfile` (sandbox image)
- [ ] `backend/.env.example`
- [ ] FastAPI app with CORS
- [ ] Celery worker configured
- [ ] WebSocket + Redis pub/sub

### Database (12 tables)

- [x] `scans`
- [x] `recon_targets`
- [x] `static_findings`
- [x] `fuzz_runs`
- [x] `crashes`
- [x] `verified_povs`
- [x] `vulndna_matches`
- [x] `patch_candidates`
- [x] `reports`
- [x] `gate_decisions`
- [x] `learning_log_entries`
- [x] `pipeline_events`

### API (12 endpoints + WS)

- [x] `GET /api/health`
- [x] `POST /api/scans/upload`
- [x] `GET /api/scans`
- [x] `GET /api/scans/{id}`
- [x] `GET /api/scans/{id}/recon`
- [x] `GET /api/scans/{id}/findings`
- [x] `GET /api/scans/{id}/povs`
- [x] `GET /api/vulndna/search`
- [x] `GET /api/scans/{id}/vulndna`
- [x] `GET /api/scans/{id}/patches`
- [x] `GET /api/scans/{id}/report`
- [x] `POST /api/scans/{id}/gate`
- [x] `GET /api/learning-log`
- [x] `WS /api/scans/{id}/stream`

### Core modules

- [x] `core/sandbox/docker_runner.py`
- [x] `core/sandbox/compile.py`
- [x] `core/parsers/asan.py`
- [x] `core/parsers/semgrep.py`
- [x] `core/llm/client.py` (Ollama → Windows host)
- [x] `core/llm/prompts.py`
- [x] `core/scoring/confidence.py`

### Pipeline workers

- [x] `orchestrator/pipeline.py`
- [x] `orchestrator/state_machine.py`
- [x] `workers/recon/task.py`
- [x] `workers/bug_finding/task.py`
- [x] `workers/bug_finding/static_runner.py`
- [x] `workers/bug_finding/fuzz_runner.py`
- [x] `workers/bug_finding/llm_runner.py`
- [x] `workers/bug_finding/orchestrator.py`
- [x] `workers/pov_verifier/task.py`
- [x] `workers/vulndna/task.py`
- [x] `workers/patch_engine/task.py`
- [x] `workers/patch_engine/agents.py`
- [x] `workers/patch_engine/selector.py`
- [x] `workers/patch_engine/attack_variants.py`
- [x] `workers/report/task.py`

### VulnDNA

- [x] `vulndna/ingest_cvefixes.py`
- [x] `vulndna/query.py`
- [ ] ChromaDB corpus populated (seed: `--seed`; full: CVEfixes download)

### Frontend wiring

- [ ] `frontend/src/api/client.js`
- [ ] Vite dev proxy
- [ ] Upload → real API
- [ ] Dashboard → WebSocket
- [ ] ReconEngine → `/recon`
- [ ] BugFinding → `/findings`
- [ ] PovVerifier → `/povs`
- [ ] VulnDNA → `/vulndna`
- [ ] PatchEngine → `/patches`
- [ ] SecurityReport → `/report` + gate POST
- [ ] LearningLog → `/learning-log`
- [ ] Sidebar live stage status

### Tests

- [ ] `tests/fixtures/vulnerable_server/`
- [ ] `tests/fixtures/clean_hello/`
- [ ] PoV verifier unit tests
- [ ] VulnDNA retrieval tests
- [ ] Golden pipeline integration test

---

## 16. Recommended Start Order

```text
1. Phase 0  — WSL setup + FastAPI + Celery + WS + scan model
2. Phase 2  — VulnDNA ingest (runs in background)
3. Phase 1  — PoV Verifier + sandbox Docker image
4. Phase 3  — Stage 1 Recon
5. Phase 4  — Stage 2 Bug Finding MVP
6. Phase 5  — Stage 5 Patch Arena
7. Phase 6  — Stage 6 Report + Gate
8. Phase 7  — Frontend integration (wire mock → live API)
```

---

*Update checkboxes in this document as tasks complete. This is the only plan document to follow.*
