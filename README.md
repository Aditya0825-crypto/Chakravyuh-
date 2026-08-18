# 🛡️ CHAKRAVYUH

<p align="center">
  <img src="https://img.shields.io/badge/CHAKRAVYUH-v4.1-0f172a?style=for-the-badge&logo=shield&logoColor=white" alt="CHAKRAVYUH v4.1"/>
  <img src="https://img.shields.io/badge/C%2FC%2B%2B-Security%20Pipeline-2563eb?style=for-the-badge" alt="C/C++ Security"/>
  <img src="https://img.shields.io/badge/AI-Assisted-7c3aed?style=for-the-badge" alt="AI Assisted"/>
  <img src="https://img.shields.io/badge/Local--First-No%20Cloud%20Dependency-059669?style=for-the-badge" alt="Local First"/>
</p>

<p align="center">
  <strong>
    AI-Assisted Vulnerability Discovery, Proof-of-Vulnerability Verification,
    Historical CVE Intelligence & Adversarial Patch Validation for C/C++
  </strong>
</p>

<p align="center">
  <em>
    Discover. Prove. Correlate. Patch. Attack the Patch. Verify. Human Gate.
  </em>
</p>

<p align="center">
  <a href="#-what-is-chakravyuh">Overview</a> •
  <a href="#-architecture">Architecture</a> •
  <a href="#-the-six-stage-security-pipeline">Pipeline</a> •
  <a href="#-vulndna---historical-vulnerability-intelligence">VulnDNA</a> •
  <a href="#-stage-5---patch-arena">Patch Arena</a> •
  <a href="#-quick-start">Quick Start</a> •
  <a href="#-api">API</a> •
  <a href="#-roadmap">Roadmap</a>
</p>

---

## ⚡ What is CHAKRAVYUH?

**CHAKRAVYUH** is a security engineering platform designed to analyze
**C/C++ targets**, discover security weaknesses using multiple
complementary techniques, prove exploitable behavior at runtime,
correlate verified vulnerabilities with historical CVE remediation data,
generate competing patches, and validate those patches against the
original proof-of-vulnerability and adversarial attack variants.

The platform is deliberately designed **not** to rely on an LLM as a
single source of truth.

Instead, CHAKRAVYUH combines:

- 🔎 **Program reconnaissance**
- 🧠 **LLM-guided security reasoning**
- 🧩 **Static analysis**
- 🧪 **Coverage-guided fuzzing**
- 🧯 **ASan/UBSan runtime evidence**
- 🧾 **Proof-of-Vulnerability (PoV) verification**
- 🧬 **VulnDNA historical CVE precedent**
- 🛠️ **Multi-agent patch generation**
- ⚔️ **Adversarial patch testing**
- 📊 **Deterministic patch scoring**
- 👤 **Mandatory human approval**

The result is a complete security workflow:

``` text
┌─────────────┐
│ C/C++ Target│
└──────┬──────┘
       │
       ▼
┌──────────────────┐
│  1. RECON ENGINE │
│ tree-sitter      │
│ Semgrep          │
│ input → sink map │
│ Qwen risk rank   │
└────────┬─────────┘
         │
         ▼
┌──────────────────────┐
│ 2. BUG FINDING       │
│ Static + AFL++ + LLM │
│ Harness + Seeds      │
│ ASan / UBSan         │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ 3. PoV VERIFIER      │
│ Replay + Sanitizers  │
│ Stack Trace + CWE    │
│ Confidence + Dedup   │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ 4. VulnDNA           │
│ Verified PoV         │
│        ↓             │
│ CVEfixes corpus      │
│        ↓             │
│ Historical precedent │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ 5. PATCH ARENA       │
│ Agent 1              │
│ Agent 2              │
│ Agent 3              │
│ Compile + Test       │
│ Attack Variants      │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ 6. SECURITY REPORT   │
│ SAFE / REVIEW / HOLD │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ 👤 HUMAN GATE        │
│ APPROVE / REJECT     │
│ HOLD                 │
└──────────────────────┘
```

------------------------------------------------------------------------

## ✨ Why CHAKRAVYUH?

Traditional AI-based code security workflows can produce plausible
explanations or patches without proving that a vulnerability is actually
reachable or that a generated patch truly closes the attack surface.

CHAKRAVYUH addresses this with an **evidence-first pipeline**.

### The core philosophy

> **An LLM can propose. Runtime evidence must prove. Historical evidence
> can guide. Adversarial testing must challenge. A human must approve.**

  -----------------------------------------------------------------------
  Capability                          CHAKRAVYUH Approach
  ----------------------------------- -----------------------------------
  Vulnerability discovery             Static + dynamic + LLM-assisted

  Runtime confirmation                ASan / UBSan + isolated PoV replay

  Historical evidence                 VulnDNA + CVEfixes

  Patch generation                    3-agent patch arena

  Patch validation                    Compile + regression + attack
                                      variants + rediscovery

  Recommendation                      Deterministic SAFE / REVIEW / HOLD

  Production deployment               **Never automatic**

  Primary language scope              **C/C++ for v1**

  Execution model                     Local-first / commodity hardware

  LLM                                 Qwen2.5-Coder via Ollama
  -----------------------------------------------------------------------

------------------------------------------------------------------------

# 🧠 Architecture

``` mermaid
flowchart TB
    U[👨‍💻 Security Engineer] --> UI[React + Vite<br/>CHAKRAVYUH Console]

    UI <-->|REST + WebSocket| API[FastAPI API]

    API --> Q[Celery + Redis<br/>Job Management]
    Q --> O[Pipeline Orchestrator]

    O --> R[Stage 1<br/>Recon]
    O --> B[Stage 2<br/>Bug Finding]
    O --> P[Stage 3<br/>PoV Verifier]
    O --> V[Stage 4<br/>VulnDNA]
    O --> A[Stage 5<br/>Patch Arena]
    O --> S[Stage 6<br/>Report + Gate]

    R --> SAN[Docker Sandbox]
    B --> SAN
    P --> SAN
    A --> SAN

    R --> LLM[Qwen2.5-Coder<br/>Ollama]
    B --> LLM
    A --> LLM

    V --> CDB[(ChromaDB)]
    CDB --> CVE[CVEfixes<br/>Historical Corpus]

    O --> DB[(PostgreSQL)]
    O --> FS[(Scan Artifacts<br/>Filesystem)]

    S --> G{Human Gate}
    G -->|APPROVE| DONE[Completed]
    G -->|REVIEW / HOLD| REVIEW[Human Review]
    G -->|REJECT| REJECTED[Rejected]
```

### Runtime layout

CHAKRAVYUH is designed around a **Windows + WSL2** development
environment:

  Component                Runtime
  ------------------------ -----------------------------
  React + Vite frontend    Windows
  FastAPI                  WSL2 Ubuntu
  Celery workers           WSL2 Ubuntu
  PostgreSQL               WSL2 native
  Redis                    WSL2 native
  ChromaDB                 WSL2 persistent local store
  Qwen2.5-Coder / Ollama   Windows host GPU
  Docker sandbox           WSL2 / Docker Engine

This keeps the application services native to Linux while allowing the
local LLM to use the Windows GPU.

------------------------------------------------------------------------

# 🔬 The Six-Stage Security Pipeline

## Stage 0 --- Target Ingestion

The system accepts:

-   ZIP archives
-   Individual source files
-   C/C++ source targets

The target is extracted into an isolated scan workspace and a `Scan`
record is created.

``` text
Upload
  ↓
Extract
  ↓
Detect language
  ↓
Create Scan
  ↓
Queue Pipeline
```

------------------------------------------------------------------------

## Stage 1 --- Recon Engine

The Recon Engine converts an unfamiliar C/C++ codebase into a ranked
security attack surface.

### Techniques

-   `tree-sitter` for structural parsing
-   Semgrep security rules
-   Optional CodeQL
-   Function/call relationship extraction
-   Input-to-sink mapping
-   Qwen2.5-Coder risk ranking
-   Heuristic fallback when the LLM is unavailable

### Example

``` text
handle_request()
     │
     ├── network input
     │
     ▼
parse_header()
     │
     ▼
strcpy()
     │
     ▼
⚠ HIGH / CRITICAL TARGET
```

The output is a prioritized set of `recon_targets` and static findings.

------------------------------------------------------------------------

# 🧪 Stage 2 --- Bug Finding Engine

Stage 2 combines three complementary approaches.

### 1. Static Analysis

Semgrep identifies suspicious security sinks and code patterns.

Examples include:

-   unsafe memory operations
-   dangerous string handling
-   format-string patterns
-   command execution sinks
-   suspicious input flows

### 2. Dynamic Fuzzing

CHAKRAVYUH can build instrumented targets using:

``` bash
clang -fsanitize=address,undefined
```

and execute fuzzing workflows using:

-   AFL++
-   LLM-generated harnesses
-   LLM-generated boundary-aware seeds
-   bounded mutation
-   directed fuzzing where configured
-   optional SymCC escalation

### 3. LLM Security Reasoning

Qwen2.5-Coder receives high-risk functions together with relevant
context and can:

-   reason about boundary conditions
-   identify suspicious input paths
-   generate candidate triggering inputs
-   generate fuzz harnesses
-   suggest targeted tests

**Crucially, LLM-generated inputs are executed against the instrumented
target.**

``` text
LLM hypothesis
     ↓
Generated input / harness
     ↓
ASan-instrumented binary
     ↓
Runtime execution
     ↓
Crash?
 ┌───┴────┐
NO       YES
 │         │
Discard   Candidate PoV
```

------------------------------------------------------------------------

# 🧯 Stage 3 --- PoV Verifier

A crash is not automatically treated as a vulnerability.

The PoV Verifier independently replays candidate crashes inside the
sandbox.

### Verification includes

-   Sanitizer replay
-   Return-code validation
-   ASan/UBSan classification
-   Stack-trace extraction
-   Stack normalization
-   Crash deduplication
-   CWE mapping
-   Confidence calculation
-   Reproducibility checks

Conceptually:

``` python
candidate_input
       ↓
isolated replay
       ↓
ASan / UBSan
       ↓
sanitizer evidence
       ↓
normalized stack
       ↓
CWE
       ↓
confidence
       ↓
VerifiedPoV
```

This creates a clean boundary between:

> **"Something suspicious happened"**

and

> **"We have reproducible runtime evidence."**

------------------------------------------------------------------------

# 🧬 VulnDNA --- Historical Vulnerability Intelligence

## The key differentiator

**VulnDNA is the evidence layer of CHAKRAVYUH.**

Instead of asking an LLM to invent a remediation strategy from scratch,
CHAKRAVYUH can search historical vulnerability and patch data from the
**CVEfixes** corpus.

### Corpus

The planned corpus contains thousands of CVE/patch examples, filtered
for relevant C/C++ security data.

Each indexed record can include:

-   CVE ID
-   CWE
-   vulnerability description
-   vulnerable code
-   patch diff
-   function
-   programming language
-   fix pattern

### Retrieval pipeline

``` text
Verified PoV
     │
     ▼
Vulnerability fingerprint
     │
     ▼
Embedding
     │
     ▼
ChromaDB similarity search
     │
     ▼
Top historical matches
     │
     ├── CVE
     ├── CWE
     ├── similarity
     ├── vulnerable code
     ├── patch
     └── fix pattern
```

### Why this matters

VulnDNA transforms:

``` text
"An AI thinks this looks vulnerable."
```

into:

``` text
"Runtime evidence confirms the vulnerability,
and historical CVE data provides remediation precedent."
```

This makes the patching stage evidence-guided rather than purely
generative.

------------------------------------------------------------------------

# ⚔️ Stage 5 --- Patch Arena

CHAKRAVYUH does not blindly accept the first patch generated by an LLM.

Instead, three patch strategies compete.

  -----------------------------------------------------------------------
  Agent                               Strategy
  ----------------------------------- -----------------------------------
  🧠 Root Cause Fixer                 Traces the underlying data flow and
                                      produces a minimal root-cause fix

  🧬 Evidence-Guided Fixer            Uses VulnDNA historical remediation
                                      patterns

  🎯 Direct Fixer                     Applies a minimal surgical
                                      correction at the crash site
  -----------------------------------------------------------------------

Each candidate must pass compilation and validation.

### Patch scoring

  Metric            Weight
  -------------- ---------
  Security         **50%**
  Regression       **25%**
  Performance      **15%**
  Re-discovery     **10%**

### Security validation

The selected candidate is tested against:

-   Original PoV
-   Truncated input
-   Null-terminated variants
-   Doubled input
-   Null-byte variants
-   `0xff` fill patterns
-   Format-string variants
-   Large inputs
-   Half/single-byte truncation
-   Targeted re-discovery

``` text
              ┌──────────────┐
              │ Original PoV │
              └──────┬───────┘
                     │
                     ▼
        ┌────────────────────────┐
        │ Candidate Patch Agent  │
        └───────────┬────────────┘
                    │
          ┌─────────┼─────────┐
          ▼         ▼         ▼
       Agent 1   Agent 2   Agent 3
          │         │         │
          └─────────┼─────────┘
                    ▼
             Compile Gate
                    │
                    ▼
          Regression Testing
                    │
                    ▼
          Attack Variant Tests
                    │
                    ▼
           Re-discovery Test
                    │
                    ▼
             Score + Rank
                    │
                    ▼
             Winning Patch
```

------------------------------------------------------------------------

# 🛡️ Stage 6 --- Security Report + Human Gate

The final report combines evidence from every stage.

### Report includes

-   Vulnerability summary
-   CWE
-   Location
-   Severity
-   CVSS information
-   Root-cause explanation
-   Static-analysis evidence
-   Dynamic/PoV evidence
-   VulnDNA evidence
-   Patch candidates
-   Rejected patch explanations
-   Verification results
-   Confidence
-   Recommendation

------------------------------------------------------------------------

# 🚦 Deterministic Recommendation Engine

The recommendation is intentionally **not delegated to the LLM**.

CHAKRAVYUH produces:

### 🟢 SAFE

Requires strong verification, including:

-   verified PoV
-   selected patch
-   patch score ≥ 85
-   100% regression pass rate
-   all attack variants blocked

### 🟡 REVIEW

The system has a viable patch but additional human review is
appropriate.

### 🔴 HOLD

Returned when evidence or patch quality is insufficient.

Examples:

-   no verified PoV
-   no selected patch
-   patch score below threshold
-   rediscovery still succeeds

``` text
                 ┌──────────────┐
                 │ Scan Results │
                 └──────┬───────┘
                        ▼
              Verified PoV exists?
                 │             │
                NO            YES
                 │             │
                 ▼             ▼
               HOLD      Patch selected?
                              │
                         ┌────┴────┐
                        NO        YES
                         │          │
                         ▼          ▼
                       HOLD     Score >= 85?
                                  │
                             ┌────┴────┐
                            NO        YES
                             │          │
                             ▼          ▼
                          REVIEW    Regression
                                     + Variants
                                          │
                                      ┌───┴───┐
                                     FAIL    PASS
                                      │        │
                                      ▼        ▼
                                    REVIEW    SAFE
```

## 👤 Human Gate

**CHAKRAVYUH never automatically deploys a generated patch.**

The final state requires an explicit human decision:

``` text
APPROVED
REJECTED
HOLD
```

This creates a clear safety boundary between automated security analysis
and production change management.

------------------------------------------------------------------------

# 🖥️ CHAKRAVYUH Console

The frontend is designed as a security operations console.

### Main routes

  Route                   Purpose
  ----------------------- ------------------------------
  `/`                     Landing page
  `/console`              Security dashboard
  `/console/upload`       Target upload
  `/console/recon`        Recon Engine
  `/console/bugfinding`   Bug Finding Engine
  `/console/verifier`     PoV Verifier
  `/console/vulndna`      VulnDNA evidence
  `/console/patch`        Patch Arena
  `/console/report`       Security Report + Human Gate
  `/console/learning`     Learning Log

### Frontend stack

-   React 19
-   Vite 8
-   React Router 7
-   Tailwind CSS 4
-   Framer Motion
-   Recharts
-   Lucide
-   react-hot-toast

The UI is designed to expose pipeline state, findings, evidence, patch
candidates, scoring and gate decisions rather than hiding the security
reasoning behind a single chatbot interface.

------------------------------------------------------------------------

# 🧱 Technology Stack

  Layer                         Technology
  ----------------------------- -----------------------
  Frontend                      React 19 + Vite 8
  Styling                       Tailwind CSS 4
  Animations                    Framer Motion
  Charts                        Recharts
  Icons                         Lucide
  API                           FastAPI
  Async orchestration           Celery
  Queue / PubSub                Redis
  Database                      PostgreSQL
  Vector store                  ChromaDB
  Embeddings                    Nomic Embed Text v1.5
  LLM                           Qwen2.5-Coder
  LLM Runtime                   Ollama
  Parsing                       tree-sitter
  Static analysis               Semgrep
  Optional static analysis      CodeQL
  Fuzzing                       AFL++
  Optional directed fuzzing     AFLGo
  Optional symbolic execution   SymCC
  Runtime verification          ASan / UBSan
  Isolation                     Docker
  Primary language scope        C/C++

------------------------------------------------------------------------

# 📁 Repository Structure

``` text
CHAKRAVYUH/
│
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   ├── context/
│   │   ├── data/
│   │   ├── pages/
│   │   └── ...
│   └── ...
│
├── backend/
│   ├── api/
│   │   ├── main.py
│   │   ├── routes/
│   │   │   ├── scans.py
│   │   │   ├── gate.py
│   │   │   └── learning_log.py
│   │   ├── websocket/
│   │   │   └── scan_stream.py
│   │   └── schemas/
│   │
│   ├── orchestrator/
│   │   ├── pipeline.py
│   │   └── state_machine.py
│   │
│   ├── workers/
│   │   ├── celery_app.py
│   │   ├── recon/
│   │   ├── bug_finding/
│   │   ├── pov_verifier/
│   │   ├── vulndna/
│   │   ├── patch_engine/
│   │   └── report/
│   │
│   ├── core/
│   │   ├── llm/
│   │   ├── sandbox/
│   │   ├── parsers/
│   │   └── scoring/
│   │
│   ├── db/
│   │   ├── models.py
│   │   ├── session.py
│   │   ├── migrations/
│   │   └── repositories/
│   │
│   ├── vulndna/
│   │   ├── ingest_cvefixes.py
│   │   └── query.py
│   │
│   ├── tests/
│   │   └── fixtures/
│   │       ├── vulnerable_server/
│   │       ├── clean_hello/
│   │       └── known_cve_sample/
│   │
│   ├── Dockerfile
│   ├── requirements.txt
│   └── .env.example
│
├── IMPLEMENTATION_PLAN.md
└── README.md
```

------------------------------------------------------------------------

# 🔌 API

## Health

``` http
GET /api/health
```

## Scan Management

``` http
POST /api/scans/upload
GET  /api/scans
GET  /api/scans/{id}
```

## Stage Data

``` http
GET /api/scans/{id}/recon
GET /api/scans/{id}/findings
GET /api/scans/{id}/povs
GET /api/scans/{id}/vulndna
GET /api/scans/{id}/patches
GET /api/scans/{id}/report
```

## VulnDNA Search

``` http
GET /api/vulndna/search
```

## Human Gate

``` http
POST /api/scans/{id}/gate
```

Example:

``` json
{
  "decision": "APPROVED",
  "notes": "Patch reviewed and validated."
}
```

## Learning Log

``` http
GET /api/learning-log
```

## Live Pipeline Stream

``` text
WS /api/scans/{id}/stream
```

Example event:

``` json
{
  "type": "stage_started",
  "stage": "recon",
  "timestamp": "2026-08-18T12:00:00Z"
}
```

------------------------------------------------------------------------

# 🚀 Quick Start

> The following setup follows the project's WSL2 + Windows architecture.

## 1. Clone

``` bash
git clone https://github.com/Aditya0825-crypto/CHAKRAVYUH.git
cd CHAKRAVYUH
```

If your repository uses a different remote name, replace the URL above
with your repository URL.

------------------------------------------------------------------------

## 2. Backend --- WSL2 / Ubuntu

Install system dependencies:

``` bash
sudo apt update

sudo apt install -y \
  postgresql \
  redis-server \
  docker.io \
  clang \
  llvm \
  build-essential \
  git \
  patch \
  python3.11 \
  python3.11-venv \
  python3-pip
```

Start PostgreSQL and Redis:

``` bash
sudo service postgresql start
sudo service redis-server start
```

------------------------------------------------------------------------

## 3. Create Python Environment

``` bash
cd backend

python3.11 -m venv .venv
source .venv/bin/activate

pip install --upgrade pip
pip install -r requirements.txt
```

------------------------------------------------------------------------

## 4. Configure Environment

Create:

``` bash
cp .env.example .env
```

Example:

``` env
DATABASE_URL=postgresql://chakravyuh:password@localhost:5432/chakravyuh
REDIS_URL=redis://localhost:6379/0

OLLAMA_HOST=http://<WINDOWS_HOST_IP>:11434
OLLAMA_MODEL=qwen2.5-coder

CHROMA_PATH=/data/chakravyuh/vulndna_db
SCAN_DATA_ROOT=/data/chakravyuh/scans

SANDBOX_IMAGE=chakravyuh-sandbox:latest

SYMCC_ENABLED=false
CODEQL_ENABLED=false
```

------------------------------------------------------------------------

# 🤖 Ollama + Qwen2.5-Coder

Install Ollama on the Windows host and pull the configured coding model.

``` bash
ollama pull qwen2.5-coder
```

From WSL, expose the Windows host address:

``` bash
export OLLAMA_HOST=http://$(grep nameserver /etc/resolv.conf | awk '{print $2}'):11434
```

Verify the model is reachable before starting the pipeline.

------------------------------------------------------------------------

# 🐳 Build the Sandbox

The Docker image is intended for **target execution and
security-analysis isolation**, not for running the complete backend.

The sandbox contains the tooling required for:

-   Clang
-   LLVM
-   ASan/UBSan
-   Semgrep
-   AFL++
-   AFLGo where configured
-   Python
-   Git
-   Patch application

Build:

``` bash
cd backend
docker build -t chakravyuh-sandbox:latest .
```

------------------------------------------------------------------------

# 🗄️ PostgreSQL

Create the application database and configure the credentials in `.env`.

Then apply the project's migrations using the configured migration
workflow.

The data model includes:

``` text
scans
recon_targets
static_findings
fuzz_runs
crashes
verified_povs
vulndna_matches
patch_candidates
reports
gate_decisions
learning_log_entries
pipeline_events
```

Large artifacts such as crash inputs, diffs and logs are kept in the
scan filesystem while PostgreSQL stores metadata and references.

------------------------------------------------------------------------

# 🧬 VulnDNA Setup

CHAKRAVYUH uses **CVEfixes** as the historical vulnerability/patch
source for VulnDNA.

Repository:

https://github.com/secureIT-project/CVEfixes

The ingestion pipeline is responsible for:

1.  Downloading/reading CVEfixes data
2.  Filtering relevant C/C++ records
3.  Validating patch information
4.  Creating embeddings
5.  Persisting vectors in ChromaDB
6.  Making the corpus queryable during scans

The project uses:

``` python
SentenceTransformer("nomic-ai/nomic-embed-text-v1.5")
```

and a persistent ChromaDB collection.

------------------------------------------------------------------------

# ▶️ Run the System

## Backend API

``` bash
cd backend
source .venv/bin/activate

uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload
```

## Celery Worker

In another WSL terminal:

``` bash
cd backend
source .venv/bin/activate

celery -A workers.celery_app worker --loglevel=info
```

## Frontend

On the frontend environment:

``` bash
cd frontend
npm install
npm run dev
```

The Vite development server runs on the configured frontend port, with
the project plan using:

``` text
http://localhost:5173
```

------------------------------------------------------------------------

# 🔄 End-to-End Demo

A recommended golden path is:

``` text
Upload vulnerable_server
        ↓
Recon identifies dangerous sink
        ↓
Bug Finding generates/executes inputs
        ↓
ASan detects crash
        ↓
PoV Verifier confirms vulnerability
        ↓
CWE classification
        ↓
VulnDNA searches historical CVEs
        ↓
Top CVE precedent returned
        ↓
3 patch agents generate candidates
        ↓
Candidates compile
        ↓
Original PoV tested
        ↓
Attack variants tested
        ↓
Re-discovery attempted
        ↓
Patch scored
        ↓
Security report generated
        ↓
SAFE / REVIEW / HOLD
        ↓
Human decision
```

------------------------------------------------------------------------

# 🧪 Test Fixtures

The project defines a validation suite around three important fixtures:

``` text
backend/tests/fixtures/
├── vulnerable_server/
├── clean_hello/
└── known_cve_sample/
```

### `vulnerable_server`

Golden-path vulnerable target used to exercise:

-   Recon
-   Bug finding
-   PoV verification
-   CWE classification
-   VulnDNA retrieval
-   Patch generation
-   Patch validation
-   Final reporting

### `clean_hello`

Negative test target intended to demonstrate a clean scan with no
verified crash.

### `known_cve_sample`

Used to validate historical VulnDNA retrieval against known
vulnerability data.

------------------------------------------------------------------------

# 📊 Validation Strategy

  Stage          Validation
  -------------- --------------------------------------------
  Recon          Known C/C++ sink detection + ranking
  Bug Finding    Known vulnerable function produces a crash
  PoV Verifier   ASan output → CWE + dedup + confidence
  VulnDNA        Known CVE → relevant top match
  Patch Arena    Patch compiles + original PoV blocked
  Report         Backend artifacts match frontend schema

### Golden integration test

``` text
Target Upload
     ↓
CWE-122 detected
     ↓
Historical VulnDNA match
     ↓
Patch candidate selected
     ↓
Original PoV blocked
     ↓
Recommendation generated
     ↓
Human gate recorded
```

------------------------------------------------------------------------

# 📡 WebSocket Event Model

The frontend can receive live pipeline events such as:

``` json
{
  "type": "stage_started",
  "stage": "recon"
}
```

``` json
{
  "type": "stage_completed",
  "stage": "recon",
  "duration_sec": 12
}
```

``` json
{
  "type": "log",
  "stage": "bugfinding",
  "message": "CRASH #1 — heap-buffer-overflow"
}
```

``` json
{
  "type": "artifact",
  "stage": "vulndna",
  "payload": {}
}
```

``` json
{
  "type": "scan_complete",
  "recommendation": "REVIEW"
}
```

This allows the console to present long-running security analysis as a
live pipeline rather than a blocking request.

------------------------------------------------------------------------

# 🗃️ Data Model

The central scan lifecycle is:

``` text
queued
  ↓
running
  ↓
stage_recon
  ↓
stage_bugfinding
  ↓
stage_pov
  ↓
stage_vulndna
  ↓
stage_patch
  ↓
stage_report
  ↓
awaiting_gate
  ├── approved
  ├── rejected
  └── hold
  ↓
completed / failed
```

### Core entities

``` text
Scan
 ├── ReconTarget[]
 ├── StaticFinding[]
 ├── FuzzRun[]
 ├── Crash[]
 ├── VerifiedPoV[]
 ├── VulnDNAMatch[]
 ├── PatchCandidate[]
 ├── Report
 ├── GateDecision
 ├── LearningLogEntry[]
 └── PipelineEvent[]
```

------------------------------------------------------------------------

# 🧠 LLM Safety & Control

CHAKRAVYUH uses the LLM as a **bounded reasoning component**, not as an
unrestricted autonomous security operator.

The architecture explicitly limits LLM behavior through fixed workflows
and controlled actions.

Examples:

-   Risk ranking
-   Harness generation
-   Seed generation
-   Code review
-   Patch generation
-   Historical-fix adaptation

Runtime validation remains outside the LLM.

This separation is fundamental:

``` text
LLM proposes
     ↓
System executes
     ↓
Sanitizers observe
     ↓
Verifier validates
     ↓
Scoring system evaluates
     ↓
Human decides
```

------------------------------------------------------------------------

# 🔐 Security Model

CHAKRAVYUH is designed for analyzing **authorized source code and
security-testing targets**.

Security-sensitive execution is isolated through ephemeral Docker
sandboxes.

The design specifically separates:

### Application services

-   FastAPI
-   Celery
-   PostgreSQL
-   Redis
-   ChromaDB

from:

### Target execution

-   compilation
-   fuzzing
-   sanitizer execution
-   PoV replay
-   patch verification

This reduces the risk of directly executing untrusted target code inside
the main application process.

------------------------------------------------------------------------

# ⚙️ Optional Advanced Components

Some capabilities are intentionally optional for the MVP.

### CodeQL

Useful for deeper static/taint analysis but requires additional setup.

``` env
CODEQL_ENABLED=false
```

### SymCC

Used as an escalation layer when fuzzing is stuck around difficult
branch conditions.

``` env
SYMCC_ENABLED=false
```

### AFLGo

Can direct fuzzing toward suspicious sinks identified during
reconnaissance.

These components can be enabled without making them mandatory
dependencies for the core demo path.

------------------------------------------------------------------------

# 📈 MVP vs Full Specification

  Capability         MVP                     Full Specification
  ------------------ ----------------------- --------------------------------
  Language           C/C++                   C/C++, Python, Java, Go, etc.
  Static analysis    Semgrep                 Semgrep + CodeQL
  Fuzzing            LLM harness + AFL++     AFL++ + AFLGo + SymCC
  VulnDNA            Top-5 + subset corpus   Full CVEfixes corpus
  Patch generation   3 agents                Full feedback/rediscovery loop
  Report             JSON + human gate       JSON + PDF export
  SymCC              Disabled by default     Optional escalation

------------------------------------------------------------------------

# 🛣️ Roadmap

``` text
                CHAKRAVYUH
                    │
        ┌───────────┴───────────┐
        │                       │
      v4.1                    Future
        │                       │
        ▼                       ▼
   C/C++ First             Multi-language
        │                       │
        ▼                       ▼
   Semgrep + AFL++        CodeQL + advanced
        │                  symbolic execution
        ▼                       │
   VulnDNA CVEfixes             ▼
        │                  Larger corpus
        ▼                       │
   3-Agent Patch Arena          ▼
        │                  Continuous security
        ▼                  verification
   Human Gate
```

### Planned expansion

-   [ ] Full CVEfixes corpus ingestion
-   [ ] Broader language support
-   [ ] CodeQL integration
-   [ ] AFLGo-directed campaigns
-   [ ] SymCC escalation
-   [ ] Larger historical vulnerability corpus
-   [ ] More regression-test integrations
-   [ ] PDF security-report export
-   [ ] Expanded patch feedback loops

------------------------------------------------------------------------

# 📋 Current Implementation Checklist

### Infrastructure

-   [x] FastAPI foundation
-   [x] Celery application
-   [x] Redis/WebSocket event architecture
-   [x] PostgreSQL data model
-   [x] Docker sandbox
-   [x] Environment configuration

### Recon

-   [x] tree-sitter function/call extraction
-   [x] Semgrep integration
-   [x] Regex fallback
-   [x] Input-to-sink path mapping
-   [x] Qwen/heuristic risk ranking

### Bug Finding

-   [x] Static analysis integration
-   [x] LLM harness generation
-   [x] ASan-instrumented compilation
-   [x] AFL++ integration
-   [x] LLM code-review path
-   [x] Bounded mutation fuzzing
-   [x] PoV integration

### PoV Verification

-   [x] Docker replay
-   [x] ASan parsing
-   [x] Stack-trace extraction
-   [x] CWE mapping
-   [x] Confidence scoring
-   [x] Crash deduplication

### VulnDNA

-   [x] Ingestion pipeline
-   [x] Query layer
-   [x] Seed/integration validation
-   [x] Empty-result handling
-   [ ] Full CVEfixes corpus population

### Patch Arena

-   [x] Three patch agents
-   [x] Unified-diff parsing
-   [x] Compile gate
-   [x] Patch scoring
-   [x] Attack-variant generation
-   [x] VulnDNA integration

### Report + Gate

-   [x] Report assembler
-   [x] SAFE / REVIEW / HOLD logic
-   [x] Human gate API
-   [x] Learning log

### Frontend

-   [x] Live API client
-   [x] Vite API proxy
-   [x] Scan context
-   [x] Live console pages
-   [x] WebSocket stage status
-   [x] Loading/error states

------------------------------------------------------------------------

# 🏆 Golden Demo Scenario

For a concise demonstration, use the project's vulnerable fixture:

``` text
┌──────────────────────┐
│ vulnerable_server    │
└──────────┬───────────┘
           ▼
      Upload Target
           ▼
      Recon Engine
           ▼
    Dangerous Sink
           ▼
      Bug Finding
           ▼
      ASan Crash
           ▼
     PoV Verifier
           ▼
       CWE-122
           ▼
       VulnDNA
           ▼
    Historical CVE
           ▼
      Patch Arena
      ╱     │     ╲
   Agent1 Agent2 Agent3
      ╲     │     ╱
           ▼
      Patch Scoring
           ▼
   Attack Variants
           ▼
     Re-discovery
           ▼
   Security Report
           ▼
     SAFE / REVIEW
           ▼
      Human Gate
```

This path demonstrates the most important differentiators of the
platform in a single scan.

------------------------------------------------------------------------

# 🎯 Design Principles

### 01 --- Evidence over Guessing

A model suggestion is not treated as a verified vulnerability.

### 02 --- Runtime Proof Matters

Security findings should be reproducible wherever possible.

### 03 --- Historical Knowledge Improves Remediation

VulnDNA connects current findings with previously fixed vulnerabilities.

### 04 --- Multiple Patches Beat One Guess

Independent patch strategies compete instead of trusting the first
generated diff.

### 05 --- Attack the Patch

A patch is tested against the original exploit and generated variants.

### 06 --- Deterministic Safety Decisions

SAFE / REVIEW / HOLD is governed by explicit rules rather than LLM
confidence.

### 07 --- Human-in-the-Loop

No generated patch is automatically deployed to production.

------------------------------------------------------------------------

# ⚠️ Limitations

CHAKRAVYUH v4.1 is intentionally focused on **C/C++ first**.

Some advanced capabilities remain optional or experimental:

-   Full CodeQL integration
-   AFLGo
-   SymCC
-   Full-scale CVEfixes ingestion
-   Multi-language analysis
-   Production-scale distributed execution
-   Full enterprise CI/CD integration

The system is best understood as an **AI-assisted security analysis and
remediation platform**, not a replacement for expert security review.

------------------------------------------------------------------------

# 🤝 Contributing

Contributions are welcome.

A useful contribution should ideally include:

1.  A clear problem statement
2.  Reproducible steps
3.  Tests where applicable
4.  Security impact assessment
5.  Documentation updates
6.  Compatibility with the existing pipeline architecture

For security-sensitive changes, please avoid introducing unrestricted
execution paths or bypassing the human gate.

------------------------------------------------------------------------

# 🔒 Responsible Use

CHAKRAVYUH is intended for:

-   Authorized security testing
-   Defensive vulnerability research
-   Software assurance
-   Secure code review
-   Controlled fuzzing
-   Patch validation
-   Research and education

Only analyze software you own or have explicit authorization to test.

------------------------------------------------------------------------

# 📚 Key References

-   **CVEfixes:** https://github.com/secureIT-project/CVEfixes
-   **Ollama:** https://ollama.com/
-   **Qwen:** https://qwenlm.github.io/
-   **FastAPI:** https://fastapi.tiangolo.com/
-   **Celery:** https://docs.celeryq.dev/
-   **Redis:** https://redis.io/
-   **PostgreSQL:** https://www.postgresql.org/
-   **ChromaDB:** https://www.trychroma.com/
-   **Semgrep:** https://semgrep.dev/
-   **AFL++:** https://aflplus.plus/
-   **LLVM:** https://llvm.org/
-   **Docker:** https://www.docker.com/
-   **tree-sitter:** https://tree-sitter.github.io/tree-sitter/

------------------------------------------------------------------------

# 📄 Project Documentation

The repository's implementation specification is maintained in:

``` text
IMPLEMENTATION_PLAN.md
```

It serves as the detailed engineering reference for:

-   architecture
-   database schema
-   API contracts
-   pipeline orchestration
-   stage specifications
-   infrastructure
-   test fixtures
-   risk register
-   implementation phases

------------------------------------------------------------------------

# 🌟 Project Vision

CHAKRAVYUH is built around a simple idea:

> **Security automation should not stop at finding a suspicious line of
> code. It should establish evidence, understand precedent, produce a
> defensible remediation, attack that remediation, and put the final
> decision in human hands.**

``` text
             DISCOVER
                ↓
               PROVE
                ↓
             CORRELATE
                ↓
               PATCH
                ↓
             ATTACK FIX
                ↓
              VERIFY
                ↓
           HUMAN GATE
                ↓
             SECURE
```

```{=html}
<p align="center">
```
`<strong>`{=html}🛡️ CHAKRAVYUH --- Evidence-driven security engineering
for modern C/C++ software.`</strong>`{=html}
```{=html}
</p>
```
```{=html}
<p align="center">
```
Built with ❤️ for secure software research, defensive security, and
engineering.
```{=html}
</p>
```
