export const stages = [
  {
    id: "recon",
    number: "01",
    name: "Recon",
    devanagari: "टोह",
    line: "Maps the codebase into a structural graph before a single bug is chased.",
    detail:
      "Walks the repository to build a dependency and call graph, fingerprints languages and frameworks, and ranks modules by attack-surface exposure — so every later stage searches with priorities, not blindly.",
    chips: ["AST Parsing", "Call Graph", "Dependency Graph", "Attack-Surface Ranking"],
    accent: "steel",
  },
  {
    id: "bugfinding",
    number: "02",
    name: "Bug Finding",
    devanagari: "अन्वेषण",
    line: "Three independent methods hunt in parallel, then converge through a reasoning orchestrator.",
    detail:
      "Static analysis, fuzzing, and LLM-guided review run concurrently against the ranked attack surface. Their findings are not merged blindly — a reasoning orchestrator cross-checks and deduplicates before anything is called a candidate bug.",
    chips: ["Semgrep", "CodeQL", "AFL++", "AFLGo", "LLM Review"],
    accent: "steel",
  },
  {
    id: "verification",
    number: "03",
    name: "Verification",
    devanagari: "सत्यापन",
    line: "Every candidate is proven, not presumed — adversarial concolic escalation confirms real reachability.",
    detail:
      "Candidate findings are pushed through adaptive concolic execution that escalates only where symbolic solving is warranted. A finding earns 'confirmed' status only when a real, reproducible trigger path is constructed — killing false positives before they reach a human.",
    chips: ["Concolic Execution", "Adaptive Escalation", "Crash Triage", "PoC Synthesis"],
    accent: "amber",
  },
  {
    id: "vulndna",
    number: "04",
    name: "VulnDNA Evidence Retrieval",
    devanagari: "साक्ष्य",
    line: "Chakravyuh's key innovation — matches confirmed bugs against a genetic fingerprint of known CVEs.",
    detail:
      "Every confirmed vulnerability is fingerprinted into a structural + semantic signature — its 'DNA' — and matched against a corpus of historic CVEs and fix patterns. This gives the patch engine evidence, not guesses, and gives judges a verifiable trail from bug to precedent.",
    chips: ["Vector Similarity", "CVE Corpus", "Fix-Pattern Library", "Structural Fingerprint"],
    accent: "signal",
    isHeadline: true,
  },
  {
    id: "patchengine",
    number: "05",
    name: "Patch Engine",
    devanagari: "उपचार",
    line: "Three specialist agents race independently; a scoring selector chooses the safest winner.",
    detail:
      "Root-Cause Fixer, Evidence-Guided Fixer, and Direct Fixer each independently generate a candidate patch. The Patch Selector scores every candidate on security, regression risk, performance, and re-discovery — only the highest-scoring, safest patch advances.",
    chips: ["Root-Cause Fixer", "Evidence-Guided Fixer", "Direct Fixer", "Patch Selector"],
    accent: "amber",
  },
  {
    id: "reportgate",
    number: "06",
    name: "Report + Human Gate",
    devanagari: "अनुमोदन",
    line: "The system never deploys itself. Every patch stops at a human before it ships.",
    detail:
      "Chakravyuh compiles an explainable report — root cause, evidence trail, patch diff, and test results — and assigns a SAFE / REVIEW / HOLD status. A human operator makes the final approve or reject call, always. No autonomous deployment, ever.",
    chips: ["Explainable Report", "Risk Classification", "Approve / Reject", "Audit Trail"],
    accent: "red",
    isGate: true,
  },
];

export const bugFindingMethods = [
  { id: "static", label: "Static", tool: "Semgrep · CodeQL", desc: "Pattern & taint analysis across the full call graph." },
  { id: "fuzz", label: "Fuzz", tool: "AFL++ · AFLGo", desc: "Directed, coverage-guided fuzzing at ranked entry points." },
  { id: "llm", label: "LLM", tool: "Reasoning Review", desc: "Contextual code review for logic-level flaws static tools miss." },
];

export const evidenceCard = {
  cveId: "CVE-2023-44487",
  title: "HTTP/2 Rapid Reset — Stream Multiplexing Exhaustion",
  similarity: 94.2,
  snippet: `func (s *Stream) reset(err error) {
    s.conn.streams.delete(s.id)
    // no request-count throttling before delete
    s.conn.metrics.active--
}`,
  fixPattern: "Rate-limit stream resets per connection window before deallocation.",
  confidence: "High",
};

export const patchAgents = [
  {
    id: "rootcause",
    name: "Root-Cause Fixer",
    approach: "Rewrites the underlying logic flaw at its source.",
    strength: "Deepest fix, lowest re-discovery risk",
  },
  {
    id: "evidenceguided",
    name: "Evidence-Guided Fixer",
    approach: "Applies the closest matched historic fix pattern from VulnDNA.",
    strength: "Fastest convergence, precedent-backed",
  },
  {
    id: "direct",
    name: "Direct Fixer",
    approach: "Minimal, surgical patch scoped to the exact trigger path.",
    strength: "Smallest diff, lowest regression surface",
  },
];

export const scoringWeights = [
  { name: "Security", value: 50, color: "#00ff9d" },
  { name: "Regression", value: 25, color: "#6f9db3" },
  { name: "Performance", value: 15, color: "#ffb800" },
  { name: "Re-discovery", value: 10, color: "#ff4d5e" },
];

export const gateStates = [
  {
    id: "safe",
    label: "SAFE",
    color: "signal",
    desc: "Verified fix, no residual risk detected. Recommended for approval.",
  },
  {
    id: "review",
    label: "REVIEW",
    color: "amber",
    desc: "Fix confirmed but touches sensitive scope. Human review required.",
  },
  {
    id: "hold",
    label: "HOLD",
    color: "red",
    desc: "Confidence below threshold or blast radius too large. Do not deploy.",
  },
];
