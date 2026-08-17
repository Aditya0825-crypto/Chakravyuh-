export const judgeCriteria = [
  {
    id: "novelty",
    name: "Novelty",
    proof: "VulnDNA is a genetic-fingerprint match against real CVE precedent — not another LLM guessing at a patch.",
    metric: "1 novel subsystem",
  },
  {
    id: "lightweight",
    name: "Lightweight",
    proof: "Runs entirely on commodity hardware. No GPU cluster, no cloud inference bill.",
    metric: "~5 GB footprint",
  },
  {
    id: "resource",
    name: "Resource Utilisation",
    proof: "Fits inside a single consumer GPU with room to spare for the host OS and tooling.",
    metric: "8 GB VRAM",
  },
  {
    id: "speed",
    name: "Speed",
    proof: "Recon through report generation completes without a human babysitting the pipeline.",
    metric: "6 stages, 1 pass",
  },
  {
    id: "precision",
    name: "Precision",
    proof: "Adaptive concolic verification kills false positives before they ever reach the report.",
    metric: "Proof, not guess",
  },
  {
    id: "scalability",
    name: "Scalability",
    proof: "Stateless, containerized stages mean horizontal scale-out across a codebase fleet.",
    metric: "Fleet-ready",
  },
  {
    id: "realism",
    name: "Realism",
    proof: "Fully open-source, air-gap capable, zero licensing cost — deployable inside a defense network today.",
    metric: "₹0 licensing",
  },
];

export const differentiators = [
  {
    id: "vulndna",
    name: "VulnDNA",
    desc: "A structural + semantic fingerprint for every confirmed bug, matched against a corpus of historic CVEs and their fixes — turning patch generation from guesswork into precedent.",
    featured: true,
  },
  {
    id: "targeted",
    name: "Targeted Discovery",
    desc: "Recon ranks the attack surface before search begins, so fuzzing and static analysis spend their budget where it matters.",
  },
  {
    id: "concolic",
    name: "Adaptive Concolic Escalation",
    desc: "Symbolic execution is invoked only when needed, escalating gradually instead of brute-forcing every path.",
  },
  {
    id: "multiagent",
    name: "Multi-Agent Patch Generation",
    desc: "Three independent fixer agents compete; a scored selector — not a coin flip — picks the safest winner.",
  },
  {
    id: "adversarial",
    name: "Adversarial Verification",
    desc: "Every candidate bug must survive an adversarial reproduction attempt before it's trusted as real.",
  },
  {
    id: "explainable",
    name: "Explainable Reports",
    desc: "Every output traces back to root cause, evidence, and test result — nothing is a black box.",
  },
  {
    id: "humangate",
    name: "Human Safety Gate",
    desc: "No patch ships without a human decision. The system recommends; it never deploys itself.",
  },
];

export const techStack = [
  {
    id: "ai",
    category: "AI Layer",
    items: ["Reasoning Orchestrator", "LLM Code Review", "VulnDNA Embedding Model"],
  },
  {
    id: "security",
    category: "Security Tools",
    items: ["Semgrep", "CodeQL", "AFL++", "AFLGo", "Concolic Execution Engine"],
  },
  {
    id: "data",
    category: "Data Layer",
    items: ["CVE Corpus", "Fix-Pattern Library", "Vector Index", "Audit Log Store"],
  },
  {
    id: "infra",
    category: "Infrastructure",
    items: ["Single Laptop Deployable", "8 GB VRAM", "No Cloud Dependency", "Fully Open-Source"],
  },
];

export const positioning = {
  is: [
    "An autonomous reasoning system that finds, verifies, and proposes fixes for real vulnerabilities.",
    "A precedent-backed patch generator, grounded in historic CVE evidence.",
    "A tool that always stops at a human before anything ships.",
  ],
  isNot: [
    "An autonomous deployment system. Nothing is patched without approval.",
    "An LLM guessing at fixes with no verification behind it.",
    "A cloud service. It runs on hardware you already control.",
  ],
};

export const demoSteps = [
  { id: 1, text: "$ chakravyuh scan --target ./critical-infra-svc", type: "cmd" },
  { id: 2, text: "[recon] mapped 142 modules · attack surface ranked", type: "log" },
  { id: 3, text: "[bugfinding] static+fuzz+llm converged → 7 candidates", type: "log" },
  { id: 4, text: "[verification] adversarial repro confirmed 2 of 7", type: "log" },
  { id: 5, text: "[vulndna] match found → CVE-2023-44487 · 94.2% similarity", type: "success" },
  { id: 6, text: "[patchengine] 3 agents dispatched · scoring candidates...", type: "log" },
  { id: 7, text: "[patchengine] winner: evidence-guided-fixer · score 91/100", type: "success" },
  { id: 8, text: "[report] compiled · risk classification: REVIEW", type: "warn" },
  { id: 9, text: "> awaiting human decision: [A]pprove  [R]eject  [H]old", type: "prompt" },
];
