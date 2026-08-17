// Mock operational data for the Chakravyuh console.
// Every scan represents one pipeline run against a target codebase.

export const stageOrder = [
  "recon",
  "bugfinding",
  "verification",
  "vulndna",
  "patchengine",
  "reportgate",
];

export const stageLabels = {
  recon: "Recon",
  bugfinding: "Bug Finding",
  verification: "Verification",
  vulndna: "VulnDNA",
  patchengine: "Patch Engine",
  reportgate: "Report + Gate",
};

export const scans = [
  {
    id: "scan-0142",
    target: "critical-infra-svc",
    repo: "git.mil/army-cyber/critical-infra-svc",
    branch: "release/4.2",
    startedAt: "2026-08-13T05:12:00Z",
    status: "review", // running | completed(safe) | review | hold | queued
    currentStage: "reportgate",
    durationSec: 812,
    linesScanned: 48210,
    findings: [
      {
        id: "f-1",
        title: "HTTP/2 Rapid Reset — Stream Multiplexing Exhaustion",
        cve: "CVE-2023-44487",
        severity: "critical",
        file: "internal/http2/stream.go",
        line: 214,
        similarity: 94.2,
        method: "Fuzz",
        status: "patched",
      },
      {
        id: "f-2",
        title: "Unbounded goroutine spawn on malformed frame",
        cve: null,
        severity: "medium",
        file: "internal/http2/frame.go",
        line: 88,
        similarity: null,
        method: "Static",
        status: "confirmed",
      },
    ],
    patch: {
      agent: "Evidence-Guided Fixer",
      score: 91,
      diffLines: 14,
      filesChanged: 2,
      breakdown: { security: 47, regression: 22, performance: 13, rediscovery: 9 },
    },
    gate: {
      status: "review",
      reason: "Fix touches connection-pool lifecycle — sensitive scope.",
      submittedAt: "2026-08-13T05:25:40Z",
    },
  },
  {
    id: "scan-0141",
    target: "auth-gateway",
    repo: "git.mil/army-cyber/auth-gateway",
    branch: "main",
    startedAt: "2026-08-12T22:04:00Z",
    status: "safe",
    currentStage: "reportgate",
    durationSec: 664,
    linesScanned: 31890,
    findings: [
      {
        id: "f-3",
        title: "JWT signature check bypass on empty `alg`",
        cve: "CVE-2022-23540",
        severity: "critical",
        file: "auth/jwt_verify.go",
        line: 52,
        similarity: 98.6,
        method: "LLM",
        status: "patched",
      },
    ],
    patch: {
      agent: "Root-Cause Fixer",
      score: 96,
      diffLines: 6,
      filesChanged: 1,
      breakdown: { security: 49, regression: 24, performance: 14, rediscovery: 9 },
    },
    gate: {
      status: "safe",
      reason: "Verified fix, no residual risk detected.",
      submittedAt: "2026-08-12T22:15:10Z",
      decidedAt: "2026-08-12T22:31:02Z",
      decidedBy: "Capt. R. Menon",
    },
  },
  {
    id: "scan-0140",
    target: "telemetry-ingest",
    repo: "git.mil/army-cyber/telemetry-ingest",
    branch: "main",
    startedAt: "2026-08-12T18:40:00Z",
    status: "hold",
    currentStage: "reportgate",
    durationSec: 1120,
    linesScanned: 67340,
    findings: [
      {
        id: "f-4",
        title: "Deserialization of untrusted protobuf field",
        cve: "CVE-2024-1597",
        severity: "high",
        file: "ingest/decode.go",
        line: 301,
        similarity: 76.4,
        method: "Static",
        status: "confirmed",
      },
      {
        id: "f-5",
        title: "Integer overflow in batch size calculation",
        cve: null,
        severity: "medium",
        file: "ingest/batch.go",
        line: 44,
        similarity: null,
        method: "Fuzz",
        status: "confirmed",
      },
    ],
    patch: {
      agent: "Direct Fixer",
      score: 68,
      diffLines: 41,
      filesChanged: 5,
      breakdown: { security: 32, regression: 14, performance: 12, rediscovery: 5 },
    },
    gate: {
      status: "hold",
      reason: "Confidence below threshold — blast radius spans 5 files. Do not deploy.",
      submittedAt: "2026-08-12T19:05:55Z",
    },
  },
  {
    id: "scan-0143",
    target: "field-comms-relay",
    repo: "git.mil/army-cyber/field-comms-relay",
    branch: "develop",
    startedAt: "2026-08-13T06:02:00Z",
    status: "running",
    currentStage: "verification",
    durationSec: 194,
    linesScanned: 22014,
    findings: [
      {
        id: "f-6",
        title: "Race condition in relay session table",
        cve: null,
        severity: "high",
        file: "relay/session.go",
        line: 129,
        similarity: null,
        method: "Fuzz",
        status: "candidate",
      },
    ],
    patch: null,
    gate: null,
  },
  {
    id: "scan-0139",
    target: "provisioning-api",
    repo: "git.mil/army-cyber/provisioning-api",
    branch: "main",
    startedAt: "2026-08-11T09:15:00Z",
    status: "safe",
    currentStage: "reportgate",
    durationSec: 540,
    linesScanned: 19870,
    findings: [
      {
        id: "f-7",
        title: "Path traversal via unsanitized template name",
        cve: "CVE-2021-41773",
        severity: "high",
        file: "provision/template.go",
        line: 77,
        similarity: 89.1,
        method: "Static",
        status: "patched",
      },
    ],
    patch: {
      agent: "Evidence-Guided Fixer",
      score: 93,
      diffLines: 9,
      filesChanged: 1,
      breakdown: { security: 48, regression: 23, performance: 14, rediscovery: 8 },
    },
    gate: {
      status: "safe",
      reason: "Verified fix, no residual risk detected.",
      submittedAt: "2026-08-11T09:24:30Z",
      decidedAt: "2026-08-11T09:40:12Z",
      decidedBy: "Capt. R. Menon",
    },
  },
  {
    id: "scan-0144",
    target: "log-aggregator",
    repo: "git.mil/army-cyber/log-aggregator",
    branch: "main",
    startedAt: "2026-08-13T06:20:00Z",
    status: "queued",
    currentStage: "recon",
    durationSec: 0,
    linesScanned: 0,
    findings: [],
    patch: null,
    gate: null,
  },
];

export const statusMeta = {
  safe: { label: "Safe", color: "signal" },
  review: { label: "Review", color: "amber" },
  hold: { label: "Hold", color: "red" },
  running: { label: "Running", color: "steel" },
  queued: { label: "Queued", color: "ink" },
};

export const severityMeta = {
  critical: { label: "Critical", color: "red" },
  high: { label: "High", color: "amber" },
  medium: { label: "Medium", color: "steel" },
  low: { label: "Low", color: "ink" },
};

export function getScan(id) {
  return scans.find((s) => s.id === id);
}

export function pendingGateScans() {
  return scans.filter((s) => s.gate && (s.gate.status === "review" || s.gate.status === "hold") && !s.gate.decidedAt);
}

export function allFindings() {
  return scans.flatMap((s) => s.findings.map((f) => ({ ...f, scanId: s.id, target: s.target })));
}

export function evidenceMatches() {
  return allFindings().filter((f) => f.cve);
}
