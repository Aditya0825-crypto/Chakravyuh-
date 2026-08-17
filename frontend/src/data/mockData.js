// ============================================================
// CHAKRAVYUH — Real-Time Production Data Structures
// All mock fallback data disabled for real-time live environment.
// ============================================================

export const systemStats = {
  targetsAnalyzed: 0,
  vulnerabilitiesFound: 0,
  patchesGenerated: 0,
  patchesVerified: 0,
  avgConfidence: 0,
  avgTimeToFix: "—",
  cvesPrevented: 0,
  uptime: "100%",
};

export const pipelineStages = [];
export const reconTargets = [];
export const semgrepFindings = [];
export const fuzzingResults = {
  status: "idle",
  runtime: "0s",
  execsPerSec: 0,
  totalExecs: 0,
  crashesFound: 0,
  uniqueCrashes: 0,
  coverage: 0,
  coverageGain: [],
  targetReached: false,
  escalated: false,
  seeds: 0,
};
export const crashes = [];
export const vulnDNAResults = [];
export const patchCandidates = [];
export const securityReport = null;
export const learningLog = [];
