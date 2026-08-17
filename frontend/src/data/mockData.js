// ============================================================
// CHAKRAVYUH v4.1 — Mock Data
// ============================================================

export const systemStats = {
  targetsAnalyzed: 47,
  vulnerabilitiesFound: 23,
  patchesGenerated: 89,
  patchesVerified: 71,
  avgConfidence: 87.4,
  avgTimeToFix: "4m 32s",
  cvesPrevented: 23,
  uptime: "99.8%",
};

export const pipelineStages = [
  { id: 1, name: "Recon Engine", status: "complete", icon: "radar", duration: "12s" },
  { id: 2, name: "Bug Finding", status: "complete", icon: "bug", duration: "4m 18s" },
  { id: 3, name: "PoV Verifier", status: "complete", icon: "check-shield", duration: "23s" },
  { id: 4, name: "VulnDNA", status: "complete", icon: "dna", duration: "84ms" },
  { id: 5, name: "Patch Engine", status: "running", icon: "wrench", duration: "1m 47s..." },
  { id: 6, name: "Report + Gate", status: "pending", icon: "file-lock", duration: "—" },
];

export const reconTargets = [
  {
    id: "fn-001",
    function: "handle_request()",
    file: "src/server.c",
    line: 142,
    risk: "CRITICAL",
    reason: "strcpy + user input + reachable sink",
    sinks: ["strcpy", "sprintf"],
    callPath: "main() → accept_conn() → handle_request()",
    inputSources: ["network socket", "HTTP headers"],
    score: 97,
  },
  {
    id: "fn-002",
    function: "parse_header()",
    file: "src/parser.c",
    line: 87,
    risk: "HIGH",
    reason: "sprintf + network data, no bounds check",
    sinks: ["sprintf"],
    callPath: "handle_request() → parse_header()",
    inputSources: ["HTTP headers"],
    score: 78,
  },
  {
    id: "fn-003",
    function: "load_config()",
    file: "src/config.c",
    line: 34,
    line: 34,
    risk: "HIGH",
    reason: "system() call with partial user control",
    sinks: ["system"],
    callPath: "main() → init() → load_config()",
    inputSources: ["config file (user-writable)"],
    score: 71,
  },
  {
    id: "fn-004",
    function: "log_access()",
    file: "src/logger.c",
    line: 211,
    risk: "MEDIUM",
    reason: "fprintf with format string from caller",
    sinks: ["fprintf"],
    callPath: "handle_request() → log_access()",
    inputSources: ["request URI"],
    score: 52,
  },
  {
    id: "fn-005",
    function: "render_page()",
    file: "src/render.c",
    line: 68,
    risk: "LOW",
    reason: "No dangerous patterns detected",
    sinks: [],
    callPath: "handle_request() → render_page()",
    inputSources: [],
    score: 12,
  },
];

export const semgrepFindings = [
  {
    id: "sg-001",
    rule: "c.lang.security.insecure-use-strcpy.insecure-use-strcpy",
    file: "src/server.c",
    line: 148,
    severity: "ERROR",
    message: "Dangerous use of strcpy() — buffer overflow possible",
    code: `  strcpy(req->body, input_buffer);`,
  },
  {
    id: "sg-002",
    rule: "c.lang.security.insecure-use-sprintf.insecure-use-sprintf",
    file: "src/parser.c",
    line: 91,
    severity: "ERROR",
    message: "sprintf() with unbounded user-controlled string",
    code: `  sprintf(header_buf, "HTTP/1.1 %s\\r\\n", raw_header);`,
  },
  {
    id: "sg-003",
    rule: "c.lang.security.system-call-with-user-input",
    file: "src/config.c",
    line: 37,
    severity: "WARNING",
    message: "system() called with partially user-controlled argument",
    code: `  system(cmd_buf);`,
  },
];

export const fuzzingResults = {
  status: "complete",
  runtime: "4m 18s",
  execsPerSec: 12400,
  totalExecs: 3189120,
  crashesFound: 7,
  uniqueCrashes: 3,
  coverage: 67.4,
  coverageGain: [12, 28, 41, 55, 61, 65, 67, 67.4],
  targetReached: true,
  escalated: false,
  seeds: 14,
};

export const crashes = [
  {
    id: "crash-001",
    status: "verified",
    type: "Heap Buffer Overflow",
    cwe: "CWE-122",
    file: "src/server.c",
    line: 148,
    function: "handle_request()",
    severity: "CRITICAL",
    signal: "SIGABRT",
    returnCode: 134,
    confidence: 96,
    asanSummary: "heap-buffer-overflow WRITE of size 512 at 0x603000000050",
    stackTrace: [
      "__asan_report_error",
      "strcpy (src/server.c:148)",
      "handle_request (src/server.c:142)",
      "accept_conn (src/network.c:77)",
      "main (src/main.c:23)",
    ],
    reproduced: true,
    deduplicated: false,
    crashInput: "POST /api/data HTTP/1.1\\r\\nContent-Length: 65536\\r\\n\\r\\n" + "A".repeat(512),
  },
  {
    id: "crash-002",
    status: "verified",
    type: "Stack Buffer Overflow",
    cwe: "CWE-121",
    file: "src/parser.c",
    line: 91,
    function: "parse_header()",
    severity: "HIGH",
    signal: "SIGSEGV",
    returnCode: 139,
    confidence: 83,
    asanSummary: "stack-buffer-overflow WRITE of size 256 at 0x7fff50a1b080",
    stackTrace: [
      "__asan_report_error",
      "sprintf (src/parser.c:91)",
      "parse_header (src/parser.c:87)",
      "handle_request (src/server.c:142)",
      "main (src/main.c:23)",
    ],
    reproduced: true,
    deduplicated: false,
    crashInput: "GET / HTTP/1.1\\r\\nX-Custom: " + "B".repeat(300),
  },
  {
    id: "crash-003",
    status: "verified",
    type: "Use-After-Free",
    cwe: "CWE-416",
    file: "src/session.c",
    line: 204,
    function: "destroy_session()",
    severity: "HIGH",
    signal: "SIGABRT",
    returnCode: 134,
    confidence: 77,
    asanSummary: "heap-use-after-free READ of size 8 at 0x602000000050",
    stackTrace: [
      "__asan_report_error",
      "destroy_session (src/session.c:204)",
      "cleanup_handler (src/server.c:301)",
      "handle_request (src/server.c:142)",
    ],
    reproduced: true,
    deduplicated: false,
    crashInput: "<binary session teardown sequence>",
  },
];

export const vulnDNAResults = [
  {
    cveId: "CVE-2021-3156",
    similarity: 91.3,
    cwe: "CWE-122",
    title: "sudo Heap-Based Buffer Overflow",
    project: "sudo",
    language: "C",
    function: "set_cmnd()",
    vulnerableCode: `strcpy(cmnd_buf, user_cmnd);`,
    patch: `- strcpy(cmnd_buf, user_cmnd);\n+ if (strlen(user_cmnd) >= cmnd_size) {\n+   fatalx("command too long");\n+ }\n+ strlcpy(cmnd_buf, user_cmnd, cmnd_size);`,
    fixPattern: "Replace strcpy with strlcpy + explicit bounds check before copy",
    whyItWorks: "Enforces max length before any write occurs; terminates safely on overflow attempt",
  },
  {
    cveId: "CVE-2022-0778",
    similarity: 84.7,
    cwe: "CWE-122",
    title: "OpenSSL Infinite Loop via Crafted Certificate",
    project: "OpenSSL",
    language: "C",
    function: "BN_mod_sqrt()",
    vulnerableCode: `memcpy(out_buf, in_buf, user_len);`,
    patch: `- memcpy(out_buf, in_buf, user_len);\n+ if (user_len > sizeof(out_buf)) return -1;\n+ memcpy(out_buf, in_buf, user_len);`,
    fixPattern: "Bounds check before memcpy using sizeof(destination)",
    whyItWorks: "Prevents write beyond allocation by validating length against actual buffer size",
  },
  {
    cveId: "CVE-2021-44228",
    similarity: 71.2,
    cwe: "CWE-117",
    title: "Log4Shell — JNDI Injection",
    project: "log4j",
    language: "Java",
    function: "MessagePatternConverter.format()",
    vulnerableCode: `sprintf(log_buf, format_str, user_input);`,
    patch: `- sprintf(log_buf, format_str, user_input);\n+ snprintf(log_buf, sizeof(log_buf), "%s", sanitized_input);`,
    fixPattern: "Replace sprintf with snprintf; sanitize format string input",
    whyItWorks: "Size-bounded write + format string neutralization prevents injection and overflow",
  },
  {
    cveId: "CVE-2019-0708",
    similarity: 65.8,
    cwe: "CWE-416",
    title: "BlueKeep — RDP Use-After-Free",
    project: "Windows RDP",
    language: "C",
    function: "MCSChannelJoinRequest()",
    vulnerableCode: `// object freed but pointer not nullified\nfree(channel);\n// ... later ...\nchannel->state = ACTIVE;`,
    patch: `  free(channel);\n+ channel = NULL;\n  // ... later ...\n+ if (channel == NULL) return ERR_INVALID;\n  channel->state = ACTIVE;`,
    fixPattern: "NULL pointer after free; guard all subsequent dereferences",
    whyItWorks: "Prevents dangling pointer dereference by invalidating pointer immediately after free",
  },
  {
    cveId: "CVE-2018-11776",
    similarity: 58.4,
    cwe: "CWE-122",
    title: "Apache Struts2 Remote Code Execution",
    project: "Apache Struts2",
    language: "Java",
    function: "DefaultActionMapper.handleSpecialParameters()",
    vulnerableCode: `execCommand(user_input);`,
    patch: `- execCommand(user_input);\n+ if (!isAllowedCommand(user_input)) throw new SecurityException("Blocked");\n+ execCommand(user_input);`,
    fixPattern: "Allowlist validation before command execution",
    whyItWorks: "Restricts executable commands to a predefined safe set before any execution occurs",
  },
];

export const patchCandidates = [
  {
    agent: "Agent 1",
    name: "Root Cause Fixer",
    strategy: "Traced tainted data flow from network socket → handle_request → strcpy. Replaces strcpy with strnlen-validated strncpy.",
    score: {
      security: 95,
      regression: 88,
      performance: 97,
      rediscovery: 100,
      total: 94.35,
    },
    status: "SELECTED",
    diff: `--- a/src/server.c
+++ b/src/server.c
@@ -140,9 +140,14 @@
 void handle_request(Connection *conn, const char *input_buffer) {
     Request *req = alloc_request();
-    strcpy(req->body, input_buffer);
+    size_t input_len = strnlen(input_buffer, MAX_BODY_SIZE + 1);
+    if (input_len > MAX_BODY_SIZE) {
+        send_error(conn, 413, "Request Entity Too Large");
+        free_request(req);
+        return;
+    }
+    memcpy(req->body, input_buffer, input_len + 1);
     process_request(conn, req);
     free_request(req);
 }`,
    linesChanged: 6,
    filesChanged: 1,
    verificationPassed: true,
    attacks: { blocked: 9, total: 9 },
    regressionTests: { passed: 47, total: 47 },
    performanceOverhead: "1.2%",
  },
  {
    agent: "Agent 2",
    name: "Evidence-Guided Fixer (VulnDNA)",
    strategy: "Adapted CVE-2021-3156 sudo fix pattern. Uses strlcpy equivalent with pre-validation, matching the proven fix from the sudo project.",
    score: {
      security: 95,
      regression: 76,
      performance: 91,
      rediscovery: 100,
      total: 89.65,
    },
    status: "REJECTED",
    rejectedReason: "Regression test failure in legacy_compat_handler — strlcpy not available in all build targets",
    diff: `--- a/src/server.c
+++ b/src/server.c
@@ -140,7 +140,12 @@
 void handle_request(Connection *conn, const char *input_buffer) {
     Request *req = alloc_request();
-    strcpy(req->body, input_buffer);
+    if (strlcpy(req->body, input_buffer, MAX_BODY_SIZE) >= MAX_BODY_SIZE) {
+        log_warn("Input truncated — possible overflow attempt");
+        send_error(conn, 400, "Bad Request");
+        free_request(req);
+        return;
+    }
     process_request(conn, req);
     free_request(req);
 }`,
    linesChanged: 5,
    filesChanged: 1,
    verificationPassed: false,
    attacks: { blocked: 9, total: 9 },
    regressionTests: { passed: 43, total: 47 },
    performanceOverhead: "0.9%",
  },
  {
    agent: "Agent 3",
    name: "Direct Fixer",
    strategy: "Minimal surgical fix — adds snprintf with hard limit. Preserves all existing behavior with minimum code change.",
    score: {
      security: 90,
      regression: 88,
      performance: 99,
      rediscovery: 90,
      total: 91.25,
    },
    status: "REJECTED",
    rejectedReason: "Re-discovery fuzzing found a variant path that still triggered overflow via null-terminator edge case",
    diff: `--- a/src/server.c
+++ b/src/server.c
@@ -140,6 +140,6 @@
 void handle_request(Connection *conn, const char *input_buffer) {
     Request *req = alloc_request();
-    strcpy(req->body, input_buffer);
+    snprintf(req->body, MAX_BODY_SIZE, "%s", input_buffer);
     process_request(conn, req);
     free_request(req);
 }`,
    linesChanged: 1,
    filesChanged: 1,
    verificationPassed: false,
    attacks: { blocked: 8, total: 9 },
    regressionTests: { passed: 47, total: 47 },
    performanceOverhead: "0.4%",
  },
];

export const securityReport = {
  id: "CHK-2026-0047",
  timestamp: "2026-08-13T21:47:33Z",
  target: "vulnerable_server v2.1.4",
  vulnerability: {
    type: "Heap Buffer Overflow",
    cweId: "CWE-122",
    cweName: "Heap-based Buffer Overflow",
    location: "src/server.c:148",
    function: "handle_request()",
    severity: "CRITICAL",
    cvssScore: 9.8,
  },
  rootCause: `Tainted data enters via network socket in accept_conn() (src/network.c:77). It is passed as input_buffer to handle_request() without length validation. strcpy() at line 148 copies the unbounded input directly into a fixed-size heap allocation (req->body, 512 bytes). An attacker sending more than 512 bytes triggers a heap-buffer-overflow, enabling arbitrary code execution.`,
  selectedPatch: patchCandidates[0],
  confidence: 96,
  recommendation: "SAFE",
  humanDecision: null,
  vulnDNATopMatch: { cveId: "CVE-2021-3156", similarity: 91.3 },
  numSimilarCVEs: 5,
};

export const learningLog = [
  {
    id: "log-001",
    date: "2026-08-13",
    target: "vulnerable_server",
    cwe: "CWE-122",
    crashType: "Heap Buffer Overflow",
    discoveryMethod: "AFL++ + Directed Fuzzing",
    winningAgent: "Agent 1 — Root Cause Fixer",
    confidence: 96,
    patchSuccess: true,
    topCVE: "CVE-2021-3156",
    notes: "strcpy → strnlen + memcpy. All 47 regression tests passed.",
  },
  {
    id: "log-002",
    date: "2026-08-11",
    target: "auth_service",
    cwe: "CWE-89",
    crashType: "SQL Injection",
    discoveryMethod: "Semgrep + LLM Analysis",
    winningAgent: "Agent 2 — Evidence-Guided Fixer",
    confidence: 91,
    patchSuccess: true,
    topCVE: "CVE-2019-11358",
    notes: "Parameterized query replacement. CVE-2019-11358 pattern adapted.",
  },
  {
    id: "log-003",
    date: "2026-08-09",
    target: "file_parser",
    cwe: "CWE-416",
    crashType: "Use-After-Free",
    discoveryMethod: "AFL++ + Concolic Escalation",
    winningAgent: "Agent 1 — Root Cause Fixer",
    confidence: 84,
    patchSuccess: true,
    topCVE: "CVE-2019-0708",
    notes: "NULL after free + guard check. Concolic escalation reached the branch.",
  },
  {
    id: "log-004",
    date: "2026-08-07",
    target: "network_stack",
    cwe: "CWE-476",
    crashType: "NULL Pointer Dereference",
    discoveryMethod: "Static Analysis (Semgrep)",
    winningAgent: "Agent 3 — Direct Fixer",
    confidence: 79,
    patchSuccess: true,
    topCVE: "CVE-2021-20317",
    notes: "NULL guard inserted before dereference. Static analysis alone sufficient.",
  },
  {
    id: "log-005",
    date: "2026-08-05",
    target: "crypto_lib",
    cwe: "CWE-190",
    crashType: "Integer Overflow",
    discoveryMethod: "AFL++ + LLM Seed Generation",
    winningAgent: "Agent 2 — Evidence-Guided Fixer",
    confidence: 88,
    patchSuccess: true,
    topCVE: "CVE-2022-1292",
    notes: "Safe multiplication with overflow check. LLM-generated boundary seeds were key.",
  },
  {
    id: "log-006",
    date: "2026-08-02",
    target: "http_proxy",
    cwe: "CWE-121",
    crashType: "Stack Buffer Overflow",
    discoveryMethod: "AFL++ + Directed Fuzzing",
    winningAgent: "Agent 1 — Root Cause Fixer",
    confidence: 92,
    patchSuccess: false,
    topCVE: "CVE-2020-1971",
    notes: "All 3 patches failed verification. Requires manual review — complex aliasing.",
  },
];
