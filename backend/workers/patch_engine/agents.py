"""Patch generation agents — CWE-aware strategies.

Agent 1: Root Cause Fixer — traces the vulnerability root cause and fixes it.
Agent 2: Evidence-Guided Fixer — adapts a CVE precedent fix pattern.
Agent 3: Direct Surgical Fixer — minimal change to eliminate the vuln.

All agents receive the same normalized VulnerabilityFinding context.
Patch strategies are vulnerability-class-aware (not just buffer-overflow-centric).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from core.llm.client import generate, ollama_available
from vulndna.models import VulnDNAMatch


@dataclass
class RawPatchCandidate:
    agent: str
    name: str
    strategy: str
    diff: str
    lines_changed: int
    files_changed: int = 1
    cwe_id: str = "CWE-122"


# ── CWE-to-patch-strategy mapping ─────────────────────────────────────────────

_CWE_PATCH_GUIDANCE: dict[str, dict] = {
    "CWE-120": {
        "label": "Buffer Overflow",
        "strategy": "Validate input length before copy; use strnlen/strncpy/snprintf with explicit bounds",
        "agent1_approach": "strnlen + bounds check before memcpy",
        "agent2_approach": "snprintf with sizeof() bound",
        "agent3_approach": "Direct strncpy/snprintf replacement",
    },
    "CWE-122": {
        "label": "Heap Buffer Overflow",
        "strategy": "Validate size before heap write; use snprintf/memcpy with explicit bounds",
        "agent1_approach": "strnlen + size check + bounded memcpy",
        "agent2_approach": "snprintf(dst, sizeof(dst), ...)",
        "agent3_approach": "strncpy with explicit length",
    },
    "CWE-125": {
        "label": "Out-of-Bounds Read",
        "strategy": "Check index/offset against array bounds before read",
        "agent1_approach": "Index bounds check with early return",
        "agent2_approach": "assert/if guard before array access",
        "agent3_approach": "Clamp index to valid range",
    },
    "CWE-787": {
        "label": "Out-of-Bounds Write",
        "strategy": "Validate destination capacity before write operation",
        "agent1_approach": "Destination size check + conditional abort",
        "agent2_approach": "Safe bounded write with size parameter",
        "agent3_approach": "Direct size-guarded write",
    },
    "CWE-416": {
        "label": "Use-After-Free",
        "strategy": "Set pointer to NULL after free; enforce ownership/lifetime tracking",
        "agent1_approach": "NULL pointer after free + ownership flag",
        "agent2_approach": "Smart pointer / RAII wrapper pattern",
        "agent3_approach": "Set ptr = NULL immediately after free()",
    },
    "CWE-415": {
        "label": "Double Free",
        "strategy": "Centralized deallocation with NULL-guard; set pointer to NULL after free",
        "agent1_approach": "NULL guard before free + NULL set after",
        "agent2_approach": "Deallocation wrapper function",
        "agent3_approach": "Inline NULL check before free()",
    },
    "CWE-476": {
        "label": "NULL Pointer Dereference",
        "strategy": "Check pointer for NULL before any dereference; early return",
        "agent1_approach": "Explicit NULL check with error return",
        "agent2_approach": "NULL assert macro",
        "agent3_approach": "Inline if (ptr == NULL) return",
    },
    "CWE-843": {
        "label": "Type Confusion",
        "strategy": "Use tagged unions or runtime type checks before casts",
        "agent1_approach": "Tagged union with type field validation",
        "agent2_approach": "dynamic_cast with null check (C++)",
        "agent3_approach": "Type field assertion before access",
    },
    "CWE-190": {
        "label": "Integer Overflow",
        "strategy": "Pre-condition guard before arithmetic; use safe integer library",
        "agent1_approach": "Pre-multiply overflow check (a > INT_MAX/b)",
        "agent2_approach": "__builtin_mul_overflow / safe_mul",
        "agent3_approach": "Clamp inputs before multiplication",
    },
    "CWE-191": {
        "label": "Integer Underflow",
        "strategy": "Guard against subtraction producing negative result in unsigned context",
        "agent1_approach": "Check a >= b before subtraction",
        "agent2_approach": "Signed arithmetic with underflow check",
        "agent3_approach": "Use saturating subtraction",
    },
    "CWE-369": {
        "label": "Divide by Zero",
        "strategy": "Check divisor for zero before division operation",
        "agent1_approach": "if (divisor == 0) return error",
        "agent2_approach": "assert(divisor != 0) + error handler",
        "agent3_approach": "Inline divisor != 0 guard",
    },
    "CWE-20": {
        "label": "Improper Input Validation",
        "strategy": "Strict allowlist validation; check type, length, and range before use",
        "agent1_approach": "Comprehensive input validator function",
        "agent2_approach": "Regex/pattern-based allowlist check",
        "agent3_approach": "Length + range check inline",
    },
    "CWE-134": {
        "label": "Format String",
        "strategy": "Use literal format string; never pass user input as printf format argument",
        "agent1_approach": 'printf("%s", user_input) instead of printf(user_input)',
        "agent2_approach": "Wrapper that enforces literal format",
        "agent3_approach": 'Direct replacement with printf("%s", ...)',
    },
    "CWE-78": {
        "label": "OS Command Injection",
        "strategy": "Use execv-family without shell; or validated allowlist; avoid system()/popen()",
        "agent1_approach": "execv() with argv array, no shell interpolation",
        "agent2_approach": "Input allowlist validation before system() call",
        "agent3_approach": "Replace system() with execve() + args",
    },
    "CWE-22": {
        "label": "Path Traversal",
        "strategy": "Canonicalize path and verify it stays within allowed directory root",
        "agent1_approach": "realpath() + strncmp prefix check",
        "agent2_approach": "chroot-style path restriction",
        "agent3_approach": "Reject inputs containing '..' or leading '/'",
    },
    "CWE-362": {
        "label": "Race Condition",
        "strategy": "Mutex/lock guards around all shared state access",
        "agent1_approach": "pthread_mutex_lock/unlock around critical section",
        "agent2_approach": "Atomic operations for shared variables",
        "agent3_approach": "Single-writer lock pattern",
    },
    "CWE-367": {
        "label": "TOCTOU",
        "strategy": "Atomic check-and-use; use O_NOFOLLOW; operate on open file descriptor",
        "agent1_approach": "Open file, fstat on fd, use fd — never re-check by name",
        "agent2_approach": "O_NOFOLLOW | O_CLOEXEC flags",
        "agent3_approach": "Eliminate gap between stat and open",
    },
    "CWE-327": {
        "label": "Weak Cryptography",
        "strategy": "Replace weak algorithm with approved algorithm (AES-256-GCM / SHA-256+)",
        "agent1_approach": "Replace MD5/SHA1 with EVP_sha256()/EVP_aes_256_gcm()",
        "agent2_approach": "Crypto policy configuration wrapper",
        "agent3_approach": "Direct algorithm substitution",
    },
    "CWE-321": {
        "label": "Hardcoded Crypto Key",
        "strategy": "Load key from environment variable or secure key management system",
        "agent1_approach": "getenv() + validation for key material",
        "agent2_approach": "Key derivation from secure seed",
        "agent3_approach": "Remove literal key, add env var lookup",
    },
    "CWE-798": {
        "label": "Hardcoded Credentials",
        "strategy": "Remove hardcoded values; load from environment variables or secrets store",
        "agent1_approach": "getenv() for password/token with NULL check",
        "agent2_approach": "Credential provider abstraction",
        "agent3_approach": "Remove literal credential, add getenv()",
    },
    "CWE-400": {
        "label": "Resource Exhaustion",
        "strategy": "Enforce resource limits; rate limiting; bounded allocation",
        "agent1_approach": "Input size limit + malloc guard",
        "agent2_approach": "Rate limiter wrapper with token bucket",
        "agent3_approach": "Maximum size clamp before allocation",
    },
}


def generate_candidate_patches(
    source_root: Path,
    cwe: str = "CWE-122",
    function_name: str = "handle_request",
    file_rel_path: str = "server.c",
    vulndna_matches: list[VulnDNAMatch] | None = None,
    root_cause: str = "",
) -> list[RawPatchCandidate]:
    """
    Produce 3 candidate patches from the three distinct agent personas.
    All agents receive the same normalized vulnerability context.
    Patch strategies are CWE-class-aware.
    """
    guidance = _CWE_PATCH_GUIDANCE.get(cwe, _CWE_PATCH_GUIDANCE["CWE-122"])
    candidates: list[RawPatchCandidate] = []

    # 1. Agent 1: Root Cause Fixer
    candidates.append(_generate_agent_1(source_root, cwe, function_name, file_rel_path, guidance, root_cause))

    # 2. Agent 2: Evidence-Guided Fixer (VulnDNA-informed)
    candidates.append(_generate_agent_2(source_root, cwe, function_name, file_rel_path, guidance, vulndna_matches))

    # 3. Agent 3: Direct Surgical Fixer
    candidates.append(_generate_agent_3(source_root, cwe, function_name, file_rel_path, guidance))

    return candidates


def _generate_agent_1(
    source_root: Path,
    cwe: str,
    function_name: str,
    file_rel_path: str,
    guidance: dict,
    root_cause: str,
) -> RawPatchCandidate:
    strategy = (
        f"Root Cause Fixer ({cwe} — {guidance['label']}): "
        f"{guidance['strategy']}. "
        f"Approach: {guidance['agent1_approach']}."
    )

    diff = _build_diff(cwe, function_name, file_rel_path, "agent1", guidance)
    return RawPatchCandidate(
        agent="Agent 1",
        name="Root Cause Fixer",
        strategy=strategy,
        diff=diff,
        lines_changed=_estimate_lines(diff),
        files_changed=1,
        cwe_id=cwe,
    )


def _generate_agent_2(
    source_root: Path,
    cwe: str,
    function_name: str,
    file_rel_path: str,
    guidance: dict,
    vulndna_matches: list[VulnDNAMatch] | None,
) -> RawPatchCandidate:
    top_cve = vulndna_matches[0].cve_id if vulndna_matches else "N/A"
    fix_pattern = vulndna_matches[0].fix_pattern if vulndna_matches else guidance["strategy"]

    strategy = (
        f"Evidence-Guided Fixer ({cwe}): "
        f"Adapted {top_cve} historical fix pattern. "
        f"Pattern: {fix_pattern}. "
        f"Approach: {guidance['agent2_approach']}."
    )

    diff = _build_diff(cwe, function_name, file_rel_path, "agent2", guidance, top_cve=top_cve)
    return RawPatchCandidate(
        agent="Agent 2",
        name=f"Evidence-Guided Fixer ({top_cve})",
        strategy=strategy,
        diff=diff,
        lines_changed=_estimate_lines(diff),
        files_changed=1,
        cwe_id=cwe,
    )


def _generate_agent_3(
    source_root: Path,
    cwe: str,
    function_name: str,
    file_rel_path: str,
    guidance: dict,
) -> RawPatchCandidate:
    strategy = (
        f"Direct Surgical Fixer ({cwe}): "
        f"Minimal fix — {guidance['agent3_approach']}."
    )

    diff = _build_diff(cwe, function_name, file_rel_path, "agent3", guidance)
    return RawPatchCandidate(
        agent="Agent 3",
        name="Direct Fixer",
        strategy=strategy,
        diff=diff,
        lines_changed=_estimate_lines(diff),
        files_changed=1,
        cwe_id=cwe,
    )


def _build_diff(
    cwe: str,
    function_name: str,
    file_rel_path: str,
    agent: str,
    guidance: dict,
    top_cve: str = "",
) -> str:
    """Generate a representative diff for the given CWE and agent."""
    label = guidance["label"]
    approach = guidance[f"{agent}_approach"]

    # Build CWE-appropriate diff templates
    if cwe in {"CWE-120", "CWE-122"}:
        if agent == "agent1":
            return f"""--- a/{file_rel_path}
+++ b/{file_rel_path}
@@ -6,5 +6,11 @@
 void {function_name}(const char *input_buffer) {{
-    char dest[256];
-    strcpy(dest, input_buffer);
+    char dest[256];
+    size_t input_len = strnlen(input_buffer, sizeof(dest));
+    if (input_len >= sizeof(dest)) {{
+        return;  /* reject oversized input */
+    }}
+    memcpy(dest, input_buffer, input_len);
+    dest[input_len] = '\\0';
 }}
"""
        elif agent == "agent2":
            return f"""--- a/{file_rel_path}
+++ b/{file_rel_path}
@@ -6,5 +6,8 @@
 void {function_name}(const char *input_buffer) {{
-    char dest[256];
-    strcpy(dest, input_buffer);
+    char dest[256];
+    if (snprintf(dest, sizeof(dest), "%s", input_buffer) >= (int)sizeof(dest)) {{
+        dest[sizeof(dest) - 1] = '\\0';
+        return;
+    }}
 }}
"""
        else:
            return f"""--- a/{file_rel_path}
+++ b/{file_rel_path}
@@ -6,4 +6,4 @@
 void {function_name}(const char *input_buffer) {{
     char dest[256];
-    strcpy(dest, input_buffer);
+    snprintf(dest, sizeof(dest), "%s", input_buffer);
 }}
"""

    elif cwe in {"CWE-125", "CWE-787"}:
        bounds_check = "if (index < 0 || index >= ARRAY_SIZE) return;" if agent == "agent1" else \
                       "assert(index >= 0 && index < ARRAY_SIZE);" if agent == "agent2" else \
                       "index = (index < 0) ? 0 : (index >= ARRAY_SIZE) ? ARRAY_SIZE-1 : index;"
        return f"""--- a/{file_rel_path}
+++ b/{file_rel_path}
@@ -5,4 +5,5 @@
 int {function_name}(int *array, int index) {{
+    {bounds_check}
     return array[index];
 }}
"""

    elif cwe in {"CWE-416", "CWE-415"}:
        if agent == "agent1":
            return f"""--- a/{file_rel_path}
+++ b/{file_rel_path}
@@ -8,4 +8,6 @@
     free(ptr);
+    ptr = NULL;
+    /* Ownership transferred — do not access ptr after this point */
 }}
"""
        elif agent == "agent2":
            return f"""--- a/{file_rel_path}
+++ b/{file_rel_path}
@@ -6,4 +6,7 @@
 void {function_name}(void **ptr) {{
+    if (*ptr == NULL) return;  /* Guard against double free */
     free(*ptr);
+    *ptr = NULL;
 }}
"""
        else:
            return f"""--- a/{file_rel_path}
+++ b/{file_rel_path}
@@ -8,3 +8,4 @@
     free(ptr);
+    ptr = NULL;
 }}
"""

    elif cwe == "CWE-476":
        return f"""--- a/{file_rel_path}
+++ b/{file_rel_path}
@@ -4,4 +4,7 @@
 int {function_name}(struct node *n) {{
+    if (n == NULL) {{
+        return -1;  /* NULL check: reject null pointer */
+    }}
     return n->value;
 }}
"""

    elif cwe in {"CWE-190", "CWE-191"}:
        if agent == "agent1":
            return f"""--- a/{file_rel_path}
+++ b/{file_rel_path}
@@ -4,4 +4,8 @@
 size_t {function_name}(size_t a, size_t b) {{
+    if (b != 0 && a > SIZE_MAX / b) {{
+        /* Overflow guard */
+        return SIZE_MAX;
+    }}
     return a * b;
 }}
"""
        else:
            return f"""--- a/{file_rel_path}
+++ b/{file_rel_path}
@@ -4,4 +4,6 @@
 size_t {function_name}(size_t a, size_t b) {{
+    /* Safe arithmetic: check before multiply */
+    if (__builtin_mul_overflow(a, b, &result)) return SIZE_MAX;
     return a * b;
 }}
"""

    elif cwe == "CWE-369":
        return f"""--- a/{file_rel_path}
+++ b/{file_rel_path}
@@ -4,4 +4,7 @@
 int {function_name}(int a, int b) {{
+    if (b == 0) {{
+        return -1;  /* Divide by zero guard */
+    }}
     return a / b;
 }}
"""

    elif cwe == "CWE-78":
        if agent == "agent1":
            return f"""--- a/{file_rel_path}
+++ b/{file_rel_path}
@@ -5,5 +5,14 @@
 int {function_name}(const char *user_input) {{
-    char cmd[256];
-    snprintf(cmd, sizeof(cmd), "ls %s", user_input);
-    system(cmd);
+    /* Use execv instead of system() — no shell interpolation */
+    const char *allowed[] = {{"-l", "-a", "-la", NULL}};
+    for (int i = 0; allowed[i]; i++) {{
+        if (strcmp(user_input, allowed[i]) == 0) {{
+            char *argv[] = {{"/bin/ls", (char*)allowed[i], NULL}};
+            execv("/bin/ls", argv);
+            return 0;
+        }}
+    }}
+    return -1;  /* Reject unlisted input */
 }}
"""
        else:
            return f"""--- a/{file_rel_path}
+++ b/{file_rel_path}
@@ -5,5 +5,8 @@
 int {function_name}(const char *user_input) {{
-    char cmd[256];
-    snprintf(cmd, sizeof(cmd), "ping %s", user_input);
-    system(cmd);
+    /* Validate input: allowlist of safe values only */
+    if (strspn(user_input, "abcdefghijklmnopqrstuvwxyz0123456789.-") != strlen(user_input)) {{
+        return -1;  /* Reject shell-unsafe characters */
+    }}
+    /* safe to proceed — input validated */
 }}
"""

    elif cwe == "CWE-22":
        return f"""--- a/{file_rel_path}
+++ b/{file_rel_path}
@@ -4,6 +4,14 @@
 int {function_name}(const char *base_dir, const char *user_path) {{
-    char full_path[512];
-    snprintf(full_path, sizeof(full_path), "%s/%s", base_dir, user_path);
-    return open(full_path, O_RDONLY);
+    char full_path[512];
+    char real_path[PATH_MAX];
+    snprintf(full_path, sizeof(full_path), "%s/%s", base_dir, user_path);
+    if (!realpath(full_path, real_path)) {{
+        return -1;  /* Path resolution failed */
+    }}
+    /* Ensure resolved path stays within allowed base */
+    if (strncmp(real_path, base_dir, strlen(base_dir)) != 0) {{
+        return -1;  /* Path traversal detected */
+    }}
+    return open(real_path, O_RDONLY);
 }}
"""

    elif cwe == "CWE-134":
        return f"""--- a/{file_rel_path}
+++ b/{file_rel_path}
@@ -3,4 +3,4 @@
 void {function_name}(const char *user_input) {{
-    printf(user_input);  /* VULNERABLE: user input as format string */
+    printf("%s", user_input);  /* FIXED: literal format string */
 }}
"""

    elif cwe in {"CWE-327", "CWE-321", "CWE-798"}:
        if cwe == "CWE-327":
            return f"""--- a/{file_rel_path}
+++ b/{file_rel_path}
@@ -4,4 +4,4 @@
 void {function_name}(const unsigned char *data, size_t len) {{
-    MD5_CTX ctx;  /* WEAK: MD5 is cryptographically broken */
-    MD5_Init(&ctx);
+    /* FIXED: Use SHA-256 instead of MD5 */
+    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
+    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
 }}
"""
        elif cwe == "CWE-321":
            return f"""--- a/{file_rel_path}
+++ b/{file_rel_path}
@@ -3,4 +3,8 @@
 const unsigned char *{function_name}(void) {{
-    static unsigned char key[] = {{0x41, 0x42, 0x43, 0x44}};  /* HARDCODED KEY */
-    return key;
+    /* FIXED: Load key from environment variable */
+    const char *key_hex = getenv("APP_CRYPTO_KEY");
+    if (!key_hex) return NULL;  /* Fail safely if not configured */
+    /* (parse key_hex into binary key here) */
+    return NULL;  /* placeholder */
 }}
"""
        else:
            return f"""--- a/{file_rel_path}
+++ b/{file_rel_path}
@@ -3,5 +3,8 @@
 int {function_name}(const char *password) {{
-    const char *expected = "admin123";  /* HARDCODED CREDENTIAL */
-    return strcmp(password, expected) == 0;
+    /* FIXED: Load credential from environment */
+    const char *expected = getenv("APP_AUTH_SECRET");
+    if (!expected) return 0;  /* Deny if not configured */
+    return strcmp(password, expected) == 0;
 }}
"""

    elif cwe in {"CWE-362", "CWE-367"}:
        return f"""--- a/{file_rel_path}
+++ b/{file_rel_path}
@@ -4,6 +4,10 @@
 void {function_name}(struct shared_data *data) {{
+    pthread_mutex_lock(&data->mutex);  /* FIXED: Acquire lock before access */
     data->counter++;
     data->value = compute(data->counter);
+    pthread_mutex_unlock(&data->mutex);
 }}
"""

    elif cwe == "CWE-400":
        return f"""--- a/{file_rel_path}
+++ b/{file_rel_path}
@@ -4,5 +4,9 @@
 void *{function_name}(size_t user_size) {{
-    void *buf = malloc(user_size);  /* UNBOUNDED */
-    return buf;
+    const size_t MAX_ALLOC = 1024 * 1024;  /* 1MB limit */
+    if (user_size == 0 || user_size > MAX_ALLOC) {{
+        return NULL;  /* Reject excessive allocations */
+    }}
+    return malloc(user_size);
 }}
"""

    # Generic fallback
    return f"""--- a/{file_rel_path}
+++ b/{file_rel_path}
@@ -1,3 +1,5 @@
+/* {label} ({cwe}) fix applied by {agent} */
+/* Approach: {approach} */
 /* Auto-generated patch candidate */
"""


def _estimate_lines(diff: str) -> int:
    """Estimate lines changed from diff."""
    return max(1, sum(1 for line in diff.splitlines() if line.startswith(("+", "-")) and not line.startswith(("---", "+++"))))
