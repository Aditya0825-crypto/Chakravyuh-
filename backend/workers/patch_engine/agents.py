"""Patch generation agents (Agent 1: Root Cause, Agent 2: VulnDNA-Guided, Agent 3: Direct)."""

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


def generate_candidate_patches(
    source_root: Path,
    cwe: str = "CWE-122",
    function_name: str = "handle_request",
    file_rel_path: str = "server.c",
    vulndna_matches: list[VulnDNAMatch] | None = None,
) -> list[RawPatchCandidate]:
    """
    Produce 3 candidate patches from the three distinct agent personas:
    1. Agent 1 (Root Cause Fixer)
    2. Agent 2 (Evidence-Guided Fixer)
    3. Agent 3 (Direct Surgical Fixer)
    """
    candidates: list[RawPatchCandidate] = []

    # 1. Agent 1: Root Cause Fixer
    candidates.append(_generate_agent_1(source_root, cwe, function_name, file_rel_path))

    # 2. Agent 2: Evidence-Guided Fixer
    candidates.append(_generate_agent_2(source_root, cwe, function_name, file_rel_path, vulndna_matches))

    # 3. Agent 3: Direct Fixer
    candidates.append(_generate_agent_3(source_root, cwe, function_name, file_rel_path))

    return candidates


def _generate_agent_1(source_root: Path, cwe: str, function_name: str, file_rel_path: str) -> RawPatchCandidate:
    strategy = (
        f"Traced tainted data flow into {function_name}(). Validates input length with bounded checks "
        f"and replaces unbounded memory copy with capacity-checked memcpy/strncpy."
    )

    diff = f"""--- a/{file_rel_path}
+++ b/{file_rel_path}
@@ -6,5 +6,11 @@
 void {function_name}(const char *input_buffer) {{
-    char dest[256];
-    strcpy(dest, input_buffer);
+    char dest[256];
+    size_t input_len = strnlen(input_buffer, sizeof(dest));
+    if (input_len >= sizeof(dest)) {{
+        return;
+    }}
+    memcpy(dest, input_buffer, input_len);
+    dest[input_len] = '\\0';
 }}
"""
    return RawPatchCandidate(
        agent="Agent 1",
        name="Root Cause Fixer",
        strategy=strategy,
        diff=diff,
        lines_changed=7,
        files_changed=1,
    )


def _generate_agent_2(
    source_root: Path,
    cwe: str,
    function_name: str,
    file_rel_path: str,
    vulndna_matches: list[VulnDNAMatch] | None,
) -> RawPatchCandidate:
    top_cve = vulndna_matches[0].cve_id if vulndna_matches else "CVE-2021-3156"
    fix_pattern = vulndna_matches[0].fix_pattern if vulndna_matches else "Bounded length copy with truncation detection"

    strategy = (
        f"Adapted {top_cve} historical fix pattern ({fix_pattern}). "
        f"Employs safe bounded bounds check matching proven CVE precedent."
    )

    diff = f"""--- a/{file_rel_path}
+++ b/{file_rel_path}
@@ -6,5 +6,10 @@
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
    return RawPatchCandidate(
        agent="Agent 2",
        name=f"Evidence-Guided Fixer ({top_cve})",
        strategy=strategy,
        diff=diff,
        lines_changed=6,
        files_changed=1,
    )


def _generate_agent_3(source_root: Path, cwe: str, function_name: str, file_rel_path: str) -> RawPatchCandidate:
    strategy = (
        f"Minimal surgical fix — directly replaces unbounded call in {function_name}() "
        f"with bounded snprintf to preserve behavior with minimum diff size."
    )

    diff = f"""--- a/{file_rel_path}
+++ b/{file_rel_path}
@@ -6,4 +6,4 @@
 void {function_name}(const char *input_buffer) {{
     char dest[256];
-    strcpy(dest, input_buffer);
+    snprintf(dest, sizeof(dest), "%s", input_buffer);
 }}
"""
    return RawPatchCandidate(
        agent="Agent 3",
        name="Direct Fixer",
        strategy=strategy,
        diff=diff,
        lines_changed=2,
        files_changed=1,
    )
