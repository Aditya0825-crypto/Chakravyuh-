"""LLM prompt templates for Recon, Bug Finding, and Fuzzing."""

RECON_RANK_SYSTEM = """You are a security recon engine for C/C++ codebases.
Rank functions by exploitability. Output ONLY valid JSON array — no markdown."""

RECON_RANK_PROMPT = """Rank these attack-surface targets by priority (highest first).
For each function return: function, risk (CRITICAL|HIGH|MEDIUM|LOW), reason (short), score (0-100).

Targets:
{targets_json}

Respond with JSON array:
[{{"function":"name","risk":"CRITICAL","reason":"...","score":95}}]
"""

BUG_FINDING_EXPLOIT_SYSTEM = """You are an automated vulnerability researcher analyzing C/C++ source code.
Your goal is to inspect a function with a known risky sink and provide concrete triggering payload inputs to trigger memory corruption / crashes (ASan violation, SIGSEGV, SIGABRT).
Output ONLY valid JSON — no markdown or explanatory prose outside JSON."""

BUG_FINDING_EXPLOIT_PROMPT = """Analyze the following C source code for function '{function_name}'.
Sink detected: {sinks}
Static rule / vulnerability hypothesis: {rule}
Code snippet:
{code_snippet}

Context / Call Path:
{call_path}

Generate up to 3 concrete input payload candidates that will trigger a crash or memory safety violation when fed via stdin / input buffer.
For each candidate provide:
- payload_name: short description (e.g., "long_overflow_512b")
- payload_type: "text" or "hex" or "repeated"
- payload_content: the string content, or if repeated format: "{{'char': 'A', 'count': 512}}"
- expected_cwe: CWE ID like "CWE-122" or "CWE-121"
- rationale: brief explanation

Respond with JSON array:
[
  {{
    "payload_name": "overflow_512_bytes",
    "payload_type": "repeated",
    "char": "A",
    "count": 512,
    "prefix": "",
    "suffix": "\\n",
    "expected_cwe": "CWE-122",
    "rationale": "Overwrites buffer allocated for smaller capacity"
  }}
]
"""

FUZZ_HARNESS_GEN_SYSTEM = """You are a fuzzing harness engineer.
Write a minimal, standalone C harness that accepts arbitrary binary data from stdin or memory and calls the target function with sanitized arguments."""

SEED_GEN_PROMPT = """Given the target function '{function_name}' and sink '{sinks}', generate 5 boundary seed input strings for fuzzing.
Return JSON array of strings:
["seed1", "seed2", ...]
"""
