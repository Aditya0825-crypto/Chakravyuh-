"""LLM prompt templates."""

RECON_RANK_SYSTEM = """You are a security recon engine for C/C++ codebases.
Rank functions by exploitability. Output ONLY valid JSON array — no markdown."""

RECON_RANK_PROMPT = """Rank these attack-surface targets by priority (highest first).
For each function return: function, risk (CRITICAL|HIGH|MEDIUM|LOW), reason (short), score (0-100).

Targets:
{targets_json}

Respond with JSON array:
[{{"function":"name","risk":"CRITICAL","reason":"...","score":95}}]
"""
