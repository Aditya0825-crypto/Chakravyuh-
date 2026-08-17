"""Ingest CVEFixes CSV (Kaggle format) into VulnDNA ChromaDB.

CSV schema: code, language, safety (vulnerable | safe)
Rows alternate: vulnerable row N is paired with safe row N.

Usage:
    python -m vulndna.ingest_cvefixes_csv \
        --csv /path/to/CVEFixes.csv \
        [--limit 5000] \
        [--langs c cpp h] \
        [--reset]
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import re
import sys
from pathlib import Path

csv.field_size_limit(sys.maxsize)  # rows contain large code blobs

from vulndna.chroma_store import collection_count, get_collection, upsert_entries
from vulndna.diff_utils import compact_patch, infer_fix_pattern, truncate_code
from vulndna.models import CorpusEntry

# Languages to keep (kaggle CSV uses lowercase short names)
DEFAULT_LANGS = {"c", "cpp", "h", "c++"}


def _lang_display(lang: str) -> str:
    mapping = {"c": "C", "cpp": "C++", "h": "C", "c++": "C++"}
    return mapping.get(lang.lower(), lang.upper())


def _doc_id(vuln_code: str, idx: int) -> str:
    """Stable ID based on content hash + index."""
    digest = hashlib.sha1(vuln_code.encode("utf-8", errors="replace")).hexdigest()[:12]
    return f"cvefixes-csv-{idx:06d}-{digest}"


def _infer_cwe(vuln_code: str) -> str:
    """Heuristic CWE from common dangerous patterns in the vulnerable snippet."""
    lower = vuln_code.lower()
    if re.search(r"\bstrcpy\b|\bgets\b|\bsprintf\b|\bstrcat\b", lower):
        return "CWE-120"
    if re.search(r"\bmemcpy\b|\bmemmove\b", lower) and re.search(r"len|size|count", lower):
        return "CWE-122"
    if re.search(r"free\s*\(", lower):
        return "CWE-416"
    if re.search(r"\bsystem\s*\(|\bpopen\s*\(|\bexec\w*\s*\(", lower):
        return "CWE-78"
    if re.search(r"\bsql\b|select.*from|insert.*into", lower):
        return "CWE-89"
    if re.search(r"null\s*ptr|nullptr|\bnull\b.*deref", lower):
        return "CWE-476"
    return "CWE-Unknown"


def _extract_first_function(code: str) -> str:
    """Try to grab the first function name from a code snippet."""
    # Match C-style function definitions
    m = re.search(r"[\w\*]+\s+([\w_]+)\s*\(", code)
    return f"{m.group(1)}()" if m else "unknown()"


def load_csv_entries(
    csv_path: Path,
    *,
    langs: set[str] | None = None,
    limit: int = 5000,
) -> list[CorpusEntry]:
    if langs is None:
        langs = DEFAULT_LANGS

    entries: list[CorpusEntry] = []
    vuln_buf: dict[str, str] = {}  # lang → pending vulnerable code waiting for safe pair

    with open(csv_path, "r", errors="replace") as f:
        reader = csv.DictReader(f)
        raw_rows = list(reader)

    # ── Pair up rows: find consecutive (vulnerable, safe) pairs of same language ──
    # The CSV alternates: vulnerable → safe for each language group.
    # We iterate and match pairs by language.
    pending: dict[str, str] = {}   # lang → vulnerable code snippet
    pair_idx = 0

    for row in raw_rows:
        if len(entries) >= limit:
            break

        lang = row.get("language", "").lower().strip()
        safety = row.get("safety", "").lower().strip()
        code = row.get("code", "").strip()

        if not code or lang not in langs:
            continue

        if safety == "vulnerable":
            # Store as pending, waiting for the safe counterpart
            pending[lang] = code

        elif safety == "safe" and lang in pending:
            vuln_code = pending.pop(lang)
            safe_code = code

            # Skip trivial pairs (identical or tiny)
            if vuln_code == safe_code or len(vuln_code) < 20 or len(safe_code) < 20:
                continue

            cwe = _infer_cwe(vuln_code)
            func = _extract_first_function(vuln_code)
            patch = compact_patch(vuln_code, safe_code)
            fix_pattern = infer_fix_pattern(vuln_code, safe_code, "")
            doc_id = _doc_id(vuln_code, pair_idx)
            pair_idx += 1

            entries.append(
                CorpusEntry(
                    cve_id=f"CVEFIXES-CSV-{pair_idx:05d}",
                    cwe=cwe,
                    title=f"{_lang_display(lang)} security fix — {cwe}",
                    project="cvefixes-kaggle",
                    language=_lang_display(lang),
                    function=func,
                    description=f"Vulnerable {_lang_display(lang)} snippet patched to safe equivalent. CWE heuristic: {cwe}.",
                    vulnerable_code=truncate_code(vuln_code),
                    patch=patch[:4000],
                    fix_pattern=fix_pattern,
                    doc_id=doc_id,
                )
            )

    return entries


def ingest_csv(
    csv_path: Path,
    *,
    langs: set[str] | None = None,
    limit: int = 5000,
    recreate: bool = False,
) -> int:
    if recreate:
        get_collection(recreate=True)
    entries = load_csv_entries(csv_path, langs=langs, limit=limit)
    if not entries:
        raise RuntimeError(
            "No valid paired entries found. Check --langs and that the CSV has 'code/language/safety' columns."
        )
    return upsert_entries(entries)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Ingest CVEFixes Kaggle CSV into VulnDNA ChromaDB"
    )
    parser.add_argument(
        "--csv", type=Path, required=True,
        help="Path to CVEFixes.csv from Kaggle"
    )
    parser.add_argument(
        "--limit", type=int, default=5000,
        help="Max paired entries to ingest (default: 5000)"
    )
    parser.add_argument(
        "--langs", nargs="+", default=list(DEFAULT_LANGS),
        help="Languages to include (default: c cpp h c++)"
    )
    parser.add_argument(
        "--reset", action="store_true",
        help="Wipe and recreate the ChromaDB collection before ingesting"
    )
    parser.add_argument(
        "--status", action="store_true",
        help="Print current corpus size and exit"
    )
    args = parser.parse_args()

    if args.status:
        print(f"Corpus size: {collection_count()} documents")
        return

    if not args.csv.exists():
        parser.error(f"CSV file not found: {args.csv}")

    langs = {l.lower() for l in args.langs}
    count = ingest_csv(args.csv, langs=langs, limit=args.limit, recreate=args.reset)
    print(f"✓ Ingested {count} paired entries → corpus total: {collection_count()} documents")


if __name__ == "__main__":
    main()
