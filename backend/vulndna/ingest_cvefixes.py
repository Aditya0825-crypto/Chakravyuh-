"""CVEfixes SQLite ingest → ChromaDB corpus."""

from __future__ import annotations

import argparse
import json
import sqlite3
from pathlib import Path

from vulndna.chroma_store import collection_count, get_collection, upsert_entries
from vulndna.diff_utils import (
    compact_patch,
    extract_function_name,
    infer_fix_pattern,
    truncate_code,
)
from vulndna.models import CorpusEntry

SEED_PATH = Path(__file__).resolve().parent / "seed_corpus.json"

C_CPP_LANGS = ("C", "C++", "C/C++", "Cpp", "cpp")

CVEFIXES_QUERY = """
SELECT
    cv.cve_id,
    cv.description,
    cc.cwe_id,
    r.repo_name,
    fc.filename,
    fc.programming_language,
    fc.code_before,
    fc.code_after,
    fc.diff,
    fc.file_change_id,
    mc.name AS method_name
FROM file_change fc
JOIN commits c ON fc.hash = c.hash
JOIN fixes fx ON c.hash = fx.hash
JOIN cve cv ON fx.cve_id = cv.cve_id
LEFT JOIN cwe_classification cc ON cv.cve_id = cc.cve_id
LEFT JOIN repository r ON c.repo_url = r.repo_url
LEFT JOIN method_change mc
    ON fc.file_change_id = mc.file_change_id AND mc.before_change = 1
WHERE fc.programming_language IN ({lang_placeholders})
  AND fc.code_before IS NOT NULL
  AND fc.code_after IS NOT NULL
  AND TRIM(fc.code_before) != ''
  AND TRIM(fc.code_after) != ''
  AND fc.code_before != fc.code_after
ORDER BY cv.cve_id, fc.file_change_id
LIMIT ?
"""


def load_seed_entries() -> list[CorpusEntry]:
    raw = json.loads(SEED_PATH.read_text(encoding="utf-8"))
    entries: list[CorpusEntry] = []
    for i, row in enumerate(raw):
        entries.append(
            CorpusEntry(
                cve_id=row["cve_id"],
                cwe=row.get("cwe", "CWE-Unknown"),
                title=row.get("title", row["cve_id"]),
                project=row.get("project", "unknown"),
                language=row.get("language", "C"),
                function=row.get("function", "unknown()"),
                description=row.get("description", ""),
                vulnerable_code=row.get("vulnerable_code", ""),
                patch=row.get("patch", ""),
                fix_pattern=row.get("fix_pattern", ""),
                doc_id=f"{row['cve_id']}-seed-{i}",
            )
        )
    return entries


def _row_get(row: sqlite3.Row, key: str, default: str = "") -> str:
    val = row[key]
    return default if val is None else str(val)


def load_cvefixes_entries(db_path: Path, *, limit: int = 5000) -> list[CorpusEntry]:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    placeholders = ",".join("?" for _ in C_CPP_LANGS)
    query = CVEFIXES_QUERY.format(lang_placeholders=placeholders)
    params = [*C_CPP_LANGS, limit]

    rows = conn.execute(query, params).fetchall()
    conn.close()

    entries: list[CorpusEntry] = []
    seen: set[str] = set()

    for row in rows:
        cve_id = _row_get(row, "cve_id")
        file_change_id = _row_get(row, "file_change_id")
        doc_id = f"{cve_id}-{file_change_id}"
        if doc_id in seen:
            continue
        seen.add(doc_id)

        before = _row_get(row, "code_before")
        after = _row_get(row, "code_after")
        filename = _row_get(row, "filename", "file.c")
        diff = _row_get(row, "diff")
        patch = diff if diff.strip() else compact_patch(before, after, filename=filename)

        description = _row_get(row, "description")
        cwe = _row_get(row, "cwe_id", "CWE-Unknown")
        if not cwe.startswith("CWE-"):
            cwe = f"CWE-{cwe}" if cwe.isdigit() else "CWE-Unknown"

        vuln_snippet = truncate_code(before)
        entries.append(
            CorpusEntry(
                cve_id=cve_id,
                cwe=cwe,
                title=description.split(".")[0][:120] if description else cve_id,
                project=_row_get(row, "repo_name", "unknown"),
                language=_row_get(row, "programming_language", "C"),
                function=extract_function_name(
                    row["method_name"] if "method_name" in row.keys() else None,
                    before,
                ),
                description=description[:1000],
                vulnerable_code=vuln_snippet,
                patch=patch[:4000],
                fix_pattern=infer_fix_pattern(before, after, description),
                doc_id=doc_id,
            )
        )

    return entries


def ingest_seed(*, recreate: bool = False) -> int:
    if recreate:
        get_collection(recreate=True)
    entries = load_seed_entries()
    return upsert_entries(entries)


def ingest_cvefixes(db_path: Path, *, limit: int = 5000, recreate: bool = False) -> int:
    if recreate:
        get_collection(recreate=True)
    entries = load_cvefixes_entries(db_path, limit=limit)
    if not entries:
        raise RuntimeError(f"No C/C++ patch entries found in {db_path}")
    return upsert_entries(entries)


def main() -> None:
    parser = argparse.ArgumentParser(description="Ingest CVEfixes or seed corpus into VulnDNA ChromaDB")
    parser.add_argument("--seed", action="store_true", help="Load bundled seed corpus (~12 CVEs)")
    parser.add_argument("--db", type=Path, help="Path to CVEfixes SQLite database")
    parser.add_argument("--limit", type=int, default=5000, help="Max rows from CVEfixes")
    parser.add_argument("--reset", action="store_true", help="Recreate collection before ingest")
    parser.add_argument("--status", action="store_true", help="Print corpus size and exit")
    args = parser.parse_args()

    if args.status:
        print(f"Corpus size: {collection_count()} documents")
        return

    if args.seed:
        count = ingest_seed(recreate=args.reset)
        print(f"Ingested {count} seed documents → corpus size {collection_count()}")
        return

    if args.db:
        count = ingest_cvefixes(args.db, limit=args.limit, recreate=args.reset)
        print(f"Ingested {count} CVEfixes documents → corpus size {collection_count()}")
        return

    parser.error("Specify --seed, --db PATH, or --status")


if __name__ == "__main__":
    main()
