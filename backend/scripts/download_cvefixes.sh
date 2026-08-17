#!/usr/bin/env bash
# Download CVEfixes v1.0.8 SQL dump from Zenodo and build SQLite DB.
# Full dataset is large (~GB). Run in WSL with sufficient disk space.
set -euo pipefail

DATA_DIR="${1:-./data/cvefixes}"
mkdir -p "$DATA_DIR"
cd "$DATA_DIR"

ZENODO_URL="https://zenodo.org/records/13118970/files/CVEfixes_v1.0.8.sql.gz?download=1"
ARCHIVE="CVEfixes_v1.0.8.sql.gz"
DB="CVEfixes.db"

if [ -f "$DB" ]; then
  echo "Database already exists: $DATA_DIR/$DB"
  exit 0
fi

echo "Downloading CVEfixes v1.0.8 from Zenodo..."
curl -L -o "$ARCHIVE" "$ZENODO_URL"

echo "Building SQLite database (may take several minutes)..."
gunzip -c "$ARCHIVE" | sqlite3 "$DB"

echo "Done: $DATA_DIR/$DB"
echo "Ingest with:"
echo "  python -m vulndna.ingest_cvefixes --db $DATA_DIR/$DB --limit 5000 --reset"
