#!/usr/bin/env bash
# CHAKRAVYUH Phase 0 — WSL environment bootstrap (Ubuntu)
set -euo pipefail

echo "==> CHAKRAVYUH WSL setup"

sudo apt update
sudo apt install -y \
  postgresql redis-server docker.io \
  clang llvm build-essential git patch \
  python3.11 python3.11-venv python3-pip

# PostgreSQL database + role
sudo service postgresql start
sudo -u postgres psql -tc "SELECT 1 FROM pg_roles WHERE rolname='chakravyuh'" | grep -q 1 || \
  sudo -u postgres psql -c "CREATE USER chakravyuh WITH PASSWORD 'password';"
sudo -u postgres psql -tc "SELECT 1 FROM pg_database WHERE datname='chakravyuh'" | grep -q 1 || \
  sudo -u postgres psql -c "CREATE DATABASE chakravyuh OWNER chakravyuh;"

sudo service redis-server start

# Data directories (plan paths)
sudo mkdir -p /data/chakravyuh/scans /data/chakravyuh/vulndna_db
sudo chown -R "$USER:$USER" /data/chakravyuh

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BACKEND="$REPO_ROOT/backend"

cd "$BACKEND"
python3.11 -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -r requirements.txt

cp -n .env.example .env 2>/dev/null || true

# Run migrations
alembic upgrade head

echo ""
echo "Setup complete. Start services:"
echo "  cd backend && source .venv/bin/activate"
echo "  uvicorn api.main:app --reload --host 0.0.0.0 --port 8000"
echo "  celery -A workers.celery_app worker --loglevel=info"
echo ""
echo "Frontend (Windows): cd frontend && npm run dev"
