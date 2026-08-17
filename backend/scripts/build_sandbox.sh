#!/usr/bin/env bash
# Build the CHAKRAVYUH sandbox Docker image (PoV replay, compile, fuzz).
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BACKEND="$(cd "$SCRIPT_DIR/.." && pwd)"
IMAGE="${1:-chakravyuh-sandbox:latest}"

echo "Building sandbox image: $IMAGE"
docker build -t "$IMAGE" "$BACKEND"
echo "Done. Set SANDBOX_MODE=docker in .env to use container isolation."
