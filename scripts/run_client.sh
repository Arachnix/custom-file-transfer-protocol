#!/usr/bin/env bash
# Shell script to run CFTP client on Linux/macOS
set -euo pipefail

HOST="${1:-127.0.0.1}"
PORT="${2:-9000}"
DOWNLOAD_DIR="${3:-downloads}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "=========================================================="
echo "  Launching CFTP/1.0 Client connecting to $HOST:$PORT"
echo "  Download Directory: $DOWNLOAD_DIR"
echo "=========================================================="

cd "$PROJECT_ROOT"
export PYTHONPATH="$PROJECT_ROOT"
python3 -m cftp.client --host "$HOST" --port "$PORT" --download-dir "$DOWNLOAD_DIR"
