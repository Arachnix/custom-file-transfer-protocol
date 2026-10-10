#!/usr/bin/env bash
# Shell script to run CFTP server on Linux/macOS
set -euo pipefail

HOST="${1:-127.0.0.1}"
PORT="${2:-9000}"
STORAGE_DIR="${3:-server_storage}"
LOG_LEVEL="${4:-INFO}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "=========================================================="
echo "  Starting CFTP/1.0 Server on $HOST:$PORT"
echo "  Storage Directory: $STORAGE_DIR"
echo "=========================================================="

cd "$PROJECT_ROOT"
export PYTHONPATH="$PROJECT_ROOT"
python3 -m cftp.server --host "$HOST" --port "$PORT" --storage-dir "$STORAGE_DIR" --log-level "$LOG_LEVEL"
