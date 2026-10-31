#!/usr/bin/env bash
# Stop all AgentShield services started by scripts/start.sh.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PID_FILE="${REPO_ROOT}/.agentpids"

if [[ ! -f "$PID_FILE" ]]; then
  echo "No PID file found. Trying to stop by process name..."
  pkill -f "uvicorn app.main:app" 2>/dev/null || true
  pkill -f "node src/index.js" 2>/dev/null || true
  pkill -f "worker/src/index.js" 2>/dev/null || true
  pkill -f "proxy/src/index.js" 2>/dev/null || true
  echo "Done."
  exit 0
fi

echo "Stopping AgentShield services..."
while read -r pid; do
  [[ -n "${pid:-}" ]] && kill "$pid" 2>/dev/null || true
done < "$PID_FILE"

# Give processes a moment to exit, then force-kill any survivors.
sleep 2
while read -r pid; do
  [[ -n "${pid:-}" ]] && kill -9 "$pid" 2>/dev/null || true
done < "$PID_FILE"

rm -f "$PID_FILE"
echo "All AgentShield services stopped."
