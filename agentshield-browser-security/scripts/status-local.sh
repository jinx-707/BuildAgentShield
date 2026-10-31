#!/bin/bash
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PID_DIR="$ROOT/data/local/pids"
echo "AgentShield Local Mode Status"
echo "============================="
for pidfile in "$PID_DIR"/*.pid; do
  [ -f "$pidfile" ] || continue
  name=$(basename "$pidfile" .pid)
  pid=$(cat "$pidfile")
  if kill -0 "$pid" 2>/dev/null; then
    echo "  $name: RUNNING (pid $pid)"
  else
    echo "  $name: STOPPED"
  fi
done
echo ""
echo "Health:"
for url in "http://127.0.0.1:8000/health" "http://127.0.0.1:8080/health" "http://127.0.0.1:9090/health" "http://127.0.0.1:8090/health" "http://127.0.0.1:8091/health"; do
  code=$(curl -s -o /dev/null -w '%{http_code}' "$url" 2>/dev/null || echo "UNREACHABLE")
  echo "  $url -> $code"
done
