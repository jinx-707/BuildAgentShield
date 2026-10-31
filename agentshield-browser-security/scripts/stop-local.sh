#!/bin/bash
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PID_DIR="$ROOT/data/local/pids"
for pidfile in "$PID_DIR"/*.pid; do
  [ -f "$pidfile" ] || continue
  pid=$(cat "$pidfile")
  if kill -0 "$pid" 2>/dev/null; then
    kill "$pid" 2>/dev/null && echo "stopped $(basename $pidfile .pid) (pid $pid)"
  fi
  rm -f "$pidfile"
done
echo "Local Mode stopped."
