#!/bin/bash
set -e

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PID_DIR="$ROOT/data/local/pids"
LOG_DIR="$ROOT/data/local/logs"
mkdir -p "$PID_DIR" "$LOG_DIR" "$ROOT/data/local"

# Override for local mode: SQLite + localhost (pydantic reads .env directly)
export DATABASE_URL="sqlite:///$ROOT/data/local/agentshield.db"
export ENVIRONMENT="${ENVIRONMENT:-development}"
export API_HOST="${API_HOST:-127.0.0.1}"
export API_PORT="${API_PORT:-8000}"
export WORKER_HOST="${WORKER_HOST:-127.0.0.1}"
export WORKER_PORT="${WORKER_PORT:-8080}"
export PROXY_HOST="${PROXY_HOST:-127.0.0.1}"
export PROXY_PORT="${PROXY_PORT:-3128}"
export PROXY_HEALTH_PORT="${PROXY_HEALTH_PORT:-9090}"
export BROWSER_WORKER_URL="http://127.0.0.1:8080"
export EGRESS_PROXY_URL="http://127.0.0.1:3128"
export EGRESS_PROXY_HEALTH_URL="http://127.0.0.1:9090/health"
export SIMULATION_CONTROLLER_URL="http://127.0.0.1:8090"
export EVIDENCE_COLLECTOR_URL="http://127.0.0.1:8091"

PY="$ROOT/api/.venv/bin/python"
if [ ! -x "$PY" ]; then
  echo "Python venv not found. Creating..."
  python3 -m venv "$ROOT/api/.venv"
  "$ROOT/api/.venv/bin/pip" install -r "$ROOT/api/requirements.txt" >/dev/null 2>&1
  PY="$ROOT/api/.venv/bin/python"
fi

# Init DB (create tables)
cd "$ROOT/api"
DATABASE_URL="$DATABASE_URL" "$PY" -c "from app.config import Settings; from app.db.base import init_db, create_all; s=Settings(); init_db(s); create_all(); print('DB initialized')" 2>&1 | tail -3
cd "$ROOT"

start_proc() {
  local name=$1; shift
  local pidfile="$PID_DIR/$name.pid"
  if [ -f "$pidfile" ] && kill -0 "$(cat $pidfile)" 2>/dev/null; then
    echo "  $name already running (pid $(cat $pidfile))"
    return
  fi
  nohup "$@" > "$LOG_DIR/$name.log" 2>&1 &
  echo $! > "$pidfile"
  echo "  started $name (pid $!)"
}

echo "Starting AgentShield Local Mode..."

# API
cd "$ROOT/api"
DATABASE_URL="$DATABASE_URL" nohup "$PY" -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --no-proxy-headers > "$LOG_DIR/api.log" 2>&1 &
echo $! > "$PID_DIR/api.pid"
echo "  started api (pid $!)"
cd "$ROOT"

# Worker
cd "$ROOT/worker"
nohup npm start > "$LOG_DIR/worker.log" 2>&1 &
echo $! > "$PID_DIR/worker.pid"
echo "  started worker (pid $!)"
cd "$ROOT"

# Proxy
cd "$ROOT/proxy"
nohup npm start > "$LOG_DIR/proxy.log" 2>&1 &
echo $! > "$PID_DIR/proxy.pid"
echo "  started proxy (pid $!)"
cd "$ROOT"

# Mock metadata (port 8088)
cd "$ROOT/cyber-range/targets/mock-metadata"
MOCK_HOST=127.0.0.1 MOCK_PORT=8088 nohup "$PY" main.py > "$LOG_DIR/mock-metadata.log" 2>&1 &
echo $! > "$PID_DIR/mock-metadata.pid"
echo "  started mock-metadata (pid $!)"
cd "$ROOT"

# Targets
for t in prompt-injection:8081 phishing:8082 ssrf:8083 malicious-download:8084 resource-exhaustion:8085 dns-rebinding:8086 data-exfiltration:8087; do
  name="${t%%:*}"; port="${t##*:}"
  cd "$ROOT/cyber-range/targets/$name"
  TARGET_HOST=127.0.0.1 TARGET_PORT=$port EVIDENCE_COLLECTOR_URL=http://127.0.0.1:8091 nohup "$PY" main.py > "$LOG_DIR/$name.log" 2>&1 &
  echo $! > "$PID_DIR/$name.pid"
  echo "  started $name (pid $!)"
  cd "$ROOT"
done

# Evidence collector
cd "$ROOT/cyber-range/evidence-collector"
COLLECTOR_HOST=127.0.0.1 COLLECTOR_PORT=8091 DATABASE_URL="$DATABASE_URL" nohup "$PY" main.py > "$LOG_DIR/evidence-collector.log" 2>&1 &
echo $! > "$PID_DIR/evidence-collector.pid"
echo "  started evidence-collector (pid $!)"
cd "$ROOT"

# Simulation controller
cd "$ROOT/cyber-range/simulation-controller"
CONTROLLER_HOST=127.0.0.1 CONTROLLER_PORT=8090 DATABASE_URL="$DATABASE_URL" API_URL=http://127.0.0.1:8000 BROWSER_WORKER_URL=http://127.0.0.1:8080 EGRESS_PROXY_URL=http://127.0.0.1:3128 EVIDENCE_COLLECTOR_URL=http://127.0.0.1:8091 PROMPT_INJECTION_TARGET_URL=http://127.0.0.1:8081 PHISHING_TARGET_URL=http://127.0.0.1:8082 SSRF_TARGET_URL=http://127.0.0.1:8083 MALICIOUS_DOWNLOAD_TARGET_URL=http://127.0.0.1:8084 RESOURCE_EXHAUSTION_TARGET_URL=http://127.0.0.1:8085 DNS_REBINDING_TARGET_URL=http://127.0.0.1:8086 DATA_EXFILTRATION_SINK_URL=http://127.0.0.1:8087 nohup "$PY" main.py > "$LOG_DIR/simulation-controller.log" 2>&1 &
echo $! > "$PID_DIR/simulation-controller.pid"
echo "  started simulation-controller (pid $!)"
cd "$ROOT"

echo ""
echo "Waiting for services to be healthy (15s)..."
sleep 15

echo ""
echo "Service Status:"
for svc in api worker proxy; do
  code=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:$([ "$svc" = "api" ] && echo 8000 || ([ "$svc" = "worker" ] && echo 8080 || echo 9090))/health 2>/dev/null || echo "UNREACHABLE")
  echo "  $svc: $code"
done

echo ""
echo "AgentShield Local Mode started."
echo "  Frontend (Vite): http://127.0.0.1:8443"
echo "  API:             http://127.0.0.1:8000"
echo "  Worker:          http://127.0.0.1:8080"
echo "  Proxy health:    http://127.0.0.1:9090"
echo "  Sim controller:  http://127.0.0.1:8090"
echo "  Evidence:        http://127.0.0.1:8091"
echo "  Database:        $ROOT/data/local/agentshield.db"
