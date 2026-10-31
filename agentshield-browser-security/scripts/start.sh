#!/usr/bin/env bash
# Start AgentShield locally for development.
#
# Usage: ./scripts/start.sh
#
# Starts the browser worker, FastAPI API, and egress proxy in the background,
# waits for all health checks to pass, then prints connection info.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

ENV_FILE="${REPO_ROOT}/.env"
if [[ ! -f "$ENV_FILE" ]]; then
  echo "Creating .env from .env.example..."
  cp .env.example "$ENV_FILE"
fi

LOG_DIR="${REPO_ROOT}/.logs"
mkdir -p "$LOG_DIR"

PID_FILE="${REPO_ROOT}/.agentpids"
: > "$PID_FILE"

cleanup() {
  echo "Stopping AgentShield services..."
  if [[ -f "$PID_FILE" ]]; then
    while read -r pid; do
      [[ -n "${pid:-}" ]] && kill "$pid" 2>/dev/null || true
    done < "$PID_FILE"
  fi
  rm -f "$PID_FILE"
}
trap cleanup EXIT

start_worker() {
  echo "Starting browser worker..."
  (
    cd worker
    source "$ENV_FILE" 2>/dev/null || true
    export WORKER_HOST="${WORKER_HOST:-127.0.0.1}"
    export WORKER_PORT="${WORKER_PORT:-8080}"
    export LOG_LEVEL="${LOG_LEVEL:-info}"
    export BROWSER_HEADLESS="${BROWSER_HEADLESS:-true}"
    export BROWSER_NAVIGATION_TIMEOUT_MS="${BROWSER_NAVIGATION_TIMEOUT_MS:-20000}"
    export BROWSER_MAX_CONTENT_BYTES="${BROWSER_MAX_CONTENT_BYTES:-524288}"
    export BROWSER_ALLOW_PRIVATE_NETWORKS="${BROWSER_ALLOW_PRIVATE_NETWORKS:-false}"
    export ALLOWED_DOMAINS="${ALLOWED_DOMAINS:-example.com}"
    export BLOCKED_DOMAINS="${BLOCKED_DOMAINS:-}"
    export DEFAULT_DOMAIN_POLICY="${DEFAULT_DOMAIN_POLICY:-deny}"
    export ALLOWED_PORTS="${ALLOWED_PORTS:-80,443}"
    export MAX_REDIRECTS="${MAX_REDIRECTS:-5}"
    export BLOCK_HTTPS_DOWNGRADE="${BLOCK_HTTPS_DOWNGRADE:-true}"
    export EGRESS_PROXY_URL="${EGRESS_PROXY_URL:-http://127.0.0.1:3128}"
    export EGRESS_PROXY_HEALTH_URL="${EGRESS_PROXY_HEALTH_URL:-http://127.0.0.1:9090/health/ready}"
    export PROXY_AUTH_TOKEN="${PROXY_AUTH_TOKEN:-}"
    export REQUIRE_EGRESS_PROXY="${REQUIRE_EGRESS_PROXY:-true}"
    export BROWSER_SESSION_IDLE_TIMEOUT_MS="${BROWSER_SESSION_IDLE_TIMEOUT_MS:-300000}"
    export BROWSER_SESSION_MAX_LEASE_MS="${BROWSER_SESSION_MAX_LEASE_MS:-120000}"
    export BROWSER_SESSION_MAX_AGE_MS="${BROWSER_SESSION_MAX_AGE_MS:-900000}"
    export BROWSER_MAX_SESSIONS="${BROWSER_MAX_SESSIONS:-5}"
    export BROWSER_MAX_CONCURRENT_CONTEXTS="${BROWSER_MAX_CONCURRENT_CONTEXTS:-10}"
    export BROWSER_MAX_EXTRACTION_TEXT_BYTES="${BROWSER_MAX_EXTRACTION_TEXT_BYTES:-131072}"
    export BROWSER_MAX_EXTRACTION_LINKS="${BROWSER_MAX_EXTRACTION_LINKS:-100}"
    export BROWSER_ACTION_TIMEOUT_MS="${BROWSER_ACTION_TIMEOUT_MS:-10000}"
    export BROWSER_ACTION_MAX_TYPE_BYTES="${BROWSER_ACTION_MAX_TYPE_BYTES:-4000}"
    export BROWSER_ACTION_MAX_SCROLL_PX="${BROWSER_ACTION_MAX_SCROLL_PX:-5000}"
    export BROWSER_ACTION_MAX_TEXT_BYTES="${BROWSER_ACTION_MAX_TEXT_BYTES:-8192}"
    export BROWSER_SCREENSHOT_TIMEOUT_MS="${BROWSER_SCREENSHOT_TIMEOUT_MS:-10000}"
    export BROWSER_SCREENSHOT_MAX_WIDTH="${BROWSER_SCREENSHOT_MAX_WIDTH:-2048}"
    export BROWSER_SCREENSHOT_MAX_HEIGHT="${BROWSER_SCREENSHOT_MAX_HEIGHT:-2048}"
    export BROWSER_SCREENSHOT_MAX_FULL_PAGE_HEIGHT="${BROWSER_SCREENSHOT_MAX_FULL_PAGE_HEIGHT:-12000}"
    export BROWSER_SCREENSHOT_MAX_BYTES="${BROWSER_SCREENSHOT_MAX_BYTES:-5242880}"
    export BROWSER_SCREENSHOT_MAX_CONCURRENT="${BROWSER_SCREENSHOT_MAX_CONCURRENT:-2}"
    export BROWSER_SCREENSHOT_RATE_LIMIT_PER_MINUTE="${BROWSER_SCREENSHOT_RATE_LIMIT_PER_MINUTE:-20}"
    export BROWSER_SCREENSHOT_MAX_PER_SESSION="${BROWSER_SCREENSHOT_MAX_PER_SESSION:-100}"
    export BROWSER_ALLOW_WEBRTC="${BROWSER_ALLOW_WEBRTC:-false}"
    export WORKER_AUTH_TOKEN="${WORKER_AUTH_TOKEN:-}"
    npm start > "$LOG_DIR/worker.log" 2>&1 &
    echo $! >> "$PID_FILE"
  )
}

start_proxy() {
  echo "Starting egress proxy..."
  (
    cd proxy
    source "$ENV_FILE" 2>/dev/null || true
    export PROXY_HOST="${PROXY_HOST:-127.0.0.1}"
    export PROXY_PORT="${PROXY_PORT:-3128}"
    export PROXY_HEALTH_HOST="${PROXY_HEALTH_HOST:-127.0.0.1}"
    export PROXY_HEALTH_PORT="${PROXY_HEALTH_PORT:-9090}"
    export LOG_LEVEL="${LOG_LEVEL:-info}"
    export PROXY_ALLOWED_DOMAINS="${ALLOWED_DOMAINS:-example.com}"
    export PROXY_BLOCKED_DOMAINS="${BLOCKED_DOMAINS:-}"
    export PROXY_DEFAULT_DOMAIN_POLICY="${DEFAULT_DOMAIN_POLICY:-deny}"
    export PROXY_ALLOWED_PORTS="${ALLOWED_PORTS:-80,443}"
    export PROXY_ALLOW_PRIVATE_NETWORKS="${BROWSER_ALLOW_PRIVATE_NETWORKS:-false}"
    export PROXY_DNS_TIMEOUT_MS="${PROXY_DNS_TIMEOUT_MS:-5000}"
    export PROXY_CONNECT_TIMEOUT_MS="${PROXY_CONNECT_TIMEOUT_MS:-10000}"
    export PROXY_AUTH_TOKEN="${PROXY_AUTH_TOKEN:-}"
    npm start > "$LOG_DIR/proxy.log" 2>&1 &
    echo $! >> "$PID_FILE"
  )
}

start_api() {
  echo "Starting FastAPI API..."
  (
    source "$ENV_FILE" 2>/dev/null || true
    export API_HOST="${API_HOST:-127.0.0.1}"
    export API_PORT="${API_PORT:-8000}"
    export BROWSER_WORKER_URL="${BROWSER_WORKER_URL:-http://127.0.0.1:8080}"
    export BROWSER_WORKER_TIMEOUT_SECONDS="${BROWSER_WORKER_TIMEOUT_SECONDS:-30}"
    export BROWSER_WORKER_HEALTH_TIMEOUT_SECONDS="${BROWSER_WORKER_HEALTH_TIMEOUT_SECONDS:-3}"
    export WORKER_AUTH_TOKEN="${WORKER_AUTH_TOKEN:-}"
    export API_AUTH_TOKEN="${API_AUTH_TOKEN:-}"
    export POLICY_BACKEND="${POLICY_BACKEND:-mock}"
    export INSPECTION_BACKEND="${INSPECTION_BACKEND:-mock}"
    export ALLOWED_DOMAINS="${ALLOWED_DOMAINS:-example.com}"
    export BLOCKED_DOMAINS="${BLOCKED_DOMAINS:-}"
    export DEFAULT_DOMAIN_POLICY="${DEFAULT_DOMAIN_POLICY:-deny}"
    export ALLOWED_PORTS="${ALLOWED_PORTS:-80,443}"
    export MAX_REDIRECTS="${MAX_REDIRECTS:-5}"
    export BLOCK_HTTPS_DOWNGRADE="${BLOCK_HTTPS_DOWNGRADE:-true}"
    export ALLOW_PRIVATE_NETWORKS="${ALLOW_PRIVATE_NETWORKS:-false}"
    export DNS_PREFLIGHT_ENABLED="${DNS_PREFLIGHT_ENABLED:-true}"
    export RATE_LIMIT_ENABLED="${RATE_LIMIT_ENABLED:-true}"
    export RATE_LIMIT_BACKEND="${RATE_LIMIT_BACKEND:-memory}"
    export RATE_LIMIT_FAIL_OPEN="${RATE_LIMIT_FAIL_OPEN:-false}"
    export REDIS_URL="${REDIS_URL:-}"
    cd api
    uvicorn app.main:app --host "${API_HOST:-127.0.0.1}" --port "${API_PORT:-8000}" --no-proxy-headers > "$LOG_DIR/api.log" 2>&1 &
    echo $! >> "$PID_FILE"
  )
}

wait_for() {
  local url="$1"
  local name="$2"
  local timeout="${3:-30}"
  local elapsed=0
  echo "Waiting for $name at $url..."
  while ! curl -sf "$url" >/dev/null 2>&1; do
    sleep 1
    elapsed=$((elapsed + 1))
    if [[ $elapsed -ge $timeout ]]; then
      echo "ERROR: $name did not become ready at $url within ${timeout}s"
      echo "Recent logs:"
      tail -20 "$LOG_DIR/$name.log" 2>/dev/null || true
      exit 1
    fi
  done
  echo "$name is ready."
}

start_proxy
start_worker
start_api

wait_for "http://127.0.0.1:9090/health/ready" "proxy" 30
wait_for "http://127.0.0.1:8080/health/ready" "worker" 60
wait_for "http://127.0.0.1:8000/health/ready" "api" 30

echo ""
echo "=== AgentShield is running ==="
echo "API:           http://127.0.0.1:8000"
echo "API docs:      http://127.0.0.1:8000/docs"
echo "Worker:        http://127.0.0.1:8080 (internal)"
echo "Egress proxy:  http://127.0.0.1:3128"
echo "Logs:          $LOG_DIR/"
echo ""
echo "Run ./scripts/stop.sh to stop all services."
echo "PIDs written to $PID_FILE"
