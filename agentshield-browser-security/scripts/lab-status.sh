#!/bin/bash
set -e

echo "AgentShield Cyber Range Status"
echo "=============================="
echo ""
docker compose --profile core --profile lab ps
echo ""
echo "Health Checks:"
echo "API: $(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8000/health/ready || echo 'UNREACHABLE')"
echo "Frontend: $(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:3000 || echo 'UNREACHABLE')"
echo "Simulation Controller: $(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8090/health || echo 'UNREACHABLE')"
echo "Evidence Collector: $(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8091/health || echo 'UNREACHABLE')"