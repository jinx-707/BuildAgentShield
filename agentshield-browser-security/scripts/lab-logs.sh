#!/bin/bash
set -e

echo "AgentShield Cyber Range Logs"
echo "==========================="
docker compose --profile core --profile lab logs -f --tail=50 "$@"