#!/bin/bash
set -e

echo "Stopping AgentShield Cyber Range..."
docker compose --profile core --profile lab stop

echo ""
echo "Services stopped (data preserved in volumes)"