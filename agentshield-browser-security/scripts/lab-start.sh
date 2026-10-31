#!/bin/bash
set -e

echo "Starting AgentShield Cyber Range (core + lab profiles)..."
docker compose --profile core --profile lab up -d --build

echo ""
echo "Waiting for services to be healthy..."
sleep 10

echo ""
echo "Service Status:"
docker compose ps
echo ""
echo "Frontend available at: http://127.0.0.1:3000"
echo "API available at: http://127.0.0.1:8000"
echo "Simulation Controller: http://127.0.0.1:8090"
echo "Evidence Collector: http://127.0.0.1:8091"