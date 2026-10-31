#!/bin/bash
set -e

echo "Running AgentShield Cyber Range Test Suite"
echo "=========================================="
cd "$(dirname "$0")/.."
api/.venv/bin/python -m pytest api/tests/ -q 2>&1 | tail -20