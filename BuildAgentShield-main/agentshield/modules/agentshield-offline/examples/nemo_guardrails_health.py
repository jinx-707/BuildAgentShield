"""
AgentShield + NeMo — Health & Status Demo.

Shows NeMo engine status, configuration, and health reporting.

Usage:
    python examples/nemo_guardrails_health.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.integrations.nemo.nemo_health import get_nemo_health


def demo() -> None:
    print("\n" + "="*60)
    print("  AgentShield — NeMo Guardrails Health Report")
    print("="*60)

    # ---- NeMo disabled (default) ----
    health_disabled = get_nemo_health(None)
    print("\n[A] NeMo disabled (default):")
    for k, v in health_disabled.items():
        print(f"    {k:30s}: {v}")

    # ---- NeMo enabled with mock engine ----
    from tests.fixtures.nemo.mock_engine import MockNemoEngine, make_passed_result
    engine = MockNemoEngine(input_result=make_passed_result())
    health_enabled = get_nemo_health(engine)
    print("\n[B] NeMo enabled (mock engine):")
    for k, v in health_enabled.items():
        print(f"    {k:30s}: {v}")

    # ---- Verify no secrets in health output ----
    health_str = str(health_enabled)
    secrets_to_check = ["sk-", "AKIA", "password=", "token=", "api_key="]
    for s in secrets_to_check:
        assert s not in health_str.lower(), f"Secret pattern '{s}' found in health output!"

    print("\n[C] Security check: no secrets in health output — PASSED")
    print("\nTo enable NeMo in production:")
    print("  export AGENTSHIELD_NEMO_ENABLED=true")
    print("  export AGENTSHIELD_NEMO_PROFILE=local")
    print("  pip install -e '[nemo]'")
    print("  python -m app.main")
    print("="*60 + "\n")


if __name__ == "__main__":
    demo()
