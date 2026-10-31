from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

from .helpers import (
    ApiClient,
    FixtureSite,
    Stack,
    build_stack,
)


def pytest_collection_modifyitems(config, items):
    if os.environ.get("RUN_E2E") == "1":
        return
    skip = pytest.mark.skip(
        reason="real-process E2E tests are opt-in; set RUN_E2E=1 to run them"
    )
    for item in items:
        if "e2e" in item.keywords:
            item.add_marker(skip)


@pytest.fixture(scope="session")
def fixture_site() -> FixtureSite:
    site = FixtureSite()
    site.start()
    try:
        yield site
    finally:
        site.stop()


def _start_stack(name: str, **kwargs) -> Stack:
    log_dir = Path(tempfile.mkdtemp(prefix=f"agentshield-{name}-"))
    try:
        return build_stack(name, log_dir=log_dir, **kwargs)
    except Exception:
        chunks = []
        for path in sorted(log_dir.glob("*.log")):
            chunks.append(f"### {path.name}\n{path.read_text(errors='replace')[-8000:]}")
        raise AssertionError(
            f"failed to start {name} stack\n" + "\n".join(chunks)
        )


@pytest.fixture(scope="session")
def functional_stack() -> Stack:
    stack = _start_stack("functional")
    try:
        yield stack
    finally:
        stack.stop()


@pytest.fixture(scope="session")
def strict_stack() -> Stack:
    stack = _start_stack(
        "strict",
        allow_private=False,
        allowed_domains=(
            "127.0.0.1,localhost,localtest.me,169.254.169.254,"
            "10.0.0.1,172.16.0.1,192.168.1.1"
        ),
        api_extra_env={"LOG_LEVEL": "INFO"},
        worker_extra_env={"LOG_LEVEL": "info"},
    )
    try:
        yield stack
    finally:
        stack.stop()


@pytest.fixture()
def api(functional_stack: Stack) -> ApiClient:
    client = ApiClient(functional_stack.api_url)
    try:
        yield client
    finally:
        client.close()


@pytest.fixture()
def strict_api(strict_stack: Stack) -> ApiClient:
    client = ApiClient(strict_stack.api_url)
    try:
        yield client
    finally:
        client.close()
