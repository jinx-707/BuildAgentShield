"""DEMO 2: SSRF attempts are rejected before the protected destination.

The strict stack deliberately allows the *names* under test in the domain
policy while keeping private-network access disabled. That isolates the
address-level control: a rejection is proof that the IP/DNS guard fired, not
merely that an allowlist happened to exclude the host.
"""

from __future__ import annotations

import pytest

from .helpers import ApiClient, FixtureSite, Stack

pytestmark = pytest.mark.e2e


def _assert_private_block(response) -> None:
    assert response.status_code == 403, response.text
    detail = response.json()["detail"]
    assert detail["code"] in {
        "PRIVATE_IP_BLOCKED",
        "DNS_RESOLUTION_FAILED",
        "DOMAIN_BLOCKED",
    }, detail


@pytest.mark.parametrize(
    "template",
    [
        "http://127.0.0.1:{port}/ssrf-target",
        "http://10.0.0.1:{port}/ssrf-target",
        "http://172.16.0.1:{port}/ssrf-target",
        "http://192.168.1.1:{port}/ssrf-target",
        "http://169.254.169.254/latest/meta-data/",
        "http://100.100.100.200/latest/meta-data/",
    ],
)
def test_ssrf_literal_addresses_are_rejected(
    strict_api: ApiClient, fixture_site: FixtureSite, template: str
) -> None:
    before = fixture_site.count("/ssrf-target")
    url = template.format(port=fixture_site.port)
    response = strict_api.navigate(url)

    _assert_private_block(response)
    assert fixture_site.count("/ssrf-target") == before


def test_ssrf_hostname_resolving_to_private_is_rejected(
    strict_api: ApiClient, fixture_site: FixtureSite
) -> None:
    before = fixture_site.count("/ssrf-target")
    response = strict_api.navigate(
        f"http://localtest.me:{fixture_site.port}/ssrf-target"
    )

    _assert_private_block(response)
    assert response.json()["detail"]["code"] == "PRIVATE_IP_BLOCKED"
    assert fixture_site.count("/ssrf-target") == before


def test_ssrf_rejection_happens_in_the_api(
    strict_api: ApiClient, strict_stack: Stack, fixture_site: FixtureSite
) -> None:
    response = strict_api.navigate(
        f"http://127.0.0.1:{fixture_site.port}/ssrf-target"
    )
    _assert_private_block(response)

    api_log = strict_stack.apis[0].service.output()
    assert "browser_navigation_blocked" in api_log
    assert "PRIVATE_IP_BLOCKED" in api_log
    assert f"127.0.0.1:{fixture_site.port}/ssrf-target" not in (
        strict_stack.worker.service.output()
    )
