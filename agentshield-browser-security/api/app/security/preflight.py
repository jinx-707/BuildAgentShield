from __future__ import annotations

from app.security.dns_policy import DnsValidator
from app.security.url_policy import UrlPolicy, ValidatedUrl


class NetworkPreflight:
    def __init__(
        self,
        *,
        url_policy: UrlPolicy,
        dns_validator: DnsValidator,
        dns_enabled: bool = True,
    ) -> None:
        self._url_policy = url_policy
        self._dns_validator = dns_validator
        self._dns_enabled = dns_enabled

    async def validate(self, raw_url: str) -> ValidatedUrl:
        validated = self._url_policy.validate(raw_url)
        if self._dns_enabled:
            await self._dns_validator.validate(validated)
        return validated
