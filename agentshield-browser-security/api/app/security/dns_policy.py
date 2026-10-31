from __future__ import annotations

import asyncio
import socket
from typing import Protocol

from app.security.errors import (
    DNS_RESOLUTION_FAILED,
    PRIVATE_IP_BLOCKED,
    SecurityViolation,
)
from app.security.ip_policy import is_blocked_ip, parse_ip
from app.security.url_policy import ValidatedUrl


class DnsResolver(Protocol):
    async def resolve(self, hostname: str) -> list[str]:
        ...


class SystemDnsResolver:
    async def resolve(self, hostname: str) -> list[str]:
        return await asyncio.to_thread(self._resolve_sync, hostname)

    @staticmethod
    def _resolve_sync(hostname: str) -> list[str]:
        results = socket.getaddrinfo(
            hostname,
            None,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
        )
        addresses: list[str] = []
        for result in results:
            address = result[4][0]
            if address not in addresses:
                addresses.append(address)
        return addresses


class DnsValidator:
    def __init__(
        self,
        *,
        resolver: DnsResolver | None = None,
        allow_private_networks: bool = False,
    ) -> None:
        self._resolver = resolver or SystemDnsResolver()
        self._allow_private = allow_private_networks

    async def validate(self, validated_url: ValidatedUrl) -> None:
        if validated_url.is_ip:
            return

        try:
            addresses = await self._resolver.resolve(validated_url.hostname)
        except Exception as exc:
            raise SecurityViolation(
                DNS_RESOLUTION_FAILED,
                "The destination hostname could not be resolved safely.",
            ) from exc

        if not addresses:
            raise SecurityViolation(
                DNS_RESOLUTION_FAILED,
                "The destination hostname could not be resolved safely.",
            )

        for address in addresses:
            parsed = parse_ip(address)
            if parsed is None or is_blocked_ip(
                address, allow_private=self._allow_private
            ):
                raise SecurityViolation(
                    PRIVATE_IP_BLOCKED,
                    "The destination resolves to a restricted network.",
                )
