"""In-memory SSE event broadcaster for real-time security monitoring.

Publishes audit events to subscribed Server-Sent Event clients. This is a
single-process broadcaster; Redis pub/sub can be added later for multi-replica
deployments. It is intentionally lightweight: no Kafka or large infrastructure
dependency is required for the SSE pipeline.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

logger = logging.getLogger(__name__)


class EventBroadcaster:
    """Fan-out broadcast channel for SSE clients.

    Subscribers register an asyncio.Queue. Publishers call :meth:`publish` and
    every connected subscriber receives the event. Queues are bounded; a slow
    subscriber is dropped to prevent memory growth.
    """

    def __init__(self, max_queue_size: int = 1000) -> None:
        self._subscribers: set[asyncio.Queue[str]] = set()
        self._lock = asyncio.Lock()
        self._max_queue_size = max_queue_size

    async def subscribe(self) -> asyncio.Queue[str]:
        queue: asyncio.Queue[str] = asyncio.Queue(maxsize=self._max_queue_size)
        async with self._lock:
            self._subscribers.add(queue)
        return queue

    async def unsubscribe(self, queue: asyncio.Queue[str]) -> None:
        async with self._lock:
            self._subscribers.discard(queue)

    async def publish(self, event: dict[str, Any]) -> None:
        payload = json.dumps(event, default=str)
        disconnected: list[asyncio.Queue[str]] = []
        async with self._lock:
            subscribers = list(self._subscribers)
        for queue in subscribers:
            try:
                queue.put_nowait(payload)
            except asyncio.QueueFull:
                disconnected.append(queue)
        for queue in disconnected:
            await self.unsubscribe(queue)

    def subscriber_count(self) -> int:
        return len(self._subscribers)


# Shared singleton attached to app state in create_app().
broadcaster = EventBroadcaster()
