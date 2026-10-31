"""Structured (one JSON object per line) application logging.

Application events attach correlation fields — ``request_id``, ``download_id``,
``tenant_id``, stage, verdict — through ``extra``.  The default stdlib
formatter silently discards those fields, so a JSON formatter is installed
when this process has not configured root logging itself.  A host that owns
logging (uvicorn, pytest, an embedding service) keeps its own handlers and
level; this module never fights it.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

_RESERVED = frozenset(
    logging.LogRecord("", 0, "", 0, "", (), None).__dict__
) | {"message", "asctime"}


class JsonFormatter(logging.Formatter):
    """Serialises the record's structured fields without altering its data."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, object] = {
            "timestamp": datetime.fromtimestamp(
                record.created, tz=timezone.utc
            ).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "event": record.getMessage(),
        }
        for key, value in record.__dict__.items():
            if key in _RESERVED or key.startswith("_"):
                continue
            payload[key] = value
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def configure_logging(level: str) -> None:
    """Install the JSON handler only when root logging is unconfigured."""
    root = logging.getLogger()
    if root.handlers:
        return
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    root.addHandler(handler)
    root.setLevel(level.upper())
