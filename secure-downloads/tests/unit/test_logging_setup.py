"""Structured logging output (Prompt 3, Phase 3F)."""
from __future__ import annotations

import json
import logging
import sys

from config.logging_setup import JsonFormatter, configure_logging


def _record(message: str, *, exc_info=None) -> logging.LogRecord:
    return logging.LogRecord(
        name="api.middleware",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg=message,
        args=(),
        exc_info=exc_info,
    )


def test_structured_extras_are_serialised_as_json():
    record = _record("request_completed")
    record.request_id = "req-abc"
    record.method = "POST"
    record.status_code = 200
    record.elapsed_ms = 12

    payload = json.loads(JsonFormatter().format(record))

    assert payload["event"] == "request_completed"
    assert payload["level"] == "INFO"
    assert payload["logger"] == "api.middleware"
    assert payload["request_id"] == "req-abc"
    assert payload["method"] == "POST"
    assert payload["status_code"] == 200
    assert payload["elapsed_ms"] == 12
    assert "timestamp" in payload


def test_stdlib_bookkeeping_fields_are_not_duplicated():
    payload = json.loads(JsonFormatter().format(_record("event")))
    for field in ("msg", "args", "pathname", "lineno", "levelno", "exc_info"):
        assert field not in payload


def test_exception_details_are_attached():
    try:
        1 / 0
    except ZeroDivisionError:
        record = _record("unhandled_exception", exc_info=sys.exc_info())

    payload = json.loads(JsonFormatter().format(record))

    assert "ZeroDivisionError" in payload["exception"]


def test_host_logging_configuration_is_left_untouched():
    root = logging.getLogger()
    before = list(root.handlers)

    configure_logging("DEBUG")

    # pytest (or uvicorn) owns logging here: no handler is added or replaced.
    assert root.handlers == before


def test_json_handler_is_installed_when_root_is_unconfigured():
    root = logging.getLogger()
    saved_handlers = list(root.handlers)
    saved_level = root.level
    for handler in saved_handlers:
        root.removeHandler(handler)
    try:
        configure_logging("DEBUG")

        assert len(root.handlers) == 1
        assert isinstance(root.handlers[0].formatter, JsonFormatter)
        assert root.level == logging.DEBUG
    finally:
        for handler in list(root.handlers):
            root.removeHandler(handler)
        for handler in saved_handlers:
            root.addHandler(handler)
        root.setLevel(saved_level)
