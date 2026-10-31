"""
P1 module loader.

Adds P1's root directory to sys.path when the package has not been installed
as a proper Python package, then imports and returns the P1 classes.
This loader is the only place that touches sys.path — all other P1 integration
code imports through this module.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Optional

import structlog

from app.core.configuration import get_settings
from app.integrations.p1.exceptions import P1ConfigError, P1NotAvailableError

log = structlog.get_logger(__name__)

_P1_CLASSES: Optional[dict[str, Any]] = None


def _resolve_p1_path() -> Optional[Path]:
    """Return the directory that contains P1's `core/` package, or None."""
    settings = get_settings()
    # 1. Explicit path from settings
    explicit = getattr(settings, "p1_module_path", None)
    if explicit:
        p = Path(explicit).resolve()
        if (p / "core" / "security_engine.py").exists():
            return p

    # 2. Sibling directory convention: ../penetration-prevention--main
    candidate = Path(__file__).resolve().parent.parent.parent.parent.parent / "penetration-prevention--main"
    if (candidate / "core" / "security_engine.py").exists():
        return candidate

    return None


def ensure_p1_importable() -> Path:
    """
    Ensures P1's root is on sys.path and returns its path.
    Raises P1NotAvailableError if the module cannot be located.
    """
    p1_path = _resolve_p1_path()
    if p1_path is None:
        raise P1NotAvailableError()

    path_str = str(p1_path)
    if path_str not in sys.path:
        sys.path.insert(0, path_str)
        log.info("p1_path_added_to_sys_path", path=path_str)

    return p1_path


def load_p1_classes() -> dict[str, Any]:
    """
    Import and cache P1 classes.  Called once at initialisation.
    Returns a dict of class references keyed by name.
    """
    global _P1_CLASSES
    if _P1_CLASSES is not None:
        return _P1_CLASSES

    ensure_p1_importable()

    try:
        from core.config import AgentShieldConfig          # type: ignore[import]
        from core.security_engine import SecurityEngine    # type: ignore[import]
        from core.input_guard import InputGuard            # type: ignore[import]
        from core.output_guard import OutputGuard          # type: ignore[import]
        from core.schemas import (                         # type: ignore[import]
            Action, GuardrailContext, SourceType, TrustLevel,
        )
    except ImportError as exc:
        raise P1NotAvailableError() from exc
    except Exception as exc:
        raise P1ConfigError(f"Failed to import P1 modules: {exc}") from exc

    _P1_CLASSES = {
        "AgentShieldConfig": AgentShieldConfig,
        "SecurityEngine": SecurityEngine,
        "InputGuard": InputGuard,
        "OutputGuard": OutputGuard,
        "Action": Action,
        "GuardrailContext": GuardrailContext,
        "SourceType": SourceType,
        "TrustLevel": TrustLevel,
    }
    log.info("p1_classes_loaded", classes=list(_P1_CLASSES.keys()))
    return _P1_CLASSES
