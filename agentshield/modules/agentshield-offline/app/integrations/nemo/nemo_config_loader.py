"""
AgentShield Offline — NeMo configuration loader.

Resolves which NeMo config profile to load and validates that the
directory exists and contains a config.yml before initialising the engine.

Profile directories:
  configs/nemo/local/          — heuristic rails, no model required
  configs/nemo/model_backed/   — LLM-backed rails, requires provider config
  configs/nemo/production/     — production-tuned rails
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import structlog

from app.core.configuration import get_settings
from app.integrations.nemo.exceptions import NemoConfigError

log = structlog.get_logger(__name__)

_VALID_PROFILES = {"local", "model_backed", "production"}


def resolve_config_path(
    base_path: Optional[str] = None,
    profile: Optional[str] = None,
) -> Path:
    """
    Return the Path to the NeMo config directory for the active profile.
    Raises NemoConfigError if the directory or config.yml is missing.
    """
    settings = get_settings()
    base = Path(base_path or settings.nemo_config_path)
    prof = (profile or settings.nemo_profile).lower()

    if prof not in _VALID_PROFILES:
        raise NemoConfigError(
            f"Unknown NeMo profile '{prof}'. Valid profiles: {_VALID_PROFILES}"
        )

    config_dir = base / prof
    config_file = config_dir / "config.yml"

    if not config_dir.exists():
        raise NemoConfigError(
            f"NeMo config directory not found: {config_dir}. "
            f"Create the directory and add a config.yml file, "
            f"or copy from configs/nemo/{prof}/config.yml.example"
        )
    if not config_file.exists():
        raise NemoConfigError(
            f"NeMo config.yml not found at: {config_file}"
        )

    log.info(
        "nemo_config_resolved",
        profile=prof,
        path=str(config_dir),
    )
    return config_dir


def load_rails_config(config_dir: Path):
    """
    Load a NeMo RailsConfig from the given directory.
    Raises NemoNotInstalledError if nemoguardrails is not installed.
    Raises NemoConfigError if the config is invalid.
    """
    try:
        from nemoguardrails import RailsConfig  # type: ignore[import]
    except ImportError as exc:
        from app.integrations.nemo.exceptions import NemoNotInstalledError
        raise NemoNotInstalledError() from exc

    try:
        cfg = RailsConfig.from_path(str(config_dir))
        log.info("nemo_rails_config_loaded", config_dir=str(config_dir))
        return cfg
    except Exception as exc:
        raise NemoConfigError(
            f"Failed to load NeMo RailsConfig from {config_dir}: {exc}"
        ) from exc
