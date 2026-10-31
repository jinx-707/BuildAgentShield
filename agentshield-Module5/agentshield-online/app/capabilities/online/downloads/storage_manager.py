"""
Storage manager for downloads — secure temporary file storage.
"""
from __future__ import annotations

import logging
import os
import uuid
from pathlib import Path

logger = logging.getLogger(__name__)


class StorageManager:
    """Manages secure temporary storage for downloaded files."""

    def __init__(self, base_dir: str = "./downloads") -> None:
        self._base = Path(base_dir)
        self._base.mkdir(parents=True, exist_ok=True)

    def allocate(self, suffix: str = ".tmp") -> Path:
        """Reserve a secure path for a new download."""
        filename = f"dl_{uuid.uuid4().hex}{suffix}"
        path = self._base / filename
        return path

    def exists(self, file_path: str | Path) -> bool:
        return Path(file_path).exists()

    def delete(self, file_path: str | Path) -> None:
        try:
            Path(file_path).unlink(missing_ok=True)
        except Exception as e:
            logger.warning("StorageManager: could not delete %s: %s", file_path, e)

    def get_size(self, file_path: str | Path) -> int:
        try:
            return Path(file_path).stat().st_size
        except Exception:
            return 0
