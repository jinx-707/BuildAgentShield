"""
AgentShield Offline — Document Quarantine.

Moves suspicious documents to a restricted quarantine directory with
0600 permissions. Quarantined documents are never returned to the agent.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import structlog

from app.core.configuration import get_settings

log = structlog.get_logger(__name__)


class QuarantineManager:
    """
    Manages document quarantine storage.
    """

    def __init__(self, quarantine_dir: Optional[str] = None) -> None:
        settings = get_settings()
        self._dir = Path(quarantine_dir or settings.quarantine_dir)
        self._dir.mkdir(parents=True, exist_ok=True)
        # Restrict directory permissions (owner only)
        try:
            os.chmod(self._dir, stat.S_IRWXU)
        except OSError:
            pass  # Windows may not support this
        log.info("quarantine_initialized", dir=str(self._dir))

    def quarantine(
        self,
        source_path: Path,
        *,
        reason: str,
        original_hash: str,
        document_id: str,
        metadata: Optional[dict] = None,
    ) -> str:
        """
        Move a file to quarantine and record metadata.
        Returns the quarantine ID.
        """
        quarantine_id = str(uuid.uuid4())
        q_dir = self._dir / quarantine_id
        q_dir.mkdir(parents=True, exist_ok=True)

        # Move the file
        q_file = q_dir / source_path.name
        try:
            shutil.move(str(source_path), str(q_file))
        except Exception as exc:
            # Copy as fallback
            try:
                shutil.copy2(str(source_path), str(q_file))
            except Exception:
                pass
            log.error("quarantine_move_failed", error=str(exc))

        # Restrict file permissions
        try:
            os.chmod(q_file, stat.S_IRUSR)
        except OSError:
            pass

        # Write metadata record
        meta_file = q_dir / "quarantine.json"
        record = {
            "quarantine_id": quarantine_id,
            "document_id": document_id,
            "original_filename": source_path.name,
            "original_hash": original_hash,
            "reason": reason,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "metadata": metadata or {},
        }
        with meta_file.open("w", encoding="utf-8") as f:
            json.dump(record, f, indent=2)

        log.warning(
            "document_quarantined",
            quarantine_id=quarantine_id,
            document_id=document_id,
            reason=reason,
        )
        return quarantine_id

    def get_quarantine_record(self, quarantine_id: str) -> Optional[dict]:
        meta_file = self._dir / quarantine_id / "quarantine.json"
        if not meta_file.exists():
            return None
        with meta_file.open("r", encoding="utf-8") as f:
            return json.load(f)

    def release(self, quarantine_id: str, destination: Path) -> bool:
        """
        Release a quarantined file to a specified destination.
        Requires explicit authorisation (not implemented here — add auth check).
        Returns True on success.
        """
        q_dir = self._dir / quarantine_id
        if not q_dir.exists():
            return False
        meta = self.get_quarantine_record(quarantine_id)
        if not meta:
            return False
        q_file = q_dir / meta["original_filename"]
        if not q_file.exists():
            return False
        shutil.copy2(str(q_file), str(destination))
        log.warning("document_released_from_quarantine", quarantine_id=quarantine_id)
        return True
