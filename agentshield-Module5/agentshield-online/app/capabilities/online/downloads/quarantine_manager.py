"""
Quarantine manager — stores suspicious/infected files securely.
Quarantined files cannot be returned to agents.
Records full metadata for security audit.
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

from app.capabilities.online.downloads.file_hasher import hash_file

logger = logging.getLogger(__name__)


class QuarantineRecord:
    def __init__(
        self,
        quarantine_id: str,
        original_url: str,
        sha256: str,
        file_size: int,
        mime_type: str,
        scan_result: str,
        security_decision: str,
        quarantine_reason: str,
        quarantine_path: str,
        timestamp: datetime,
    ) -> None:
        self.quarantine_id = quarantine_id
        self.original_url = original_url
        self.sha256 = sha256
        self.file_size = file_size
        self.mime_type = mime_type
        self.scan_result = scan_result
        self.security_decision = security_decision
        self.quarantine_reason = quarantine_reason
        self.quarantine_path = quarantine_path
        self.timestamp = timestamp

    def to_dict(self) -> dict[str, Any]:
        return {
            "quarantine_id": self.quarantine_id,
            "original_url": self.original_url,
            "sha256": self.sha256,
            "file_size": self.file_size,
            "mime_type": self.mime_type,
            "scan_result": self.scan_result,
            "security_decision": self.security_decision,
            "quarantine_reason": self.quarantine_reason,
            "timestamp": self.timestamp.isoformat(),
            # Do NOT include quarantine_path in external responses
        }


class QuarantineManager:
    """
    Moves suspicious files to a restricted quarantine directory.
    Records full metadata.
    Quarantined files are NEVER returned to agents.
    """

    def __init__(self, quarantine_dir: str = "./quarantine") -> None:
        self._dir = Path(quarantine_dir)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._metadata_file = self._dir / "quarantine_manifest.jsonl"
        # In-memory index for fast lookups
        self._records: dict[str, QuarantineRecord] = {}
        self._load_existing()

    def _load_existing(self) -> None:
        if self._metadata_file.exists():
            try:
                with open(self._metadata_file) as f:
                    for line in f:
                        data = json.loads(line.strip())
                        rec = QuarantineRecord(**{
                            k: (datetime.fromisoformat(v) if k == "timestamp" else v)
                            for k, v in data.items()
                        })
                        self._records[rec.quarantine_id] = rec
            except Exception as e:
                logger.warning("QuarantineManager: could not load manifest: %s", e)

    def quarantine(
        self,
        file_path: str | Path,
        original_url: str,
        mime_type: str,
        scan_result: str,
        security_decision: str,
        quarantine_reason: str,
    ) -> QuarantineRecord:
        """
        Move file to quarantine and record metadata.
        Returns the QuarantineRecord (without path for external use).
        """
        src = Path(file_path)
        quarantine_id = f"quar_{uuid.uuid4().hex[:12]}"
        dest = self._dir / quarantine_id

        # Compute hash before moving
        try:
            sha256 = hash_file(src)
            file_size = src.stat().st_size
        except Exception as e:
            logger.error("QuarantineManager: could not hash file %s: %s", src, e)
            sha256 = "UNKNOWN"
            file_size = 0

        # Move to quarantine
        try:
            shutil.move(str(src), str(dest))
            # Remove execute permissions
            os.chmod(dest, 0o600)
        except Exception as e:
            logger.error("QuarantineManager: could not move file: %s", e)

        record = QuarantineRecord(
            quarantine_id=quarantine_id,
            original_url=original_url,
            sha256=sha256,
            file_size=file_size,
            mime_type=mime_type,
            scan_result=scan_result,
            security_decision=security_decision,
            quarantine_reason=quarantine_reason,
            quarantine_path=str(dest),
            timestamp=datetime.utcnow(),
        )
        self._records[quarantine_id] = record
        self._persist(record)

        logger.warning(
            "File quarantined: id=%s url=%s sha256=%s reason=%s",
            quarantine_id,
            original_url[:80],
            sha256[:16],
            quarantine_reason,
        )
        return record

    def _persist(self, record: QuarantineRecord) -> None:
        try:
            data = record.to_dict()
            data["quarantine_path"] = record.quarantine_path  # include internally
            with open(self._metadata_file, "a") as f:
                f.write(json.dumps(data) + "\n")
        except Exception as e:
            logger.error("QuarantineManager: could not persist record: %s", e)

    def get_record(self, quarantine_id: str) -> QuarantineRecord | None:
        return self._records.get(quarantine_id)

    def list_records(self) -> list[dict[str, Any]]:
        return [r.to_dict() for r in self._records.values()]
