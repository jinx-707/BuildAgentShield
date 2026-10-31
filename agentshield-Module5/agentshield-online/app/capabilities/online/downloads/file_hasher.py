"""
File hasher — SHA-256 hashing for downloaded files.
"""
from __future__ import annotations

import hashlib
from pathlib import Path


def hash_file(file_path: str | Path) -> str:
    """Compute SHA-256 of a file. Returns hex digest."""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def hash_bytes(data: bytes) -> str:
    """Compute SHA-256 of bytes."""
    return hashlib.sha256(data).hexdigest()
