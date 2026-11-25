"""
ForensicFusion — Evidence Integrity
====================================

Provides SHA-256 hashing for files and byte-streams, plus an
``evidence record`` builder that captures chain-of-custody metadata
at upload time.
"""

from __future__ import annotations

import hashlib
import os
from typing import Optional, Union


def _human_readable_size(size_bytes: int) -> str:
    """Convert a byte count into a human-friendly string.

    Examples
    --------
    >>> _human_readable_size(0)
    '0 B'
    >>> _human_readable_size(1234)
    '1.2 KB'
    >>> _human_readable_size(1_048_576)
    '1.0 MB'
    """
    if size_bytes == 0:
        return "0 B"

    units = ("B", "KB", "MB", "GB", "TB")
    factor = 1024.0
    value = float(size_bytes)
    for unit in units:
        if abs(value) < factor or unit == units[-1]:
            if unit == "B":
                return f"{int(value)} B"
            return f"{value:.1f} {unit}"
        value /= factor
    # Fallback (should not be reached)
    return f"{size_bytes} B"  # pragma: no cover


def calculate_sha256(file_path_or_bytes: Union[str, bytes]) -> str:
    """Compute the SHA-256 hex digest of a file or raw bytes.

    Parameters
    ----------
    file_path_or_bytes:
        Either a filesystem path (``str``) pointing to a file, or raw
        ``bytes`` to hash directly.

    Returns
    -------
    str
        Lowercase hexadecimal SHA-256 digest.

    Raises
    ------
    FileNotFoundError
        If a string path is given but the file does not exist.
    TypeError
        If the argument is neither ``str`` nor ``bytes``.
    """
    if isinstance(file_path_or_bytes, bytes):
        return hashlib.sha256(file_path_or_bytes).hexdigest()

    if isinstance(file_path_or_bytes, str):
        if not os.path.isfile(file_path_or_bytes):
            raise FileNotFoundError(
                f"Cannot hash — file not found: {file_path_or_bytes}"
            )
        sha = hashlib.sha256()
        with open(file_path_or_bytes, "rb") as fh:
            for chunk in iter(lambda: fh.read(8192), b""):
                sha.update(chunk)
        return sha.hexdigest()

    raise TypeError(
        f"Expected str (file path) or bytes, got {type(file_path_or_bytes).__name__}"
    )


def create_evidence_record(
    filename: str,
    file_bytes: bytes,
    upload_time: Optional[str] = None,
) -> dict:
    """Build a metadata record for an uploaded evidence file.

    Parameters
    ----------
    filename:
        Original name of the uploaded file.
    file_bytes:
        The raw file contents.
    upload_time:
        ISO 8601 timestamp string of when the file was uploaded (defaults to current UTC time).

    Returns
    -------
    dict
        ``{ filename, file_size, sha256, upload_time, file_size_human }``
    """
    if upload_time is None:
        from datetime import datetime, timezone
        upload_time = datetime.now(timezone.utc).isoformat()

    file_size: int = len(file_bytes)
    sha256: str = calculate_sha256(file_bytes)

    return {
        "filename": filename,
        "file_size": file_size,
        "sha256": sha256,
        "upload_time": upload_time,
        "file_size_human": _human_readable_size(file_size),
    }
