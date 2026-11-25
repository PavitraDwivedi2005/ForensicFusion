"""
ForensicFusion — Multi-Source Evidence Parser
=============================================

Parses CSV evidence files from authentication logs, audit trails, and file
activity monitors into a standardized event dictionary format.

Each parser subclass handles the column-mapping quirks of its source type
and fills in ``None`` for any columns that are absent.
"""

from __future__ import annotations

import csv
import os
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Type


# ---------------------------------------------------------------------------
# Standardised event field names (order used in output dicts)
# ---------------------------------------------------------------------------
STANDARD_FIELDS: List[str] = [
    "event_id",
    "timestamp",
    "original_timestamp",
    "source_type",
    "event_type",
    "username",
    "session_id",
    "source_ip",
    "pid",
    "ppid",
    "process",
    "executable",
    "file_path",
    "file_hash",
    "action",
    "source_file",
]


def _safe_int(value: Optional[str]) -> Optional[int]:
    """Convert *value* to ``int``, returning ``None`` on failure."""
    if value is None:
        return None
    try:
        return int(value)
    except (ValueError, TypeError):
        return None


def _safe_str(value: Optional[str]) -> Optional[str]:
    """Return stripped string or ``None`` for empty / missing values."""
    if value is None:
        return None
    value = str(value).strip()
    return value if value else None


# ---------------------------------------------------------------------------
# Base class
# ---------------------------------------------------------------------------

class LogParser(ABC):
    """Abstract base class for all evidence-log parsers.

    Subclasses must implement :pymethod:`_map_row` which converts a single
    CSV ``DictReader`` row into the standardised event dictionary.
    """

    source_type: str = ""  # overridden by subclasses

    # --------------------------------------------------------------------- #
    def parse(self, filepath: str) -> List[dict]:
        """Read *filepath* (CSV) and return a list of standardised event dicts.

        Parameters
        ----------
        filepath:
            Absolute or relative path to the CSV file.

        Returns
        -------
        List[dict]
            Each dict contains the keys listed in :pydata:`STANDARD_FIELDS`.

        Raises
        ------
        FileNotFoundError
            If *filepath* does not exist.
        """
        if not os.path.isfile(filepath):
            raise FileNotFoundError(f"Evidence file not found: {filepath}")

        events: List[dict] = []
        source_file = os.path.basename(filepath)

        with open(filepath, "r", encoding="utf-8-sig", newline="") as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                event = self._map_row(row, source_file)
                if event is not None:
                    events.append(event)
        return events

    # --------------------------------------------------------------------- #
    @abstractmethod
    def _map_row(self, row: Dict[str, str], source_file: str) -> Optional[dict]:
        """Convert a single CSV row into a standardised event dict.

        Parameters
        ----------
        row:
            A dictionary produced by ``csv.DictReader``.
        source_file:
            The base filename of the source CSV.

        Returns
        -------
        dict or None
            Standardised event dictionary, or ``None`` to skip the row.
        """
        ...  # pragma: no cover

    # --------------------------------------------------------------------- #
    @staticmethod
    def _blank_event() -> dict:
        """Return a template event dict with every standard field set to ``None``."""
        return {field: None for field in STANDARD_FIELDS}


# ---------------------------------------------------------------------------
# Authentication log parser
# ---------------------------------------------------------------------------

class AuthenticationParser(LogParser):
    """Parser for authentication / SSH log CSVs.

    Column mapping
    ~~~~~~~~~~~~~~
    ============== =====================
    CSV column      Standardised field
    ============== =====================
    event_id        event_id
    timestamp       timestamp
    username        username
    source_ip       source_ip
    auth_result     action
    ssh_session     session_id
    event_type      event_type
    ============== =====================
    """

    source_type: str = "authentication"

    def _map_row(self, row: Dict[str, str], source_file: str) -> Optional[dict]:
        event = self._blank_event()
        event["event_id"] = _safe_str(row.get("event_id"))
        event["timestamp"] = _safe_str(row.get("timestamp"))
        event["original_timestamp"] = event["timestamp"]
        event["source_type"] = self.source_type
        event["event_type"] = _safe_str(row.get("event_type"))
        event["username"] = _safe_str(row.get("username"))
        event["session_id"] = _safe_str(row.get("ssh_session"))
        event["source_ip"] = _safe_str(row.get("source_ip"))
        event["action"] = _safe_str(row.get("auth_result"))
        event["source_file"] = source_file
        return event


# ---------------------------------------------------------------------------
# Audit log parser
# ---------------------------------------------------------------------------

class AuditParser(LogParser):
    """Parser for audit-trail CSVs (e.g. ``auditd``-style logs).

    Column mapping
    ~~~~~~~~~~~~~~
    =============== =====================
    CSV column       Standardised field
    =============== =====================
    event_id         event_id
    timestamp        timestamp
    username         username
    uid              (ignored — kept for reference only)
    audit_session    session_id
    pid              pid
    ppid             ppid
    command          process
    executable       executable
    event_type       event_type
    =============== =====================
    """

    source_type: str = "audit"

    def _map_row(self, row: Dict[str, str], source_file: str) -> Optional[dict]:
        event = self._blank_event()
        event["event_id"] = _safe_str(row.get("event_id"))
        event["timestamp"] = _safe_str(row.get("timestamp"))
        event["original_timestamp"] = event["timestamp"]
        event["source_type"] = self.source_type
        event["event_type"] = _safe_str(row.get("event_type"))
        event["username"] = _safe_str(row.get("username"))
        event["session_id"] = _safe_str(row.get("audit_session"))
        event["pid"] = _safe_int(row.get("pid"))
        event["ppid"] = _safe_int(row.get("ppid"))
        event["process"] = _safe_str(row.get("command"))
        event["executable"] = _safe_str(row.get("executable"))
        event["source_file"] = source_file
        return event


# ---------------------------------------------------------------------------
# File-activity parser
# ---------------------------------------------------------------------------

class FileActivityParser(LogParser):
    """Parser for file-activity monitor CSVs (e.g. ``inotify`` / ``fanotify``).

    Column mapping
    ~~~~~~~~~~~~~~
    ============== =====================
    CSV column      Standardised field
    ============== =====================
    event_id        event_id
    timestamp       timestamp
    username        username
    session_id      session_id
    pid             pid
    file_path       file_path
    action          action
    file_hash       file_hash
    ============== =====================
    """

    source_type: str = "file_activity"

    def _map_row(self, row: Dict[str, str], source_file: str) -> Optional[dict]:
        event = self._blank_event()
        event["event_id"] = _safe_str(row.get("event_id"))
        event["timestamp"] = _safe_str(row.get("timestamp"))
        event["original_timestamp"] = event["timestamp"]
        event["source_type"] = self.source_type
        event["event_type"] = _safe_str(row.get("event_type"))
        event["username"] = _safe_str(row.get("username"))
        event["session_id"] = _safe_str(row.get("session_id"))
        event["pid"] = _safe_int(row.get("pid"))
        event["file_path"] = _safe_str(row.get("file_path"))
        event["file_hash"] = _safe_str(row.get("file_hash"))
        event["action"] = _safe_str(row.get("action"))
        event["source_file"] = source_file
        return event


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

class ParserFactory:
    """Factory that returns the correct :class:`LogParser` subclass for a
    given evidence source type.

    Usage::

        parser = ParserFactory.get_parser("authentication")
        events = parser.parse("auth_logs.csv")
    """

    _registry: Dict[str, Type[LogParser]] = {
        "authentication": AuthenticationParser,
        "audit": AuditParser,
        "file_activity": FileActivityParser,
    }

    @classmethod
    def get_parser(cls, source_type: str) -> LogParser:
        """Return an instance of the parser for *source_type*.

        Parameters
        ----------
        source_type:
            One of ``"authentication"``, ``"audit"``, or ``"file_activity"``.

        Raises
        ------
        ValueError
            If *source_type* is not recognised.
        """
        source_type = source_type.strip().lower()
        parser_cls = cls._registry.get(source_type)
        if parser_cls is None:
            valid = ", ".join(sorted(cls._registry.keys()))
            raise ValueError(
                f"Unknown source type '{source_type}'. "
                f"Valid types: {valid}"
            )
        return parser_cls()

    @classmethod
    def supported_types(cls) -> List[str]:
        """Return a sorted list of supported source-type strings."""
        return sorted(cls._registry.keys())
