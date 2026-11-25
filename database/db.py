"""
ForensicFusion Database Module — SQLite persistence layer.

Provides the :class:`ForensicDatabase` class that stores investigations,
evidence files, parsed events, correlation results, and event groups in a
local SQLite database.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


class ForensicDatabase:
    """SQLite-backed storage for forensic investigations and analysis results.

    Parameters
    ----------
    db_path : str
        Filesystem path for the SQLite database file.
        Defaults to ``"forensicfusion.db"`` in the current working directory.
    """

    def __init__(self, db_path: str = "forensicfusion.db") -> None:
        self.db_path: str = db_path
        self.init_db()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        """Return a new connection with foreign-key enforcement enabled."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    # ------------------------------------------------------------------
    # Schema initialisation
    # ------------------------------------------------------------------

    def init_db(self) -> None:
        """Create all tables if they do not already exist."""
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS investigations (
                    id           INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_name    TEXT    NOT NULL,
                    investigator TEXT,
                    description  TEXT,
                    created_at   TEXT,
                    status       TEXT    DEFAULT 'active'
                );

                CREATE TABLE IF NOT EXISTS evidence_files (
                    id               INTEGER PRIMARY KEY AUTOINCREMENT,
                    investigation_id INTEGER REFERENCES investigations(id),
                    filename         TEXT,
                    file_size        INTEGER,
                    sha256           TEXT,
                    upload_time      TEXT,
                    source_type      TEXT,
                    event_count      INTEGER
                );

                CREATE TABLE IF NOT EXISTS events (
                    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
                    investigation_id   INTEGER REFERENCES investigations(id),
                    event_id           TEXT,
                    timestamp          TEXT,
                    original_timestamp TEXT,
                    source_type        TEXT,
                    event_type         TEXT,
                    username           TEXT,
                    session_id         TEXT,
                    source_ip          TEXT,
                    pid                INTEGER,
                    ppid               INTEGER,
                    process            TEXT,
                    executable         TEXT,
                    file_path          TEXT,
                    file_hash          TEXT,
                    action             TEXT,
                    source_file        TEXT
                );

                CREATE TABLE IF NOT EXISTS correlations (
                    id               INTEGER PRIMARY KEY AUTOINCREMENT,
                    investigation_id INTEGER REFERENCES investigations(id),
                    event_a_id       TEXT,
                    event_b_id       TEXT,
                    total_score      REAL,
                    classification   TEXT,
                    explanation      TEXT,
                    factors_json     TEXT
                );

                CREATE TABLE IF NOT EXISTS event_groups (
                    id               INTEGER PRIMARY KEY AUTOINCREMENT,
                    investigation_id INTEGER REFERENCES investigations(id),
                    group_index      INTEGER,
                    event_ids_json   TEXT
                );
                """
            )

    # ------------------------------------------------------------------
    # Investigations
    # ------------------------------------------------------------------

    def create_investigation(
        self,
        case_name: str,
        investigator: str,
        description: str,
    ) -> int:
        """Create a new investigation and return its ID.

        Parameters
        ----------
        case_name : str
            Short name / title for the case.
        investigator : str
            Name of the lead investigator.
        description : str
            Free-text description of the investigation.

        Returns
        -------
        int
            The auto-generated investigation ID.
        """
        created_at = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO investigations (case_name, investigator, description, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (case_name, investigator, description, created_at),
            )
            return cursor.lastrowid  # type: ignore[return-value]

    def get_investigation(self, inv_id: int) -> Optional[Dict[str, Any]]:
        """Retrieve a single investigation by ID, or ``None`` if not found."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM investigations WHERE id = ?", (inv_id,)
            ).fetchone()
            return dict(row) if row else None

    def list_investigations(self) -> List[Dict[str, Any]]:
        """Return every investigation, newest first."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM investigations ORDER BY created_at DESC"
            ).fetchall()
            return [dict(r) for r in rows]

    def delete_investigation(self, inv_id: int) -> None:
        """Delete an investigation and all its related records.

        Cascading deletes are performed manually so that the schema does not
        require ``ON DELETE CASCADE`` (which needs ``PRAGMA foreign_keys``
        at connection time — already enabled, but explicit deletion is safer).
        """
        with self._connect() as conn:
            conn.execute("DELETE FROM event_groups  WHERE investigation_id = ?", (inv_id,))
            conn.execute("DELETE FROM correlations   WHERE investigation_id = ?", (inv_id,))
            conn.execute("DELETE FROM events         WHERE investigation_id = ?", (inv_id,))
            conn.execute("DELETE FROM evidence_files WHERE investigation_id = ?", (inv_id,))
            conn.execute("DELETE FROM investigations WHERE id = ?", (inv_id,))

    # ------------------------------------------------------------------
    # Evidence files
    # ------------------------------------------------------------------

    def add_evidence_file(
        self,
        investigation_id: int,
        evidence_record: Dict[str, Any],
        source_type: str,
        event_count: int,
    ) -> None:
        """Insert an evidence-file metadata record.

        Parameters
        ----------
        investigation_id : int
            Owning investigation.
        evidence_record : dict
            Must contain ``filename``, ``file_size``, and ``sha256``.
        source_type : str
            One of ``"authentication"``, ``"audit"``, ``"file_activity"``.
        event_count : int
            Number of events parsed from the file.
        """
        upload_time = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO evidence_files
                    (investigation_id, filename, file_size, sha256,
                     upload_time, source_type, event_count)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    investigation_id,
                    evidence_record.get("filename", ""),
                    evidence_record.get("file_size", 0),
                    evidence_record.get("sha256", ""),
                    upload_time,
                    source_type,
                    event_count,
                ),
            )

    def get_evidence_files(self, investigation_id: int) -> List[Dict[str, Any]]:
        """Return all evidence files for a given investigation."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM evidence_files WHERE investigation_id = ? ORDER BY upload_time",
                (investigation_id,),
            ).fetchall()
            return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Events
    # ------------------------------------------------------------------

    def add_events(self, investigation_id: int, events: List[Dict[str, Any]]) -> None:
        """Bulk-insert parsed events into the database.

        Parameters
        ----------
        investigation_id : int
            Owning investigation.
        events : list of dict
            Each dict should contain event fields such as ``event_id``,
            ``timestamp``, ``source_type``, etc.
        """
        with self._connect() as conn:
            conn.executemany(
                """
                INSERT INTO events
                    (investigation_id, event_id, timestamp, original_timestamp,
                     source_type, event_type, username, session_id, source_ip,
                     pid, ppid, process, executable, file_path, file_hash,
                     action, source_file)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        investigation_id,
                        e.get("event_id", ""),
                        e.get("timestamp", ""),
                        e.get("original_timestamp", ""),
                        e.get("source_type", ""),
                        e.get("event_type", ""),
                        e.get("username", ""),
                        e.get("session_id", ""),
                        e.get("source_ip", ""),
                        e.get("pid"),
                        e.get("ppid"),
                        e.get("process", ""),
                        e.get("executable", ""),
                        e.get("file_path", ""),
                        e.get("file_hash", ""),
                        e.get("action", ""),
                        e.get("source_file", ""),
                    )
                    for e in events
                ],
            )

    def get_events(
        self,
        investigation_id: int,
        filters: Optional[Dict[str, str]] = None,
    ) -> List[Dict[str, Any]]:
        """Return events for an investigation, optionally filtered.

        Parameters
        ----------
        investigation_id : int
            Owning investigation.
        filters : dict, optional
            Supported keys: ``username``, ``source_type``, ``event_type``,
            ``session_id``.  Values are matched with SQL ``=``.
        """
        query = "SELECT * FROM events WHERE investigation_id = ?"
        params: List[Any] = [investigation_id]

        if filters:
            for key in ("username", "source_type", "event_type", "session_id"):
                if key in filters and filters[key]:
                    query += f" AND {key} = ?"
                    params.append(filters[key])

        query += " ORDER BY timestamp"

        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
            return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Correlations
    # ------------------------------------------------------------------

    def add_correlations(
        self, investigation_id: int, correlations: List[Dict[str, Any]]
    ) -> None:
        """Bulk-insert correlation results.

        Parameters
        ----------
        investigation_id : int
            Owning investigation.
        correlations : list of dict
            Each dict should contain ``event_a_id``, ``event_b_id``,
            ``total_score``, ``classification``, ``explanation``, and
            ``factors`` (a list that will be serialised to JSON).
        """
        with self._connect() as conn:
            conn.executemany(
                """
                INSERT INTO correlations
                    (investigation_id, event_a_id, event_b_id,
                     total_score, classification, explanation, factors_json)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        investigation_id,
                        c.get("event_a_id", ""),
                        c.get("event_b_id", ""),
                        c.get("total_score", 0.0),
                        c.get("classification", ""),
                        c.get("explanation_text") or c.get("explanation", ""),
                        json.dumps(c.get("factors", [])),
                    )
                    for c in correlations
                ],
            )

    def get_correlations(
        self, investigation_id: int, min_score: float = 0
    ) -> List[Dict[str, Any]]:
        """Return correlations for an investigation, optionally above a score threshold.

        Parameters
        ----------
        investigation_id : int
            Owning investigation.
        min_score : float
            Minimum ``total_score`` to include (default ``0``).

        Returns
        -------
        list of dict
            Each dict includes a ``factors`` key (deserialised from JSON).
        """
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT * FROM correlations
                WHERE investigation_id = ? AND total_score >= ?
                ORDER BY total_score DESC
                """,
                (investigation_id, min_score),
            ).fetchall()

            results: List[Dict[str, Any]] = []
            for row in rows:
                d = dict(row)
                d["factors"] = json.loads(d.pop("factors_json", "[]"))
                # Ensure both explanation and explanation_text keys exist for compatibility
                expl = d.get("explanation", "")
                d["explanation_text"] = expl
                results.append(d)
            return results

    # ------------------------------------------------------------------
    # Event groups
    # ------------------------------------------------------------------

    def add_event_groups(
        self, investigation_id: int, groups: List[List[str]]
    ) -> None:
        """Store event-group membership lists.

        Parameters
        ----------
        investigation_id : int
            Owning investigation.
        groups : list of list of str
            Each inner list contains the ``event_id`` values belonging to
            that group.
        """
        with self._connect() as conn:
            conn.executemany(
                """
                INSERT INTO event_groups (investigation_id, group_index, event_ids_json)
                VALUES (?, ?, ?)
                """,
                [
                    (investigation_id, idx, json.dumps(g))
                    for idx, g in enumerate(groups)
                ],
            )

    def get_event_groups(self, investigation_id: int) -> List[List[str]]:
        """Return ordered event groups for an investigation.

        Returns
        -------
        list of list of str
            Each inner list contains the event IDs in that group.
        """
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT event_ids_json FROM event_groups
                WHERE investigation_id = ?
                ORDER BY group_index
                """,
                (investigation_id,),
            ).fetchall()
            return [json.loads(row["event_ids_json"]) for row in rows]

    # ------------------------------------------------------------------
    # Statistics / dashboard
    # ------------------------------------------------------------------

    def get_investigation_stats(self, investigation_id: int) -> Dict[str, int]:
        """Compute summary statistics for a single investigation.

        Returns
        -------
        dict
            Keys: ``total_events``, ``total_correlations``,
            ``strong_correlations`` (score ≥ 60), ``event_groups_count``,
            ``evidence_files_count``.
        """
        with self._connect() as conn:
            total_events = conn.execute(
                "SELECT COUNT(*) AS cnt FROM events WHERE investigation_id = ?",
                (investigation_id,),
            ).fetchone()["cnt"]

            total_correlations = conn.execute(
                "SELECT COUNT(*) AS cnt FROM correlations WHERE investigation_id = ?",
                (investigation_id,),
            ).fetchone()["cnt"]

            strong_correlations = conn.execute(
                "SELECT COUNT(*) AS cnt FROM correlations "
                "WHERE investigation_id = ? AND total_score >= 60",
                (investigation_id,),
            ).fetchone()["cnt"]

            event_groups_count = conn.execute(
                "SELECT COUNT(*) AS cnt FROM event_groups WHERE investigation_id = ?",
                (investigation_id,),
            ).fetchone()["cnt"]

            evidence_files_count = conn.execute(
                "SELECT COUNT(*) AS cnt FROM evidence_files WHERE investigation_id = ?",
                (investigation_id,),
            ).fetchone()["cnt"]

        return {
            "total_events": total_events,
            "total_correlations": total_correlations,
            "strong_correlations": strong_correlations,
            "event_groups_count": event_groups_count,
            "evidence_files_count": evidence_files_count,
        }

    def get_dashboard_stats(self) -> Dict[str, int]:
        """Compute high-level dashboard statistics across all investigations.

        Returns
        -------
        dict
            Keys: ``total_investigations``, ``total_evidence_files``,
            ``total_events``, ``total_groups``, ``strong_correlations``.
        """
        with self._connect() as conn:
            total_investigations = conn.execute(
                "SELECT COUNT(*) AS cnt FROM investigations"
            ).fetchone()["cnt"]

            total_evidence_files = conn.execute(
                "SELECT COUNT(*) AS cnt FROM evidence_files"
            ).fetchone()["cnt"]

            total_events = conn.execute(
                "SELECT COUNT(*) AS cnt FROM events"
            ).fetchone()["cnt"]

            total_groups = conn.execute(
                "SELECT COUNT(*) AS cnt FROM event_groups"
            ).fetchone()["cnt"]

            strong_correlations = conn.execute(
                "SELECT COUNT(*) AS cnt FROM correlations WHERE total_score >= 60"
            ).fetchone()["cnt"]

        return {
            "total_investigations": total_investigations,
            "total_evidence_files": total_evidence_files,
            "total_events": total_events,
            "total_groups": total_groups,
            "strong_correlations": strong_correlations,
        }
