"""
ForensicFusion — Timestamp Normalization
========================================

Converts timestamps from heterogeneous log sources into a canonical
**ISO 8601 UTC** representation while preserving the original string.

Supported input formats
-----------------------
* ISO 8601 (with or without timezone info)
* Common syslog formats (``"Jan  5 14:03:01"``, ``"2024-01-05 14:03:01"``)
* Unix epoch seconds (integer or float, as string or number)
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import List, Tuple

from dateutil import parser as dateutil_parser


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_EPOCH_RE = re.compile(r"^\d+(\.\d+)?$")


def _is_epoch(value: str) -> bool:
    """Return ``True`` if *value* looks like a Unix epoch timestamp."""
    return bool(_EPOCH_RE.match(value.strip()))


def _epoch_to_utc(value: str) -> datetime:
    """Convert a numeric epoch string to a timezone-aware UTC datetime."""
    return datetime.fromtimestamp(float(value.strip()), tz=timezone.utc)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def normalize_timestamp(ts_string: str) -> Tuple[str, str, List[str]]:
    """Normalise a single timestamp string to ISO 8601 UTC.

    Parameters
    ----------
    ts_string:
        Raw timestamp string from a log file.

    Returns
    -------
    tuple[str, str, list[str]]
        ``(normalized_utc_iso, original_string, warnings)``

        * *normalized_utc_iso* — the UTC ISO 8601 string (e.g.
          ``"2024-01-05T14:03:01+00:00"``).  On parse failure the original
          string is returned unchanged.
        * *original_string* — the input, unchanged.
        * *warnings* — list of human-readable warning strings (empty on
          success).
    """
    original: str = str(ts_string).strip()
    warnings: List[str] = []

    if not original:
        warnings.append("Empty timestamp string — cannot normalise.")
        return original, original, warnings

    try:
        # --- Epoch handling ---
        if _is_epoch(original):
            dt = _epoch_to_utc(original)
            warnings.append(
                f"Interpreted '{original}' as a Unix epoch timestamp."
            )
            return dt.isoformat(), original, warnings

        # --- General date/time parsing via dateutil ---
        dt = dateutil_parser.parse(original)

        # If no timezone info was present, assume UTC and warn
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
            warnings.append(
                f"No timezone in '{original}' — assumed UTC."
            )

        # Convert to UTC
        dt_utc = dt.astimezone(timezone.utc)
        return dt_utc.isoformat(), original, warnings

    except (ValueError, OverflowError) as exc:
        warnings.append(
            f"Failed to parse timestamp '{original}': {exc}. "
            "Returning original value."
        )
        return original, original, warnings


def normalize_events(
    events: List[dict],
) -> Tuple[List[dict], List[str]]:
    """Normalise the ``timestamp`` field of every event in *events*.

    Each event dict gains a ``normalized_timestamp`` key containing the
    UTC ISO 8601 string.  The ``original_timestamp`` key is preserved (or
    set from the raw ``timestamp`` value if missing).

    Parameters
    ----------
    events:
        List of standardised event dictionaries (as produced by
        :mod:`core.parser`).

    Returns
    -------
    tuple[list[dict], list[str]]
        ``(events_with_normalized_ts, all_warnings)``
    """
    all_warnings: List[str] = []

    for event in events:
        raw_ts: str = event.get("timestamp", "") or ""

        # Preserve the very first original value
        if "original_timestamp" not in event or event["original_timestamp"] is None:
            event["original_timestamp"] = raw_ts

        normalized, _original, warnings = normalize_timestamp(raw_ts)
        event["normalized_timestamp"] = normalized

        # Tag warnings with event_id for traceability
        eid = event.get("event_id", "unknown")
        for w in warnings:
            all_warnings.append(f"[{eid}] {w}")

    return events, all_warnings
