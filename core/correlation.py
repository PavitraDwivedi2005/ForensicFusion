"""
ForensicFusion — Multi-Factor Correlation Engine
=================================================

The **heart** of ForensicFusion.  Given a set of normalised events the
engine computes pairwise correlation scores across five independent
factors (temporal, user, session, process, file) and classifies each
pair as *Weak / Possible / Strong / Very Strong*.
"""

from __future__ import annotations

import itertools
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from dateutil import parser as dateutil_parser


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_ts(event: dict) -> Optional[datetime]:
    """Best-effort parse of the event's normalised (or raw) timestamp."""
    for key in ("normalized_timestamp", "timestamp"):
        raw = event.get(key)
        if raw:
            try:
                dt = dateutil_parser.parse(str(raw))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt
            except (ValueError, OverflowError):
                continue
    return None


# ---------------------------------------------------------------------------
# Correlation Engine
# ---------------------------------------------------------------------------

class CorrelationEngine:
    """Multi-factor event correlation engine.

    Parameters
    ----------
    weights:
        Dict mapping factor names to integer weights that sum to 100.
        Defaults: ``temporal=20, user=20, session=30, process=10, file=20``.
    time_window_minutes:
        Maximum gap (in minutes) for two events to receive a non-zero
        temporal score.
    min_score_threshold:
        Minimum total score (0–100) for a correlation to be reported by
        :pymeth:`correlate_all`.
    """

    # Configurable classification thresholds (upper-exclusive except last)
    CLASSIFICATION_THRESHOLDS: List[Tuple[float, str]] = [
        (30, "Weak"),
        (60, "Possible"),
        (80, "Strong"),
        (100.01, "Very Strong"),  # 100.01 so 100 is included
    ]

    def __init__(
        self,
        weights: Optional[Dict[str, int]] = None,
        time_window_minutes: int = 5,
        min_score_threshold: int = 30,
    ) -> None:
        self.weights: Dict[str, int] = weights or {
            "temporal": 20,
            "user": 20,
            "session": 30,
            "process": 10,
            "file": 20,
        }
        self.time_window_minutes: int = time_window_minutes
        self.min_score_threshold: int = min_score_threshold

    # ------------------------------------------------------------------ #
    # Factor scoring methods
    # ------------------------------------------------------------------ #

    def calculate_temporal_score(
        self, event_a: dict, event_b: dict
    ) -> Tuple[float, str]:
        """Score based on how close in time two events are.

        Returns
        -------
        tuple[float, str]
            ``(score_0_to_1, human_explanation)``
        """
        dt_a = _parse_ts(event_a)
        dt_b = _parse_ts(event_b)

        if dt_a is None or dt_b is None:
            return 0.0, "Unable to parse timestamps (temporal score: 0.0)"

        diff_seconds = abs((dt_a - dt_b).total_seconds())
        diff_minutes = diff_seconds / 60.0

        if diff_minutes > self.time_window_minutes:
            score = 0.0
        elif diff_minutes <= 1:
            score = 1.0
        elif diff_minutes <= 3:
            score = 0.8
        else:  # 3 < minutes <= window
            score = 0.5

        explanation = (
            f"Events occurred {diff_seconds:.0f} seconds apart "
            f"(temporal score: {score})"
        )
        return score, explanation

    def calculate_user_score(
        self, event_a: dict, event_b: dict
    ) -> Tuple[float, str]:
        """Score based on username match.

        Returns
        -------
        tuple[float, str]
        """
        user_a = event_a.get("username")
        user_b = event_b.get("username")

        if user_a is None or user_b is None:
            return 0.0, (
                f"Unknown user ('{user_a}' / '{user_b}') (user score: 0.0)"
            )

        if user_a == user_b:
            return 1.0, f"Same username '{user_a}' (user score: 1.0)"

        return 0.0, (
            f"Different users: '{user_a}' vs '{user_b}' (user score: 0.0)"
        )

    def calculate_session_score(
        self, event_a: dict, event_b: dict
    ) -> Tuple[float, str]:
        """Score based on session-ID match.

        Returns
        -------
        tuple[float, str]
        """
        sess_a = event_a.get("session_id")
        sess_b = event_b.get("session_id")

        if sess_a is None or sess_b is None:
            return 0.0, (
                f"Unknown session ('{sess_a}' / '{sess_b}') "
                f"(session score: 0.0)"
            )

        if sess_a == sess_b:
            return 1.0, f"Same session '{sess_a}' (session score: 1.0)"

        return 0.0, (
            f"Different sessions: '{sess_a}' vs '{sess_b}' "
            f"(session score: 0.0)"
        )

    def calculate_process_score(
        self, event_a: dict, event_b: dict
    ) -> Tuple[float, str]:
        """Score based on PID / parent-child relationship.

        Returns
        -------
        tuple[float, str]
        """
        pid_a = event_a.get("pid")
        pid_b = event_b.get("pid")
        ppid_a = event_a.get("ppid")
        ppid_b = event_b.get("ppid")

        # Same PID
        if pid_a is not None and pid_b is not None and pid_a == pid_b:
            return 1.0, (
                f"Same PID {pid_a} (process score: 1.0)"
            )

        # Parent-child: A's PID is B's PPID
        if pid_a is not None and ppid_b is not None and pid_a == ppid_b:
            return 1.0, (
                f"Parent-child: PID {pid_a} → PPID {ppid_b} "
                f"(process score: 1.0)"
            )

        # Parent-child: B's PID is A's PPID
        if pid_b is not None and ppid_a is not None and pid_b == ppid_a:
            return 1.0, (
                f"Parent-child: PID {pid_b} → PPID {ppid_a} "
                f"(process score: 1.0)"
            )

        return 0.0, "No process relationship (process score: 0.0)"

    def calculate_file_score(
        self, event_a: dict, event_b: dict
    ) -> Tuple[float, str]:
        """Score based on file-path match (case-sensitive after normalisation).

        Returns
        -------
        tuple[float, str]
        """
        path_a = event_a.get("file_path")
        path_b = event_b.get("file_path")

        if path_a is None or path_b is None:
            return 0.0, "No shared file (file score: 0.0)"

        # Normalise: strip, collapse repeated slashes
        norm_a = path_a.strip()
        norm_b = path_b.strip()

        if norm_a == norm_b:
            return 1.0, f"Same file '{norm_a}' (file score: 1.0)"

        return 0.0, (
            f"Different files: '{norm_a}' vs '{norm_b}' (file score: 0.0)"
        )

    # ------------------------------------------------------------------ #
    # Classification
    # ------------------------------------------------------------------ #

    def classify_score(self, score: float) -> str:
        """Map a 0–100 total score to a human-readable classification.

        Thresholds
        ----------
        * 0–29  → Weak
        * 30–59 → Possible
        * 60–79 → Strong
        * 80–100 → Very Strong
        """
        for threshold, label in self.CLASSIFICATION_THRESHOLDS:
            if score < threshold:
                return label
        return "Very Strong"  # safety fallback

    # ------------------------------------------------------------------ #
    # Explanation formatter
    # ------------------------------------------------------------------ #

    @staticmethod
    def format_explanation(correlation: dict) -> str:
        """Render a human-readable multi-line explanation.

        Parameters
        ----------
        correlation:
            A result dict as returned by :pymeth:`correlate_pair`.

        Returns
        -------
        str
            Formatted block such as::

                Correlation Score: 85/100 — Very Strong

                ✓ Same session 'session_42': +30
                ✓ Same username 'testuser': +20
                …
        """
        score = correlation["total_score"]
        classification = correlation["classification"]
        lines: List[str] = [
            f"Correlation Score: {score:.0f}/100 — {classification}",
            "",
        ]

        for factor in correlation["factors"]:
            w_score = factor["weighted_score"]
            explanation = factor["explanation"]
            marker = "✓" if w_score > 0 else "✗"
            # Extract the short description (before the parenthesised score)
            short_desc = explanation.split("(")[0].strip()
            lines.append(f"{marker} {short_desc}: +{w_score:.10g}")

        return "\n".join(lines)

    # ------------------------------------------------------------------ #
    # Pairwise correlation
    # ------------------------------------------------------------------ #

    def correlate_pair(self, event_a: dict, event_b: dict) -> dict:
        """Compute the full multi-factor correlation between two events.

        Returns
        -------
        dict
            Keys: ``event_a_id``, ``event_b_id``, ``total_score``,
            ``classification``, ``factors`` (list of factor dicts),
            ``explanation_text``.
        """
        factor_methods = [
            ("temporal", self.calculate_temporal_score),
            ("user", self.calculate_user_score),
            ("session", self.calculate_session_score),
            ("process", self.calculate_process_score),
            ("file", self.calculate_file_score),
        ]

        factors: List[dict] = []
        total_score: float = 0.0

        for factor_name, method in factor_methods:
            raw_score, explanation = method(event_a, event_b)
            weight = self.weights.get(factor_name, 0)
            weighted_score = raw_score * weight
            total_score += weighted_score
            factors.append(
                {
                    "factor": factor_name,
                    "raw_score": raw_score,
                    "weighted_score": weighted_score,
                    "explanation": explanation,
                }
            )

        classification = self.classify_score(total_score)

        result: dict = {
            "event_a_id": event_a.get("event_id", "unknown"),
            "event_b_id": event_b.get("event_id", "unknown"),
            "total_score": total_score,
            "classification": classification,
            "factors": factors,
            "explanation_text": "",  # filled below
        }
        result["explanation_text"] = self.format_explanation(result)
        return result

    # ------------------------------------------------------------------ #
    # Bulk correlation
    # ------------------------------------------------------------------ #

    def correlate_all(self, events: List[dict]) -> List[dict]:
        """Correlate all unique pairs and return those above threshold.

        Uses :func:`itertools.combinations` to avoid duplicate A↔B / B↔A
        comparisons.

        Parameters
        ----------
        events:
            List of standardised, normalised event dicts.

        Returns
        -------
        list[dict]
            Correlation result dicts (only those with
            ``total_score >= min_score_threshold``), sorted descending
            by score.
        """
        results: List[dict] = []
        for event_a, event_b in itertools.combinations(events, 2):
            corr = self.correlate_pair(event_a, event_b)
            if corr["total_score"] >= self.min_score_threshold:
                results.append(corr)

        # Sort strongest first
        results.sort(key=lambda c: c["total_score"], reverse=True)
        return results
