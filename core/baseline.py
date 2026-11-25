"""
ForensicFusion — Baseline Correlation
======================================

Implements a *timestamp-only* baseline correlator that pairs events
falling within a configurable time window.  The baseline is intentionally
simplistic so that it can be compared against the multi-factor
:class:`~core.correlation.CorrelationEngine`.
"""

from __future__ import annotations

import itertools
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple

from dateutil import parser as dateutil_parser


def _parse_ts(event: dict) -> Optional[datetime]:
    """Best-effort timestamp parse (UTC)."""
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


def _pair_key(id_a: str, id_b: str) -> Tuple[str, str]:
    """Canonical ordered pair key to avoid A↔B duplicates."""
    return (min(id_a, id_b), max(id_a, id_b))


class BaselineCorrelation:
    """Timestamp-only baseline correlator.

    Two events are considered *correlated* if their timestamps fall
    within ``time_window_minutes`` of each other.

    Parameters
    ----------
    time_window_minutes:
        Maximum allowed gap (in minutes) for two events to be paired.
    """

    def __init__(self, time_window_minutes: int = 5) -> None:
        self.time_window_minutes: int = time_window_minutes

    # ------------------------------------------------------------------ #
    # Baseline correlation
    # ------------------------------------------------------------------ #

    def correlate_all(self, events: List[dict]) -> List[dict]:
        """Return timestamp-only correlations for all event pairs.

        Parameters
        ----------
        events:
            List of standardised event dicts.

        Returns
        -------
        list[dict]
            Each dict has keys:
            ``event_a_id``, ``event_b_id``, ``time_diff_seconds``,
            ``correlated`` (always ``True``).
        """
        results: List[dict] = []
        window_seconds = self.time_window_minutes * 60

        for event_a, event_b in itertools.combinations(events, 2):
            dt_a = _parse_ts(event_a)
            dt_b = _parse_ts(event_b)

            if dt_a is None or dt_b is None:
                continue

            diff_seconds = abs((dt_a - dt_b).total_seconds())
            if diff_seconds <= window_seconds:
                results.append(
                    {
                        "event_a_id": event_a.get("event_id", "unknown"),
                        "event_b_id": event_b.get("event_id", "unknown"),
                        "time_diff_seconds": diff_seconds,
                        "correlated": True,
                    }
                )

        return results

    # ------------------------------------------------------------------ #
    # Comparison with multi-factor engine
    # ------------------------------------------------------------------ #

    def compare_with_multifactor(
        self,
        baseline_results: List[dict],
        multifactor_results: List[dict],
        ground_truth_pairs: Optional[List[dict]] = None,
    ) -> dict:
        """Compare baseline vs multi-factor correlation results.

        Parameters
        ----------
        baseline_results:
            Output of :pymeth:`BaselineCorrelation.correlate_all`.
        multifactor_results:
            Output of :pymeth:`CorrelationEngine.correlate_all`.
        ground_truth_pairs:
            Optional list of dicts with keys ``event_a_id``,
            ``event_b_id``, and ``related`` (bool).  When provided,
            precision / recall / F1 metrics are computed for both
            methods.

        Returns
        -------
        dict
            Comparison metrics including totals, strong-correlation
            counts, and (optionally) precision / recall / F1.
        """
        # --- Baseline stats ---
        baseline_pairs: Set[Tuple[str, str]] = set()
        for r in baseline_results:
            baseline_pairs.add(_pair_key(r["event_a_id"], r["event_b_id"]))

        # --- Multi-factor stats ---
        mf_pairs: Set[Tuple[str, str]] = set()
        mf_strong_count = 0
        for r in multifactor_results:
            mf_pairs.add(_pair_key(r["event_a_id"], r["event_b_id"]))
            if r.get("total_score", 0) >= 60:
                mf_strong_count += 1

        comparison: Dict = {
            "baseline": {
                "total_correlations": len(baseline_pairs),
                "strong_correlations": len(baseline_pairs),  # all baseline correlations are "strong" (they matched)
            },
            "multifactor": {
                "total_correlations": len(mf_pairs),
                "strong_correlations": mf_strong_count,
            },
            "baseline_metrics": None,
            "multifactor_metrics": None,
        }

        # --- Ground-truth evaluation ---
        if ground_truth_pairs is not None:
            gt_positive: Set[Tuple[str, str]] = set()
            gt_negative: Set[Tuple[str, str]] = set()

            for gt in ground_truth_pairs:
                key = _pair_key(gt["event_a_id"], gt["event_b_id"])
                if gt.get("related", False):
                    gt_positive.add(key)
                else:
                    gt_negative.add(key)

            comparison["baseline_metrics"] = self._calc_metrics(
                baseline_pairs, gt_positive, gt_negative
            )
            comparison["multifactor_metrics"] = self._calc_metrics(
                mf_pairs, gt_positive, gt_negative
            )

        return comparison

    # ------------------------------------------------------------------ #

    @staticmethod
    def _calc_metrics(
        predicted_pairs: Set[Tuple[str, str]],
        gt_positive: Set[Tuple[str, str]],
        gt_negative: Set[Tuple[str, str]],
    ) -> Dict[str, float]:
        """Compute precision, recall, and F1 from pair sets.

        A *true positive* is a predicted pair that also appears in
        *gt_positive*.  A *false positive* is a predicted pair that is
        in *gt_negative* (or not in *gt_positive*).

        Parameters
        ----------
        predicted_pairs:
            Set of pair keys the method labelled as correlated.
        gt_positive:
            Set of pair keys the ground truth says are related.
        gt_negative:
            Set of pair keys the ground truth says are unrelated.

        Returns
        -------
        dict
            ``{ precision, recall, f1 }`` — each a float in [0, 1].
        """
        tp = len(predicted_pairs & gt_positive)
        fp = len(predicted_pairs - gt_positive)
        fn = len(gt_positive - predicted_pairs)

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (
            2 * precision * recall / (precision + recall)
            if (precision + recall) > 0
            else 0.0
        )

        return {"precision": precision, "recall": recall, "f1": f1}
