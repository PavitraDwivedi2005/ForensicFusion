"""
Unit tests for ForensicFusion baseline (timestamp-only) correlation.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.baseline import BaselineCorrelation


class TestBaseline(unittest.TestCase):
    def setUp(self):
        self.baseline = BaselineCorrelation(time_window_minutes=5)

    def test_correlate_within_window(self):
        events = [
            {"event_id": "EVT-1", "timestamp": "2026-11-25T10:00:00Z"},
            {"event_id": "EVT-2", "timestamp": "2026-11-25T10:03:00Z"},
        ]
        results = self.baseline.correlate_all(events)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["event_a_id"], "EVT-1")
        self.assertEqual(results[0]["event_b_id"], "EVT-2")
        self.assertEqual(results[0]["time_diff_seconds"], 180.0)
        self.assertTrue(results[0]["correlated"])

    def test_outside_window(self):
        events = [
            {"event_id": "EVT-1", "timestamp": "2026-11-25T10:00:00Z"},
            {"event_id": "EVT-2", "timestamp": "2026-11-25T10:10:00Z"},
        ]
        results = self.baseline.correlate_all(events)
        self.assertEqual(len(results), 0)

    def test_compare_with_multifactor(self):
        base_res = [{"event_a_id": "A", "event_b_id": "B"}]
        mf_res = [{"event_a_id": "A", "event_b_id": "B", "total_score": 85.0}]
        gt = [{"event_a_id": "A", "event_b_id": "B", "related": True}]

        comp = self.baseline.compare_with_multifactor(base_res, mf_res, gt)
        self.assertEqual(comp["baseline"]["total_correlations"], 1)
        self.assertEqual(comp["multifactor"]["total_correlations"], 1)
        self.assertEqual(comp["baseline_metrics"]["precision"], 1.0)
        self.assertEqual(comp["multifactor_metrics"]["f1"], 1.0)


if __name__ == "__main__":
    unittest.main()
