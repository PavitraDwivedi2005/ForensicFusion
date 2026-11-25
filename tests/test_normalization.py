"""
Unit tests for ForensicFusion timestamp normalization.
"""

import os
import sys
import unittest

# Ensure project root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.normalizer import normalize_timestamp, normalize_events


class TestNormalization(unittest.TestCase):
    def test_iso8601_utc(self):
        ts = "2026-11-25T10:00:00Z"
        norm, orig, warnings = normalize_timestamp(ts)
        self.assertEqual(orig, ts)
        self.assertTrue(norm.startswith("2026-11-25T10:00:00"))
        self.assertTrue(norm.endswith("+00:00") or norm.endswith("Z"))

    def test_iso8601_offset(self):
        # 10:00:00 +05:30 is 04:30:00 UTC
        ts = "2026-11-25T10:00:00+05:30"
        norm, orig, warnings = normalize_timestamp(ts)
        self.assertEqual(orig, ts)
        self.assertTrue("04:30:00" in norm)
        self.assertTrue(norm.endswith("+00:00") or norm.endswith("Z"))

    def test_epoch_timestamp(self):
        # 1700000000 is 2023-11-14T22:13:20+00:00
        ts = "1700000000"
        norm, orig, warnings = normalize_timestamp(ts)
        self.assertEqual(orig, ts)
        self.assertIn("2023-11-14", norm)
        self.assertTrue(any("epoch" in w.lower() for w in warnings))

    def test_invalid_timestamp(self):
        ts = "this-is-not-a-timestamp"
        norm, orig, warnings = normalize_timestamp(ts)
        self.assertEqual(orig, ts)
        self.assertEqual(norm, ts)
        self.assertTrue(len(warnings) > 0)
        self.assertIn("Failed to parse", warnings[0])

    def test_empty_timestamp(self):
        norm, orig, warnings = normalize_timestamp("")
        self.assertEqual(orig, "")
        self.assertEqual(norm, "")
        self.assertTrue(len(warnings) > 0)

    def test_normalize_events(self):
        events = [
            {"event_id": "EVT-1", "timestamp": "2026-11-25T10:00:00Z"},
            {"event_id": "EVT-2", "timestamp": "invalid-time"}
        ]
        norm_events, warnings = normalize_events(events)
        self.assertEqual(len(norm_events), 2)
        self.assertIn("normalized_timestamp", norm_events[0])
        self.assertIn("original_timestamp", norm_events[0])
        self.assertEqual(norm_events[0]["original_timestamp"], "2026-11-25T10:00:00Z")
        self.assertTrue(len(warnings) > 0)
        self.assertTrue(any("EVT-2" in w for w in warnings))


if __name__ == "__main__":
    unittest.main()
