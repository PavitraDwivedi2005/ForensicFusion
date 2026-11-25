"""
Unit tests for ForensicFusion multi-factor correlation engine.
"""

import os
import sys
import unittest

# Ensure project root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.correlation import CorrelationEngine


class TestCorrelationEngine(unittest.TestCase):
    def setUp(self):
        self.engine = CorrelationEngine()

    def test_temporal_score_close(self):
        # 30 seconds apart -> 1.0
        evt_a = {"timestamp": "2026-11-25T10:00:00Z"}
        evt_b = {"timestamp": "2026-11-25T10:00:30Z"}
        score, expl = self.engine.calculate_temporal_score(evt_a, evt_b)
        self.assertEqual(score, 1.0)
        self.assertIn("30 seconds apart", expl)

    def test_temporal_score_medium(self):
        # 2 minutes apart -> 0.8
        evt_a = {"timestamp": "2026-11-25T10:00:00Z"}
        evt_b = {"timestamp": "2026-11-25T10:02:00Z"}
        score, expl = self.engine.calculate_temporal_score(evt_a, evt_b)
        self.assertEqual(score, 0.8)
        self.assertIn("120 seconds apart", expl)

    def test_temporal_score_far(self):
        # 4 minutes apart -> 0.5
        evt_a = {"timestamp": "2026-11-25T10:00:00Z"}
        evt_b = {"timestamp": "2026-11-25T10:04:00Z"}
        score, expl = self.engine.calculate_temporal_score(evt_a, evt_b)
        self.assertEqual(score, 0.5)

    def test_temporal_score_beyond(self):
        # 10 minutes apart (default window is 5m) -> 0.0
        evt_a = {"timestamp": "2026-11-25T10:00:00Z"}
        evt_b = {"timestamp": "2026-11-25T10:10:00Z"}
        score, expl = self.engine.calculate_temporal_score(evt_a, evt_b)
        self.assertEqual(score, 0.0)

    def test_user_score_same(self):
        evt_a = {"username": "alice"}
        evt_b = {"username": "alice"}
        score, expl = self.engine.calculate_user_score(evt_a, evt_b)
        self.assertEqual(score, 1.0)
        self.assertIn("Same username 'alice'", expl)

    def test_user_score_different(self):
        evt_a = {"username": "alice"}
        evt_b = {"username": "bob"}
        score, expl = self.engine.calculate_user_score(evt_a, evt_b)
        self.assertEqual(score, 0.0)
        self.assertIn("Different users", expl)

    def test_user_score_unknown(self):
        evt_a = {"username": "alice"}
        evt_b = {"username": None}
        score, _ = self.engine.calculate_user_score(evt_a, evt_b)
        self.assertEqual(score, 0.0)

    def test_session_score_same(self):
        evt_a = {"session_id": "42"}
        evt_b = {"session_id": "42"}
        score, expl = self.engine.calculate_session_score(evt_a, evt_b)
        self.assertEqual(score, 1.0)
        self.assertIn("Same session '42'", expl)

    def test_session_score_different(self):
        evt_a = {"session_id": "42"}
        evt_b = {"session_id": "100"}
        score, _ = self.engine.calculate_session_score(evt_a, evt_b)
        self.assertEqual(score, 0.0)

    def test_process_score_same_pid(self):
        evt_a = {"pid": 1234, "ppid": 1000}
        evt_b = {"pid": 1234, "ppid": 1000}
        score, expl = self.engine.calculate_process_score(evt_a, evt_b)
        self.assertEqual(score, 1.0)
        self.assertIn("Same PID 1234", expl)

    def test_process_score_parent_child(self):
        evt_a = {"pid": 1000, "ppid": 1}
        evt_b = {"pid": 1234, "ppid": 1000}
        score, expl = self.engine.calculate_process_score(evt_a, evt_b)
        self.assertEqual(score, 1.0)
        self.assertIn("Parent-child", expl)

    def test_file_score_same(self):
        evt_a = {"file_path": "/var/log/auth.log"}
        evt_b = {"file_path": "/var/log/auth.log"}
        score, expl = self.engine.calculate_file_score(evt_a, evt_b)
        self.assertEqual(score, 1.0)
        self.assertIn("Same file", expl)

    def test_file_score_different(self):
        evt_a = {"file_path": "/var/log/auth.log"}
        evt_b = {"file_path": "/etc/passwd"}
        score, _ = self.engine.calculate_file_score(evt_a, evt_b)
        self.assertEqual(score, 0.0)

    def test_classify_score(self):
        self.assertEqual(self.engine.classify_score(15), "Weak")
        self.assertEqual(self.engine.classify_score(29), "Weak")
        self.assertEqual(self.engine.classify_score(30), "Possible")
        self.assertEqual(self.engine.classify_score(59), "Possible")
        self.assertEqual(self.engine.classify_score(60), "Strong")
        self.assertEqual(self.engine.classify_score(79), "Strong")
        self.assertEqual(self.engine.classify_score(80), "Very Strong")
        self.assertEqual(self.engine.classify_score(100), "Very Strong")

    def test_full_correlation_strong(self):
        evt_a = {
            "event_id": "EVT-1",
            "timestamp": "2026-11-25T10:00:00Z",
            "username": "testuser",
            "session_id": "42",
            "pid": 100,
            "ppid": 50,
            "file_path": "/home/testuser/secret.txt"
        }
        evt_b = {
            "event_id": "EVT-2",
            "timestamp": "2026-11-25T10:00:30Z",
            "username": "testuser",
            "session_id": "42",
            "pid": 100,
            "ppid": 50,
            "file_path": "/home/testuser/secret.txt"
        }
        res = self.engine.correlate_pair(evt_a, evt_b)
        self.assertEqual(res["total_score"], 100.0)
        self.assertEqual(res["classification"], "Very Strong")
        self.assertIn("✓", res["explanation_text"])

    def test_full_correlation_weak(self):
        evt_a = {
            "event_id": "EVT-1",
            "timestamp": "2026-11-25T10:00:00Z",
            "username": "alice",
            "session_id": "1",
            "pid": 100,
            "file_path": "/a.txt"
        }
        evt_b = {
            "event_id": "EVT-2",
            "timestamp": "2026-11-25T10:20:00Z",
            "username": "bob",
            "session_id": "2",
            "pid": 200,
            "file_path": "/b.txt"
        }
        res = self.engine.correlate_pair(evt_a, evt_b)
        self.assertEqual(res["total_score"], 0.0)
        self.assertEqual(res["classification"], "Weak")
        self.assertIn("✗", res["explanation_text"])

    def test_correlate_all(self):
        events = [
            {
                "event_id": f"EVT-{i}",
                "timestamp": "2026-11-25T10:00:00Z",
                "username": "shareduser" if i < 3 else "otheruser",
                "session_id": "10" if i < 3 else "20",
                "pid": 1000 + i,
                "ppid": 999,
                "file_path": None
            }
            for i in range(4)
        ]
        # EVT-0, EVT-1, EVT-2 share user (20), session (30), time (20) = 70 score (Strong)
        corrs = self.engine.correlate_all(events)
        self.assertTrue(len(corrs) > 0)
        top = corrs[0]
        self.assertGreaterEqual(top["total_score"], 30)


if __name__ == "__main__":
    unittest.main()
