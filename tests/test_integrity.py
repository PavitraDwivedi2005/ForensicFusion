"""
Unit tests for ForensicFusion evidence integrity and hashing.
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.integrity import calculate_sha256, create_evidence_record, _human_readable_size


class TestIntegrity(unittest.TestCase):
    def test_calculate_sha256_bytes(self):
        # Empty string sha256 is e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        digest = calculate_sha256(b"")
        self.assertEqual(digest, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

        digest2 = calculate_sha256(b"hello world")
        self.assertEqual(digest2, "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9")

    def test_calculate_sha256_file(self):
        with tempfile.NamedTemporaryFile("wb", delete=False) as f:
            f.write(b"forensic evidence sample")
            f_path = f.name
        try:
            digest = calculate_sha256(f_path)
            self.assertEqual(len(digest), 64)
        finally:
            os.remove(f_path)

    def test_calculate_sha256_invalid_type(self):
        with self.assertRaises(TypeError):
            calculate_sha256(12345)  # type: ignore

    def test_calculate_sha256_file_not_found(self):
        with self.assertRaises(FileNotFoundError):
            calculate_sha256("non_existent_file_xyz.log")

    def test_create_evidence_record(self):
        rec = create_evidence_record("auth.csv", b"dummy log data", "2026-11-25T10:00:00Z")
        self.assertEqual(rec["filename"], "auth.csv")
        self.assertEqual(rec["file_size"], len(b"dummy log data"))
        self.assertEqual(len(rec["sha256"]), 64)
        self.assertEqual(rec["upload_time"], "2026-11-25T10:00:00Z")
        self.assertIn("B", rec["file_size_human"])

    def test_human_readable_size(self):
        self.assertEqual(_human_readable_size(0), "0 B")
        self.assertEqual(_human_readable_size(1024), "1.0 KB")
        self.assertEqual(_human_readable_size(1048576), "1.0 MB")


if __name__ == "__main__":
    unittest.main()
