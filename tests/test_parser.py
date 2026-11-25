"""
Unit tests for ForensicFusion multi-source evidence parsers.
"""

import os
import sys
import tempfile
import unittest

# Ensure project root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.parser import (
    AuthenticationParser,
    AuditParser,
    FileActivityParser,
    ParserFactory,
    STANDARD_FIELDS,
)


class TestParsers(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.temp_dir.cleanup()

    def _write_csv(self, filename: str, content: str) -> str:
        path = os.path.join(self.temp_dir.name, filename)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        return path

    def test_authentication_parser(self):
        csv_content = (
            "event_id,timestamp,username,source_ip,auth_result,ssh_session,event_type\n"
            "AUTH-001,2026-11-25T10:01:04Z,testuser,192.168.56.10,login_success,42,ssh_login\n"
        )
        path = self._write_csv("auth.csv", csv_content)
        parser = AuthenticationParser()
        events = parser.parse(path)

        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event["event_id"], "AUTH-001")
        self.assertEqual(event["username"], "testuser")
        self.assertEqual(event["source_type"], "authentication")
        self.assertEqual(event["session_id"], "42")
        self.assertEqual(event["action"], "login_success")
        self.assertEqual(event["source_ip"], "192.168.56.10")
        self.assertEqual(event["source_file"], "auth.csv")
        for field in STANDARD_FIELDS:
            self.assertIn(field, event)

    def test_audit_parser(self):
        csv_content = (
            "event_id,timestamp,username,uid,audit_session,pid,ppid,command,executable,event_type\n"
            "AUDIT-001,2026-11-25T10:01:47Z,testuser,1001,42,1234,1000,sudo su,/usr/bin/sudo,execve\n"
        )
        path = self._write_csv("audit.csv", csv_content)
        parser = AuditParser()
        events = parser.parse(path)

        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event["event_id"], "AUDIT-001")
        self.assertEqual(event["source_type"], "audit")
        self.assertEqual(event["session_id"], "42")
        self.assertEqual(event["pid"], 1234)
        self.assertEqual(event["ppid"], 1000)
        self.assertEqual(event["process"], "sudo su")
        self.assertEqual(event["executable"], "/usr/bin/sudo")

    def test_file_activity_parser(self):
        csv_content = (
            "event_id,timestamp,username,session_id,pid,file_path,action,file_hash\n"
            "FILE-001,2026-11-25T10:02:18Z,testuser,42,1235,/home/testuser/confidential.txt,open,e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n"
        )
        path = self._write_csv("files.csv", csv_content)
        parser = FileActivityParser()
        events = parser.parse(path)

        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event["event_id"], "FILE-001")
        self.assertEqual(event["source_type"], "file_activity")
        self.assertEqual(event["file_path"], "/home/testuser/confidential.txt")
        self.assertEqual(event["action"], "open")
        self.assertEqual(event["file_hash"], "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

    def test_parser_factory(self):
        auth_parser = ParserFactory.get_parser("authentication")
        self.assertIsInstance(auth_parser, AuthenticationParser)

        audit_parser = ParserFactory.get_parser("audit")
        self.assertIsInstance(audit_parser, AuditParser)

        file_parser = ParserFactory.get_parser("file_activity")
        self.assertIsInstance(file_parser, FileActivityParser)

        with self.assertRaises(ValueError):
            ParserFactory.get_parser("unknown_type")

    def test_missing_columns(self):
        csv_content = (
            "event_id,timestamp,username\n"
            "AUTH-099,2026-11-25T10:05:00Z,minimal_user\n"
        )
        path = self._write_csv("minimal.csv", csv_content)
        parser = AuthenticationParser()
        events = parser.parse(path)

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event_id"], "AUTH-099")
        self.assertEqual(events[0]["username"], "minimal_user")
        self.assertIsNone(events[0]["source_ip"])
        self.assertIsNone(events[0]["session_id"])

    def test_empty_csv(self):
        csv_content = "event_id,timestamp,username,source_ip,auth_result,ssh_session,event_type\n"
        path = self._write_csv("empty.csv", csv_content)
        parser = AuthenticationParser()
        events = parser.parse(path)
        self.assertEqual(events, [])


if __name__ == "__main__":
    unittest.main()
