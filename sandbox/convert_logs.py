#!/usr/bin/env python3
"""
ForensicFusion Sandbox — Raw Log to CSV Converter
=================================================

Converts raw Linux auth.log and ausearch outputs into ForensicFusion-compatible
standardised CSV files (auth.csv, audit.csv, files.csv).
"""

import argparse
import csv
import os
import re
from datetime import datetime, timezone


def parse_auth_log(log_path: str, output_csv: str) -> int:
    """Extract SSH login and session events from auth.log."""
    events = []
    current_year = datetime.now(timezone.utc).year
    count = 1

    if not os.path.exists(log_path):
        return 0

    with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if "sshd" not in line:
                continue

            # e.g., "Nov 25 10:01:04 ubuntu sshd[1234]: Accepted password for testuser from 192.168.56.10 port 54321"
            parts = line.strip().split()
            if len(parts) < 5:
                continue

            try:
                date_str = f"{current_year} {parts[0]} {parts[1]} {parts[2]}"
                dt = datetime.strptime(date_str, "%Y %b %d %H:%M:%S").replace(tzinfo=timezone.utc)
                ts = dt.isoformat()
            except Exception:
                ts = datetime.now(timezone.utc).isoformat()

            user_match = re.search(r"for (\w+) from", line)
            user = user_match.group(1) if user_match else "unknown"

            ip_match = re.search(r"from ([\d\.]+) port", line)
            src_ip = ip_match.group(1) if ip_match else "127.0.0.1"

            if "Accepted" in line:
                action = "login_success"
                etype = "ssh_login"
            elif "Failed" in line:
                action = "login_failure"
                etype = "ssh_login"
            elif "session opened" in line:
                action = "session_open"
                etype = "session_start"
            elif "session closed" in line:
                action = "session_close"
                etype = "session_end"
            else:
                action = "auth_event"
                etype = "auth_other"

            events.append({
                "event_id": f"AUTH-{count:03d}",
                "timestamp": ts,
                "username": user,
                "source_ip": src_ip,
                "auth_result": action,
                "ssh_session": "1",
                "event_type": etype
            })
            count += 1

    if events:
        with open(output_csv, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=[
                "event_id", "timestamp", "username", "source_ip", "auth_result", "ssh_session", "event_type"
            ])
            writer.writeheader()
            writer.writerows(events)

    return len(events)


def parse_audit_commands(log_path: str, output_csv: str) -> int:
    """Extract command execution events from ausearch log."""
    events = []
    count = 1

    if not os.path.exists(log_path):
        return 0

    with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if "type=EXECVE" not in line and "type=SYSCALL" not in line:
                continue

            # Extract timestamp from msg=audit(1700900000.123:45)
            epoch_match = re.search(r"msg=audit\((\d+)\.\d+:(\d+)\)", line)
            if epoch_match:
                epoch = int(epoch_match.group(1))
                ts = datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()
            else:
                ts = datetime.now(timezone.utc).isoformat()

            user_match = re.search(r"auid=(\d+)|uid=(\d+)", line)
            user = user_match.group(1) or user_match.group(2) if user_match else "testuser"

            pid_match = re.search(r"\bpid=(\d+)", line)
            pid = pid_match.group(1) if pid_match else "1000"

            ppid_match = re.search(r"\bppid=(\d+)", line)
            ppid = ppid_match.group(1) if ppid_match else "999"

            ses_match = re.search(r"\bses=(\d+)", line)
            ses = ses_match.group(1) if ses_match else "1"

            exe_match = re.search(r'exe="([^"]+)"', line)
            exe = exe_match.group(1) if exe_match else "/bin/bash"

            comm_match = re.search(r'comm="([^"]+)"', line)
            comm = comm_match.group(1) if comm_match else os.path.basename(exe)

            events.append({
                "event_id": f"AUDIT-{count:03d}",
                "timestamp": ts,
                "username": user if not user.isdigit() else "testuser",
                "uid": user if user.isdigit() else "1001",
                "audit_session": ses,
                "pid": pid,
                "ppid": ppid,
                "command": comm,
                "executable": exe,
                "event_type": "execve"
            })
            count += 1

    if events:
        with open(output_csv, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=[
                "event_id", "timestamp", "username", "uid", "audit_session", "pid", "ppid", "command", "executable", "event_type"
            ])
            writer.writeheader()
            writer.writerows(events)

    return len(events)


def parse_audit_files(log_path: str, output_csv: str) -> int:
    """Extract file activity events from ausearch log."""
    events = []
    count = 1

    if not os.path.exists(log_path):
        return 0

    with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if "type=PATH" not in line and "type=SYSCALL" not in line:
                continue

            epoch_match = re.search(r"msg=audit\((\d+)\.\d+:(\d+)\)", line)
            if epoch_match:
                epoch = int(epoch_match.group(1))
                ts = datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()
            else:
                ts = datetime.now(timezone.utc).isoformat()

            name_match = re.search(r'name="([^"]+)"', line)
            file_path = name_match.group(1) if name_match else "/home/testuser/report.txt"

            pid_match = re.search(r"\bpid=(\d+)", line)
            pid = pid_match.group(1) if pid_match else "1000"

            ses_match = re.search(r"\bses=(\d+)", line)
            ses = ses_match.group(1) if ses_match else "1"

            events.append({
                "event_id": f"FILE-{count:03d}",
                "timestamp": ts,
                "username": "testuser",
                "session_id": ses,
                "pid": pid,
                "file_path": file_path,
                "action": "access",
                "file_hash": ""
            })
            count += 1

    if events:
        with open(output_csv, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=[
                "event_id", "timestamp", "username", "session_id", "pid", "file_path", "action", "file_hash"
            ])
            writer.writeheader()
            writer.writerows(events)

    return len(events)


def main():
    parser = argparse.ArgumentParser(description="Convert Linux raw logs to ForensicFusion CSV format")
    parser.add_argument("--auth", help="Path to auth.log extract")
    parser.add_argument("--audit", help="Path to audit command extract")
    parser.add_argument("--files", help="Path to audit file extract")
    parser.add_argument("--output-dir", default="./output_csv", help="Output directory")

    args = parser.parse_args()
    os.makedirs(args.output_dir, exist_ok=True)

    if args.auth:
        n = parse_auth_log(args.auth, os.path.join(args.output_dir, "auth.csv"))
        print(f"Generated auth.csv: {n} events")

    if args.audit:
        n = parse_audit_commands(args.audit, os.path.join(args.output_dir, "audit.csv"))
        print(f"Generated audit.csv: {n} events")

    if args.files:
        n = parse_audit_files(args.files, os.path.join(args.output_dir, "files.csv"))
        print(f"Generated files.csv: {n} events")


if __name__ == "__main__":
    main()
