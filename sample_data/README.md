# ForensicFusion — Synthetic Test Data

> **⚠ SYNTHETIC DATA** — All events, timestamps, users, IP addresses, and file
> hashes in this directory are entirely fictitious and were generated for
> automated testing of the ForensicFusion cross-log correlation engine. Do not
> use this data as reference material for real forensic investigations.

Base date for all events: **2026-11-25** (ISO 8601 UTC timestamps).

---

## Scenario 1 — Single User Coherent Session (`scenario_1/`)

A single user **testuser** performs a coherent privileged session from
`192.168.56.10` (SSH session 42):

1. SSH login  
2. `sudo su` (escalate to root)  
3. `cat /etc/passwd`  
4. `cd /home/testuser/documents`  
5. `cat confidential.txt`  
6. `nano confidential.txt` (read then modify)  
7. `cp confidential.txt /tmp/backup.txt`  
8. Logout  

**Expected correlation result:** ALL events across auth, audit, and file logs
belong to the **same activity cluster**. A correct correlator should link every
event to every other event via shared session ID (42), parent-child PIDs, and
overlapping timestamps.

| File       | Events | ID Range              |
|------------|--------|-----------------------|
| auth.csv   | 6      | S1-AUTH-001 … 006     |
| audit.csv  | 9      | S1-AUDIT-001 … 009    |
| files.csv  | 5      | S1-FILE-001 … 005     |

---

## Scenario 2 — Two Independent Users, Overlapping Timestamps (`scenario_2/`)

Two users (**alice** from `10.0.0.5`, session 101 and **bob** from `10.0.0.8`,
session 102) perform completely independent activities within 2–3 minutes of
each other. Timestamps deliberately overlap so that naïve time-window
correlation would incorrectly merge them.

**alice** (session 101): login → read `report.pdf` → `grep` on syslog → logout  
**bob** (session 102): login → edit `notes.txt` → run `python3 analysis.py` → logout  

**Expected correlation result:** Alice's events form one cluster; Bob's events
form another. Cross-user pairs should **not** be correlated. The distinguishing
signals are session ID, source IP, UID, and PID lineage—not timestamps.

| File       | Events | ID Range              |
|------------|--------|-----------------------|
| auth.csv   | 6      | S2-AUTH-001 … 006     |
| audit.csv  | 8      | S2-AUDIT-001 … 008   |
| files.csv  | 5      | S2-FILE-001 … 005     |

---

## Scenario 3 — Same User, Two Distinct Sessions (`scenario_3/`)

The same user **testuser** has two temporally separated SSH sessions from
different IPs:

- **Session A** (session 201, from `172.16.0.5`, 10:00–10:05): login → read
  `/etc/app/config.yml` → logout  
- **Session B** (session 202, from `192.168.1.20`, 10:30–10:35): login → edit
  `/etc/sysctl.conf` → logout  

**Expected correlation result:** Session A events cluster together; Session B
events cluster together. Cross-session pairs should **not** be correlated, even
though the username is the same. The distinguishing signals are session ID,
source IP, and PID lineage.

| File       | Events | ID Range              |
|------------|--------|-----------------------|
| auth.csv   | 6      | S3-AUTH-001 … 006     |
| audit.csv  | 6      | S3-AUDIT-001 … 006   |
| files.csv  | 3      | S3-FILE-001 … 003     |

---

## Ground Truth (`ground_truth.csv`)

Contains 44 labelled event-ID pairs used for precision / recall evaluation.

| Column      | Description                                                      |
|-------------|------------------------------------------------------------------|
| event_id_1  | First event in the pair (e.g., `S1-AUTH-001`)                    |
| event_id_2  | Second event in the pair (e.g., `S1-AUDIT-001`)                 |
| related     | `true` if the events belong to the same activity; `false` otherwise |
| scenario    | Scenario number (1, 2, or 3)                                    |

**Pair breakdown:**

| Scenario | Related (true) | Unrelated (false) | Total |
|----------|---------------|-------------------|-------|
| 1        | 12            | 0                 | 12    |
| 2        | 11            | 6                 | 17    |
| 3        | 9             | 5                 | 14    |
| **All**  | **32**        | **11**            | **43**|

---

## CSV Column Reference

### auth.csv
`event_id, timestamp, username, source_ip, auth_result, ssh_session, event_type`

### audit.csv
`event_id, timestamp, username, uid, audit_session, pid, ppid, command, executable, event_type`

### files.csv
`event_id, timestamp, username, session_id, pid, file_path, action, file_hash`

The `ssh_session` (auth), `audit_session` (audit), and `session_id` (files)
columns all refer to the same logical session identifier and are the primary
join key across log types.
