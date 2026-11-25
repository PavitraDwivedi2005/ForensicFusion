# ForensicFusion Sandbox — Benign Evidence Generation Guide

> **IMPORTANT FORENSIC INTEGRITY NOTICE**
> 
> * This sandbox environment is intended **strictly for academic research and evaluation** on isolated, non-production Linux virtual machines (e.g., Ubuntu 22.04 LTS VM in VirtualBox/VMware).
> * **NEVER** run these commands on production systems.
> * **NO MALICIOUS ACTIVITY**: The scripts and procedures execute only benign, ordinary administrative actions (SSH logins, standard user commands, creating/modifying text files).
> * The goal is solely to produce realistic multi-source forensic artifacts (Authentication, Audit, and File Activity) to evaluate event correlation accuracy.

---

## 1. Prerequisites

- Ubuntu 22.04 LTS or Debian 12 (Test VM)
- OpenSSH server: `openssh-server`
- Linux Audit daemon: `auditd`
- Python 3.8+ (for running the conversion helper)

---

## 2. One-Time VM Setup

Execute the following commands as `root` (or with `sudo`) to prepare the test user and configure `auditd`:

```bash
# 1. Create a dedicated benign test user
sudo adduser --gecos "" testuser
# Set password when prompted (e.g., "testpass123")

# 2. Install and enable auditd
sudo apt update
sudo apt install -y auditd audispd-plugins
sudo systemctl enable --now auditd

# 3. Obtain the UID of testuser
TEST_UID=$(id -u testuser)
echo "testuser UID is: $TEST_UID"

# 4. Configure audit rules for command execution and file operations
sudo auditctl -D  # Flush any existing custom rules
sudo auditctl -a always,exit -F arch=b64 -S execve -F uid=$TEST_UID -k testuser_commands
sudo auditctl -a always,exit -F arch=b64 -S open,openat,creat,truncate -F uid=$TEST_UID -k testuser_files

# 5. Verify active rules
sudo auditctl -l
```

---

## 3. Benign Evidence Generation Session

Simulate a realistic interactive user session by connecting over SSH and performing ordinary tasks:

```bash
# Connect via SSH to generate authentication logs
ssh testuser@localhost

# In testuser shell:
# 1. Create working directory
mkdir -p ~/forensic_test
cd ~/forensic_test

# 2. Create benign test document
echo "Project report draft v1" > ~/forensic_test/report.txt

# 3. Read the document
cat ~/forensic_test/report.txt

# 4. Modify the document
echo "Updated analysis notes" >> ~/forensic_test/report.txt

# 5. Create a backup copy
cp ~/forensic_test/report.txt ~/forensic_test/backup_report.txt

# 6. Check directory contents
ls -la ~/forensic_test/

# 7. End session
exit
```

---

## 4. Evidence Artifact Extraction

Extract raw logs corresponding to the session:

```bash
# 1. Extract SSH Authentication events
sudo grep -E "sshd.*testuser" /var/log/auth.log > auth_evidence.log

# 2. Extract Audit command execution records
sudo ausearch -k testuser_commands -ts recent > audit_commands.log

# 3. Extract Audit file activity records
sudo ausearch -k testuser_files -ts recent > audit_files.log
```

---

## 5. Converting Raw Logs to ForensicFusion CSV Format

Use the bundled conversion script `convert_logs.py` to transform extracted log lines into standardized CSV files suitable for ForensicFusion upload.

```bash
python convert_logs.py \
    --auth auth_evidence.log \
    --audit audit_commands.log \
    --files audit_files.log \
    --output-dir ./extracted_csv/
```

This generates:
- `auth.csv`
- `audit.csv`
- `files.csv`

Each file contains the standardized schema required by ForensicFusion with calculated event IDs.
