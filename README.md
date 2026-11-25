# ForensicFusion — Explainable Multi-Log Event Correlation for Linux Forensics

> **Academic Research Focus:**  
> *Can multi-factor forensic event correlation reconstruct related activity sequences more accurately and explainably than timestamp-only correlation?*

ForensicFusion is a lightweight, web-based digital forensics investigation platform designed for university-level research. It ingests Linux forensic logs from heterogeneous sources (**Authentication**, **Audit/System**, and **File Activity**), computes explainable multi-factor correlation scores, clusters related events using graph theory (NetworkX), and reconstructs chronological incident sequences without relying on complex machine learning or proprietary SIEM platforms.

---

## 1. Key Features

- **Multi-Source Evidence Ingestion**: Extensible parser architecture supporting Linux Authentication (`auth.log`), Audit daemon (`auditd`), and File Activity logs formatted as CSV.
- **Evidence Integrity Verification**: Immediate SHA-256 cryptographic hashing of uploaded evidence preserving chain of custody and guaranteeing original evidence files are never modified.
- **Timestamp Normalization**: Automatic canonical conversion to ISO 8601 UTC with preservation of raw input timestamps and robust error handling.
- **Explainable Multi-Factor Scoring Engine**: Pairwise event correlation evaluated across 5 distinct dimensions:
  - **Temporal Proximity ($T$)** — Non-linear decay score based on delta time.
  - **User Identity ($U$)** — Exact username and UID matching.
  - **Session Continuity ($S$)** — Linux audit/SSH session identifier matching.
  - **Process Hierarchy ($P$)** — PID equality and parent/child (`PPID -> PID`) linkage.
  - **Resource / File Relationship ($F$)** — Normalized absolute file path alignment.
- **Transparent Factor Breakdown**: Every single score displays an itemized human-readable audit trail (e.g., `✓ Same session: +30`, `✗ No shared file: +0`).
- **Graph-Based Incident Reconstruction**: Leverages NetworkX connected components to identify clusters of related events and reconstruct chronological activity narratives.
- **Baseline Comparison (Research Evaluation)**: Quantitative comparison against naive timestamp-only window correlation, evaluating Precision, Recall, and F1-score against ground-truth benchmarks.
- **Audit-Ready Reporting**: One-click generation of standalone HTML forensic investigation reports with embedded CSS, hash tables, and forensic limitation disclaimers.

---

## 2. Mathematical Correlation Model

For any pair of forensic events $e_a$ and $e_b$, the aggregate correlation score $C \in [0, 100]$ is computed as:

$$C = W_t \cdot T(e_a, e_b) + W_u \cdot U(e_a, e_b) + W_s \cdot S(e_a, e_b) + W_p \cdot P(e_a, e_b) + W_f \cdot F(e_a, e_b)$$

### Default Factor Weights:
| Factor | Parameter | Default Weight | Scoring Criteria |
|---|---|---|---|
| **Temporal Proximity** | $W_t$ | 20 | $\Delta t \le 1\text{m}: 1.0$, $\le 3\text{m}: 0.8$, $\le 5\text{m}: 0.5$, $>5\text{m}: 0.0$ |
| **User Identity** | $W_u$ | 20 | Identical username / UID: $1.0$; Mismatch or unknown: $0.0$ |
| **Session Continuity** | $W_s$ | 30 | Identical session ID: $1.0$; Mismatch or unknown: $0.0$ |
| **Process Relationship** | $W_p$ | 10 | Same PID or parent/child (`PPID == PID`): $1.0$; Otherwise: $0.0$ |
| **Resource / File Path** | $W_f$ | 20 | Normalized file path match: $1.0$; Otherwise: $0.0$ |

*Note: All weights and window thresholds are configurable within the web UI.*

### Classification Tiers:
- **0 – 29**: Weak
- **30 – 59**: Possible
- **60 – 79**: Strong
- **80 – 100**: Very Strong

---

## 3. Forensic Principles: Fact vs. Inference

ForensicFusion enforces strict evidentiary discipline by differentiating:
1. **Observed Fact**: Directly recorded evidence attributes (e.g., *"File `/etc/passwd` was opened at 10:01:47 UTC by UID 1001 with PID 1234"*).
2. **Inference**: Algorithmic probability of association (e.g., *"Event AUDIT-003 and FILE-001 exhibit a correlation score of 85/100, suggesting related activity within session 42"*).

---

## 4. Project Structure

```text
ForensicFusion/
│
├── app.py                      # Multi-page Streamlit web application
├── requirements.txt            # Minimal Python dependencies
├── README.md                   # Complete system documentation
├── forensicfusion.db           # SQLite persistent storage
│
├── core/                       # Core correlation and processing engine
│   ├── parser.py               # Extensible CSV parser for Auth, Audit, File logs
│   ├── normalizer.py           # Timestamp parser & UTC ISO 8601 normalizer
│   ├── integrity.py            # SHA-256 evidence hashing & chain of custody
│   ├── correlation.py          # Multi-factor correlation engine & explainability
│   ├── baseline.py             # Timestamp-only baseline correlator & metrics
│   └── graph_engine.py         # NetworkX graph clustering & Plotly visualizer
│
├── database/                   # Data layer
│   └── db.py                   # SQLite database wrapper with context managers
│
├── reports/                    # Reporting engine
│   └── generator.py            # Standalone HTML forensic report builder
│
├── sample_data/                # Synthetic academic test benchmarks
│   ├── README.md               # Scenario documentation
│   ├── ground_truth.csv        # Ground truth pairs for precision/recall evaluation
│   ├── scenario_1/             # Coherent single-user session
│   ├── scenario_2/             # Unrelated overlapping concurrent users
│   └── scenario_3/             # Multiple sessions from same user
│
├── sandbox/                    # Safe VM evidence generation
│   ├── README.md               # Instructions for Ubuntu VM auditd generation
│   └── convert_logs.py         # Raw log-to-CSV transformation script
│
└── tests/                      # Unit test suite (38 tests)
    ├── test_parser.py
    ├── test_normalization.py
    ├── test_correlation.py
    ├── test_baseline.py
    └── test_integrity.py
```

---

## 5. Technology Stack & Dependencies

- **Python**: 3.8+
- **Streamlit**: Web interface and interactive forensic dashboard
- **Pandas**: Tabular log processing and timeline filtering
- **Plotly**: Dynamic timeline charts and interactive NetworkX graph rendering
- **NetworkX**: Graph representation and connected-component clustering
- **SQLite**: Local relational persistence for cases, evidence, and results
- **hashlib**: Cryptographic SHA-256 chain of custody verification

---

## 6. Installation & Execution

### 1. Clone & Set Up Virtual Environment

```bash
cd d:/ForensicFusion

# Create virtual environment (optional)
python -m venv venv
venv\Scripts\activate      # On Windows
# source venv/bin/activate  # On Linux/macOS
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Run the Web Application

```bash
streamlit run app.py
```

Open your browser at `http://localhost:8501`.

---

## 7. Running the Unit Tests

Execute the test suite to verify parsers, normalizers, scoring models, and baseline comparators:

```bash
python -m unittest discover tests
```

*Expected output:*
```text
Ran 38 tests in 0.026s
OK
```

---

## 8. Walkthrough of Web Application Pages

1. **📊 Dashboard**: Global metrics overview across all investigations, database statistics, and 1-click synthetic benchmark loaders.
2. **➕ New Investigation**: Create new forensic investigations with case metadata, custom CSV upload (Auth, Audit, File logs), and interactive weight configuration sliders.
3. **📁 Evidence Files & Integrity**: View uploaded artifacts, file sizes, SHA-256 cryptographic digests, and tamper-verification records.
4. **⏱️ Unified Timeline**: Chronological multi-stream forensic timeline with filters for User, Evidence Source, Event Type, and Session ID, complete with Plotly scatter plot.
5. **🔍 Correlation Analysis (Main Page)**:
   - *Activity Sequences*: Step-by-step reconstructed incident sequences with transition badges.
   - *Pairwise Inspector*: Interactive audit card showing exact point additions ($+30, +20, +15$) and missing factors.
6. **🕸️ Evidence Graph**: Network visualization of forensic events (nodes) and correlations (edges) with adjustable score cutoff sliders.
7. **⚖️ Baseline Comparison**: Side-by-side empirical evaluation of Multi-Factor vs. Timestamp-Only baseline. Computes Precision, Recall, and F1 metrics on ground-truth datasets.
8. **📄 Investigation Report**: Generates an audit-ready, standalone HTML forensic report available for instant preview and download.

---

## 9. Academic Evaluation: Benchmark Scenarios

| Scenario | Objective | Baseline Behavior | ForensicFusion Behavior |
|---|---|---|---|
| **Scenario 1: Coherent Session** | Reconstruct full attacker flow: login $\to$ sudo $\to$ file read $\to$ modify $\to$ logout. | Correlates all events based on time. | Correlates events with scores $70-100$, reconstructing a single continuous incident group. |
| **Scenario 2: Concurrent Activity** | Two users (Alice & Bob) working simultaneously within 2 minutes of each other. | **High False Positives**: Falsely links Alice's commands with Bob's file edits. | **Separates Clusters**: User and session factors cleanly isolate events into 2 distinct graphs. Precision is doubled. |
| **Scenario 3: Multiple Sessions** | Single user operating across two separate SSH sessions (Session 201 vs 202). | Blurs both sessions together into one massive group. | Distinguishes Session A from Session B via audit session continuity and process trees. |

---

## 10. License & Academic Disclaimer

ForensicFusion was built as an academic prototype for Digital Forensics education and research. It identifies circumstantial correlations based on log artifacts; it does not constitute conclusive proof of causation. All forensic findings should be reviewed and corroborated by a qualified digital forensics examiner.
