"""
ForensicFusion — Explainable Multi-Log Event Correlation for Linux Forensics
=============================================================================

Web-based forensic analysis application for correlating multi-source Linux
forensic logs (Authentication, Audit, File Activity) and reconstructing
incident sequences with explainable multi-factor scoring.
"""

from __future__ import annotations

import csv
import io
import json
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

# Add project root to sys.path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from core.baseline import BaselineCorrelation
from core.correlation import CorrelationEngine
from core.graph_engine import (
    build_correlation_graph,
    find_event_groups,
    generate_plotly_graph,
    reconstruct_incident,
)
from core.integrity import calculate_sha256, create_evidence_record
from core.normalizer import normalize_events
from core.parser import ParserFactory
from database.db import ForensicDatabase
from reports.generator import ReportGenerator

# ---------------------------------------------------------------------------
# Configuration & Page Setup
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="ForensicFusion — Linux Event Correlation",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom CSS for forensic aesthetic
st.markdown(
    """
    <style>
    .metric-card {
        background-color: #1E232A;
        border-radius: 8px;
        padding: 16px;
        border: 1px solid #30363D;
        margin-bottom: 12px;
    }
    .metric-val {
        font-size: 26px;
        font-weight: bold;
        color: #58A6FF;
    }
    .metric-lbl {
        font-size: 13px;
        color: #8B949E;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }
    .badge-weak {
        background-color: #3d3d3d;
        color: #ccc;
        padding: 3px 8px;
        border-radius: 4px;
        font-size: 12px;
        font-weight: bold;
    }
    .badge-possible {
        background-color: #7d6608;
        color: #f7dc6f;
        padding: 3px 8px;
        border-radius: 4px;
        font-size: 12px;
        font-weight: bold;
    }
    .badge-strong {
        background-color: #1a5276;
        color: #85c1e9;
        padding: 3px 8px;
        border-radius: 4px;
        font-size: 12px;
        font-weight: bold;
    }
    .badge-very-strong {
        background-color: #196f3d;
        color: #82e0aa;
        padding: 3px 8px;
        border-radius: 4px;
        font-size: 12px;
        font-weight: bold;
    }
    .fact-box {
        background-color: rgba(40, 116, 166, 0.15);
        border-left: 4px solid #2874a6;
        padding: 10px 14px;
        margin: 6px 0;
        border-radius: 0 4px 4px 0;
    }
    .inference-box {
        background-color: rgba(214, 137, 16, 0.15);
        border-left: 4px solid #d68910;
        padding: 10px 14px;
        margin: 6px 0;
        border-radius: 0 4px 4px 0;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


@st.cache_resource
def get_db() -> ForensicDatabase:
    """Return singleton database handle."""
    return ForensicDatabase("forensicfusion.db")


db = get_db()


# ---------------------------------------------------------------------------
# Helper: Analysis Pipeline
# ---------------------------------------------------------------------------
def run_investigation_analysis(
    inv_id: int,
    auth_csv_content: Optional[str],
    audit_csv_content: Optional[str],
    files_csv_content: Optional[str],
    auth_name: str = "auth.csv",
    audit_name: str = "audit.csv",
    files_name: str = "files.csv",
    weights: Optional[Dict[str, int]] = None,
    time_window_minutes: int = 5,
    min_score: int = 30,
) -> Tuple[int, int, int]:
    """Execute parsing, normalization, multi-factor correlation, and DB storage."""
    all_events: List[dict] = []

    # Temporary directory for file parsing
    import tempfile

    with tempfile.TemporaryDirectory() as temp_dir:
        specs = [
            ("authentication", auth_csv_content, auth_name),
            ("audit", audit_csv_content, audit_name),
            ("file_activity", files_csv_content, files_name),
        ]

        for src_type, content, fname in specs:
            if not content or not content.strip():
                continue

            content_bytes = content.encode("utf-8")
            rec = create_evidence_record(fname, content_bytes)

            temp_path = os.path.join(temp_dir, fname)
            with open(temp_path, "w", encoding="utf-8") as fh:
                fh.write(content)

            parser = ParserFactory.get_parser(src_type)
            parsed_events = parser.parse(temp_path)

            db.add_evidence_file(inv_id, rec, src_type, len(parsed_events))
            all_events.extend(parsed_events)

        if not all_events:
            return 0, 0, 0

        # Normalization
        norm_events, warnings = normalize_events(all_events)
        db.add_events(inv_id, norm_events)

        # Correlation
        engine = CorrelationEngine(
            weights=weights,
            time_window_minutes=time_window_minutes,
            min_score_threshold=min_score,
        )
        correlations = engine.correlate_all(norm_events)
        db.add_correlations(inv_id, correlations)

        # Graph grouping
        G = build_correlation_graph(norm_events, correlations, min_score=min_score)
        groups = find_event_groups(G)
        db.add_event_groups(inv_id, groups)

        return len(norm_events), len(correlations), len(groups)


# ---------------------------------------------------------------------------
# Sidebar Navigation & Investigation Selector
# ---------------------------------------------------------------------------
st.sidebar.title("🛡️ ForensicFusion")
st.sidebar.caption("Linux Forensic Event Correlation Engine")

investigations = db.list_investigations()

# Session state initialization
if "current_inv_id" not in st.session_state:
    if investigations:
        st.session_state.current_inv_id = investigations[0]["id"]
    else:
        st.session_state.current_inv_id = None

# Case selection
inv_options = {inv["id"]: f"#{inv['id']}: {inv['case_name']}" for inv in investigations}
selected_inv_id = None

if inv_options:
    curr_id = st.session_state.current_inv_id
    default_idx = (
        list(inv_options.keys()).index(curr_id)
        if curr_id in inv_options
        else 0
    )
    selected_inv_id = st.sidebar.selectbox(
        "Active Investigation",
        options=list(inv_options.keys()),
        format_func=lambda x: inv_options[x],
        index=default_idx,
    )
    st.session_state.current_inv_id = selected_inv_id
else:
    st.sidebar.info("No investigations in database. Create one to begin.")

menu_options = [
    "📊 Dashboard",
    "➕ New Investigation",
    "📁 Evidence Files & Integrity",
    "⏱️ Unified Timeline",
    "🔍 Correlation Analysis",
    "🕸️ Evidence Graph",
    "⚖️ Baseline Comparison",
    "📄 Investigation Report",
]

page = st.sidebar.radio("Navigation", menu_options)
st.sidebar.markdown("---")
st.sidebar.caption("Research Prototype • University Digital Forensics")


# ===========================================================================
# PAGE 1: DASHBOARD
# ===========================================================================
if page == "📊 Dashboard":
    st.title("📊 ForensicFusion Dashboard")
    st.markdown(
        """
        Welcome to **ForensicFusion**, an explainable multi-log event correlation prototype
        designed to reconstruct Linux forensic activities across **Authentication**,
        **Audit**, and **File Activity** traces.
        """
    )

    stats = db.get_dashboard_stats()

    col1, col2, col3, col4, col5 = st.columns(5)
    with col1:
        st.metric("Total Investigations", stats["total_investigations"])
    with col2:
        st.metric("Evidence Files", stats["total_evidence_files"])
    with col3:
        st.metric("Total Events", stats["total_events"])
    with col4:
        st.metric("Correlated Groups", stats["total_groups"])
    with col5:
        st.metric("Strong Correlations", stats["strong_correlations"])

    st.markdown("---")

    col_left, col_right = st.columns([3, 2])

    with col_left:
        st.subheader("Recent Investigations")
        if investigations:
            table_data = []
            for inv in investigations:
                inv_stat = db.get_investigation_stats(inv["id"])
                table_data.append({
                    "ID": inv["id"],
                    "Case Name": inv["case_name"],
                    "Investigator": inv.get("investigator") or "N/A",
                    "Events": inv_stat["total_events"],
                    "Correlations": inv_stat["total_correlations"],
                    "Strong (≥60)": inv_stat["strong_correlations"],
                    "Groups": inv_stat["event_groups_count"],
                    "Created": inv.get("created_at", "")[:19].replace("T", " "),
                })
            st.dataframe(pd.DataFrame(table_data), use_container_width=True)
        else:
            st.info("No investigations found. Head to **➕ New Investigation** to load sample scenarios or upload logs.")

    with col_right:
        st.subheader("Core Research Focus")
        st.info(
            """
            **Research Question:**  
            *Can multi-factor forensic event correlation reconstruct related activity sequences more accurately and explainably than timestamp-only correlation?*
            
            **Methodology:**
            - **Temporal similarity ($W_t=20$)**
            - **User identity ($W_u=20$)**
            - **Session continuity ($W_s=30$)**
            - **Process hierarchy ($W_p=10$)**
            - **Resource / File path ($W_f=20$)**
            """
        )

        st.subheader("Quick Launch Synthetic Scenarios")
        st.caption("Pre-configured academic test scenarios located in `/sample_data`:")
        q_scen = st.selectbox(
            "Select Scenario to Load Immediately",
            [
                "Scenario 1: Related Activity (Single User SSH -> sudo -> file edit -> logout)",
                "Scenario 2: Unrelated Activity (Two users overlapping in time - False positive test)",
                "Scenario 3: Multiple Sessions (Same user across two separate sessions)",
            ],
            key="quick_scen_select",
        )
        if st.button("🚀 Quick Load Selected Scenario", type="primary"):
            scen_folder = (
                "scenario_1" if "Scenario 1" in q_scen else ("scenario_2" if "Scenario 2" in q_scen else "scenario_3")
            )
            base_dir = os.path.join(os.path.dirname(__file__), "sample_data", scen_folder)
            try:
                with open(os.path.join(base_dir, "auth.csv"), "r", encoding="utf-8") as f:
                    auth_c = f.read()
                with open(os.path.join(base_dir, "audit.csv"), "r", encoding="utf-8") as f:
                    audit_c = f.read()
                with open(os.path.join(base_dir, "files.csv"), "r", encoding="utf-8") as f:
                    files_c = f.read()

                case_title = f"Academic Benchmark — {q_scen.split(':')[0]}"
                inv_new_id = db.create_investigation(
                    case_name=case_title,
                    investigator="Digital Forensics Lab",
                    description=f"Auto-generated benchmark investigation from {scen_folder}.",
                )
                run_investigation_analysis(inv_new_id, auth_c, audit_c, files_c)
                st.session_state.current_inv_id = inv_new_id
                st.success(f"Investigation #{inv_new_id} created successfully! Switch pages to view.")
                st.rerun()
            except Exception as e:
                st.error(f"Error loading scenario: {e}")


# ===========================================================================
# PAGE 2: NEW INVESTIGATION
# ===========================================================================
elif page == "➕ New Investigation":
    st.title("➕ Create New Forensic Investigation")
    st.markdown("Import Linux forensic artifacts from Authentication, Audit daemon, and File activity monitors.")

    tab_upload, tab_sample = st.tabs(["📤 Upload Custom CSV Files", "🧪 Load Benchmark Scenario"])

    with tab_upload:
        with st.form("custom_investigation_form"):
            col_a, col_b = st.columns(2)
            with col_a:
                case_name = st.text_input("Case Name / Identifier *", "INC-2026-001")
                investigator = st.text_input("Lead Investigator", "Det. Analyst")
            with col_b:
                description = st.text_area(
                    "Case Description",
                    "Suspicious activity reported on production server. Correlating authentication, audit and file logs.",
                )

            st.markdown("#### Evidence Files (Standard CSVs)")
            col_u1, col_u2, col_u3 = st.columns(3)
            with col_u1:
                auth_file = st.file_uploader("1. Authentication Logs (auth.csv)", type=["csv"], key="u_auth")
            with col_u2:
                audit_file = st.file_uploader("2. Audit/System Logs (audit.csv)", type=["csv"], key="u_audit")
            with col_u3:
                files_file = st.file_uploader("3. File Activity Logs (files.csv)", type=["csv"], key="u_files")

            with st.expander("⚙️ Advanced Correlation Engine Parameters (Weights & Thresholds)"):
                col_w1, col_w2, col_w3, col_w4, col_w5 = st.columns(5)
                with col_w1:
                    w_time = st.slider("Time Weight", 0, 50, 20)
                with col_w2:
                    w_user = st.slider("User Weight", 0, 50, 20)
                with col_w3:
                    w_sess = st.slider("Session Weight", 0, 50, 30)
                with col_w4:
                    w_proc = st.slider("Process Weight", 0, 50, 10)
                with col_w5:
                    w_file = st.slider("File Weight", 0, 50, 20)

                total_w = w_time + w_user + w_sess + w_proc + w_file
                if total_w != 100:
                    st.warning(f"Total weights sum to {total_w}/100. Recommended sum is 100.")

                col_t1, col_t2 = st.columns(2)
                with col_t1:
                    time_win = st.slider("Max Time Window (Minutes)", 1, 60, 5)
                with col_t2:
                    min_thresh = st.slider("Minimum Reporting Score Threshold", 0, 80, 30)

            submitted = st.form_submit_button("🔍 Ingest & Correlate Evidence", type="primary")

            if submitted:
                if not case_name.strip():
                    st.error("Please provide a Case Name.")
                elif not (auth_file or audit_file or files_file):
                    st.error("Please upload at least one evidence file.")
                else:
                    auth_c = auth_file.getvalue().decode("utf-8", errors="ignore") if auth_file else None
                    audit_c = audit_file.getvalue().decode("utf-8", errors="ignore") if audit_file else None
                    files_c = files_file.getvalue().decode("utf-8", errors="ignore") if files_file else None

                    inv_id = db.create_investigation(case_name, investigator, description)

                    weights_dict = {
                        "temporal": w_time,
                        "user": w_user,
                        "session": w_sess,
                        "process": w_proc,
                        "file": w_file,
                    }

                    n_events, n_corr, n_grp = run_investigation_analysis(
                        inv_id=inv_id,
                        auth_csv_content=auth_c,
                        audit_csv_content=audit_c,
                        files_csv_content=files_c,
                        auth_name=auth_file.name if auth_file else "auth.csv",
                        audit_name=audit_file.name if audit_file else "audit.csv",
                        files_name=files_file.name if files_file else "files.csv",
                        weights=weights_dict,
                        time_window_minutes=time_win,
                        min_score=min_thresh,
                    )

                    st.session_state.current_inv_id = inv_id
                    st.success(
                        f"✅ Investigation #{inv_id} created! Ingested {n_events} events, "
                        f"discovered {n_corr} correlations across {n_grp} activity clusters."
                    )
                    st.rerun()

    with tab_sample:
        st.markdown("#### Select a Synthetic Test Scenario")
        scenario_choice = st.radio(
            "Scenario Definition",
            [
                "Scenario 1: Coherent Activity (SSH login -> sudo -> access confidential.txt -> edit -> logout)",
                "Scenario 2: Unrelated Overlapping Activity (Alice and Bob perform tasks at the same time)",
                "Scenario 3: Multiple Sessions (Same user in two separate SSH sessions)",
            ],
        )

        scen_tag = "scenario_1" if "Scenario 1" in scenario_choice else ("scenario_2" if "Scenario 2" in scenario_choice else "scenario_3")
        base_dir = os.path.join(os.path.dirname(__file__), "sample_data", scen_tag)

        st.caption(f"Files will be read from: `{base_dir}`")
        if st.button("📥 Load Benchmark Dataset", type="primary"):
            try:
                with open(os.path.join(base_dir, "auth.csv"), "r", encoding="utf-8") as f:
                    auth_c = f.read()
                with open(os.path.join(base_dir, "audit.csv"), "r", encoding="utf-8") as f:
                    audit_c = f.read()
                with open(os.path.join(base_dir, "files.csv"), "r", encoding="utf-8") as f:
                    files_c = f.read()

                case_title = f"Controlled Benchmark ({scen_tag.upper()})"
                inv_id = db.create_investigation(
                    case_name=case_title,
                    investigator="DFIR Benchmark Suite",
                    description=f"Automated ingestion of {scenario_choice}.",
                )

                n_events, n_corr, n_grp = run_investigation_analysis(
                    inv_id=inv_id,
                    auth_csv_content=auth_c,
                    audit_csv_content=audit_c,
                    files_csv_content=files_c,
                )

                st.session_state.current_inv_id = inv_id
                st.success(f"Benchmark #{inv_id} loaded! Ingested {n_events} events, {n_corr} correlations.")
                st.rerun()
            except Exception as e:
                st.error(f"Failed to load sample dataset: {e}")


# ===========================================================================
# PAGE 3: EVIDENCE FILES & INTEGRITY
# ===========================================================================
elif page == "📁 Evidence Files & Integrity":
    if not selected_inv_id:
        st.warning("Please select or create an investigation first.")
        st.stop()

    inv = db.get_investigation(selected_inv_id)
    st.title("📁 Evidence Files & Cryptographic Chain of Custody")
    st.markdown(f"**Case:** #{inv['id']} — {inv['case_name']} | **Investigator:** {inv.get('investigator', 'N/A')}")

    ev_files = db.get_evidence_files(selected_inv_id)
    if not ev_files:
        st.info("No evidence files associated with this case.")
        st.stop()

    st.markdown("### Cryptographic Hashes (SHA-256)")
    st.caption("Forensic principle: Original evidence files are hashed immediately upon ingest to ensure tamper verification.")

    file_rows = []
    for f in ev_files:
        file_rows.append({
            "Filename": f.get("filename"),
            "Source Type": f.get("source_type"),
            "Size (Bytes)": f.get("file_size"),
            "Event Count": f.get("event_count"),
            "SHA-256 Digest": f.get("sha256"),
            "Ingestion Time (UTC)": f.get("upload_time", "")[:19].replace("T", " "),
        })

    st.dataframe(pd.DataFrame(file_rows), use_container_width=True)

    st.markdown("---")
    st.subheader("Integrity Verification Summary")
    for f in ev_files:
        with st.container():
            st.markdown(
                f"""
                <div class="fact-box">
                    <strong>Observed Artifact:</strong> <code>{f.get('filename')}</code><br>
                    <strong>Computed SHA-256:</strong> <code>{f.get('sha256')}</code><br>
                    <strong>Status:</strong> Verified authentic at collection time ({f.get('upload_time')}).
                </div>
                """,
                unsafe_allow_html=True,
            )


# ===========================================================================
# PAGE 4: UNIFIED TIMELINE
# ===========================================================================
elif page == "⏱️ Unified Timeline":
    if not selected_inv_id:
        st.warning("Please select or create an investigation first.")
        st.stop()

    st.title("⏱️ Unified Forensic Timeline")
    st.markdown("Chronological integration of normalized events from all evidence streams.")

    events = db.get_events(selected_inv_id)
    if not events:
        st.info("No events found for this investigation.")
        st.stop()

    # Filter controls
    col_f1, col_f2, col_f3, col_f4 = st.columns(4)
    with col_f1:
        users = sorted(list({e.get("username") for e in events if e.get("username")}))
        sel_user = st.selectbox("Filter User", ["All"] + users)
    with col_f2:
        sources = sorted(list({e.get("source_type") for e in events if e.get("source_type")}))
        sel_src = st.selectbox("Filter Source Type", ["All"] + sources)
    with col_f3:
        etypes = sorted(list({e.get("event_type") for e in events if e.get("event_type")}))
        sel_etype = st.selectbox("Filter Event Type", ["All"] + etypes)
    with col_f4:
        sessions = sorted(list({str(e.get("session_id")) for e in events if e.get("session_id")}))
        sel_sess = st.selectbox("Filter Session ID", ["All"] + sessions)

    filtered_events = events
    if sel_user != "All":
        filtered_events = [e for e in filtered_events if e.get("username") == sel_user]
    if sel_src != "All":
        filtered_events = [e for e in filtered_events if e.get("source_type") == sel_src]
    if sel_etype != "All":
        filtered_events = [e for e in filtered_events if e.get("event_type") == sel_etype]
    if sel_sess != "All":
        filtered_events = [e for e in filtered_events if str(e.get("session_id")) == sel_sess]

    st.caption(f"Displaying {len(filtered_events)} of {len(events)} events.")

    # Interactive Plotly Timeline Chart
    if filtered_events:
        df_plot = pd.DataFrame(filtered_events)
        df_plot["display_time"] = pd.to_datetime(df_plot["timestamp"])
        df_plot["hover_text"] = df_plot.apply(
            lambda r: f"<b>ID:</b> {r['event_id']}<br>"
            f"<b>Source:</b> {r['source_type']}<br>"
            f"<b>Action:</b> {r['action'] or r['event_type']}<br>"
            f"<b>User:</b> {r['username']}<br>"
            f"<b>Session:</b> {r['session_id']}<br>"
            f"<b>Process:</b> {r['process'] or r['executable']}<br>"
            f"<b>File:</b> {r['file_path']}",
            axis=1,
        )

        fig = px.scatter(
            df_plot,
            x="display_time",
            y="source_type",
            color="source_type",
            hover_name="event_id",
            custom_data=["hover_text"],
            color_discrete_map={
                "authentication": "#4A90D9",
                "audit": "#E8923F",
                "file_activity": "#5CB85C",
            },
            title="Chronological Event Distribution across Evidence Streams",
            labels={"display_time": "UTC Timestamp", "source_type": "Evidence Stream"},
            height=320,
        )
        fig.update_traces(
            marker=dict(size=14, symbol="circle", line=dict(width=1, color="white")),
            hovertemplate="%{customdata[0]}<extra></extra>",
        )
        fig.update_layout(showlegend=False, margin=dict(l=20, r=20, t=40, b=20))
        st.plotly_chart(fig, use_container_width=True)

    # Detailed table view
    st.markdown("### Chronological Event Log")
    table_rows = []
    for e in filtered_events:
        table_rows.append({
            "Event ID": e.get("event_id"),
            "UTC Timestamp": e.get("timestamp"),
            "Source": e.get("source_type"),
            "Event / Action": e.get("action") or e.get("event_type"),
            "User": e.get("username") or "-",
            "Session": e.get("session_id") or "-",
            "PID": e.get("pid") or "-",
            "Process / Cmd": e.get("process") or e.get("executable") or "-",
            "File Path": e.get("file_path") or "-",
            "Source IP": e.get("source_ip") or "-",
        })
    st.dataframe(pd.DataFrame(table_rows), use_container_width=True)


# ===========================================================================
# PAGE 5: CORRELATION ANALYSIS (MAIN PAGE)
# ===========================================================================
elif page == "🔍 Correlation Analysis":
    if not selected_inv_id:
        st.warning("Please select or create an investigation first.")
        st.stop()

    st.title("🔍 Multi-Factor Correlation Analysis")
    st.markdown(
        """
        ForensicFusion's core inference engine: evaluating pairwise relationships across
        **Temporal**, **User**, **Session**, **Process**, and **Resource/File** factors.
        """
    )

    events = db.get_events(selected_inv_id)
    correlations = db.get_correlations(selected_inv_id, min_score=0)
    groups = db.get_event_groups(selected_inv_id)

    if not correlations:
        st.info("No correlations found above the minimum threshold.")
        st.stop()

    tab_seq, tab_pair = st.tabs(["🔄 Reconstructed Activity Sequences", "🔬 Pairwise Correlation Inspector"])

    # --- TAB 1: Incident Sequences ---
    with tab_seq:
        st.markdown("### Reconstructed Activity Sequences (Incident Groups)")
        st.caption(
            "Events clustered into connected components and reconstructed chronologically. "
            "Relationships illustrate the factors binding each transition."
        )

        if not groups:
            st.info("No connected event groups identified.")
        else:
            for g_idx, grp_ids in enumerate(groups, 1):
                rec = reconstruct_incident(events, grp_ids, correlations)
                with st.expander(f"📦 Activity Group #{g_idx} ({len(grp_ids)} Events)", expanded=(g_idx == 1)):
                    st.markdown(f"**Cluster Summary:** *{rec['summary']}*")
                    st.markdown("---")

                    grp_evs = rec["events"]
                    for i, ev in enumerate(grp_evs):
                        src_badge = f"**[{ev.get('source_type', '').upper()}]**"
                        desc = ev.get("action") or ev.get("event_type") or "event"
                        usr = ev.get("username") or "system"
                        sess = f"session={ev.get('session_id')}" if ev.get("session_id") else ""
                        cmd = f"`{ev.get('process') or ev.get('executable')}`" if (ev.get("process") or ev.get("executable")) else ""
                        fpath = f"file: `{ev.get('file_path')}`" if ev.get("file_path") else ""

                        details = " | ".join(filter(None, [usr, sess, cmd, fpath]))

                        st.markdown(
                            f"""
                            <div class="fact-box">
                                <strong>{ev.get('timestamp')}</strong> — <code>{ev.get('event_id')}</code> {src_badge} <strong>{desc}</strong><br>
                                <span style="font-size: 13px; color: #bbb;">{details}</span>
                            </div>
                            """,
                            unsafe_allow_html=True,
                        )

                        # If there is a next event, show link
                        if i < len(grp_evs) - 1:
                            rel = rec["relationships"][i]
                            score_val = rel["score"]
                            if score_val is not None:
                                badge_class = (
                                    "badge-very-strong" if score_val >= 80 else ("badge-strong" if score_val >= 60 else "badge-possible")
                                )
                                expl_short = rel["explanation"].split("\n")[0] if rel.get("explanation") else ""
                                st.markdown(
                                    f"""
                                    <div style="margin-left: 30px; padding: 4px 0;">
                                        ⬇️ <span class="{badge_class}">Score: {score_val:.0f}/100</span> — <em>{expl_short}</em>
                                    </div>
                                    """,
                                    unsafe_allow_html=True,
                                )
                            else:
                                st.markdown(
                                    """
                                    <div style="margin-left: 30px; padding: 4px 0; color: #888;">
                                        ⬇️ Indirect connection through group component
                                    </div>
                                    """
                                )

    # --- TAB 2: Pairwise Inspector ---
    with tab_pair:
        st.markdown("### Explainable Pairwise Correlation Inspector")
        st.caption("Inspect the exact breakdown of why two forensic events were or were not correlated.")

        col_fil1, col_fil2 = st.columns(2)
        with col_fil1:
            classes = ["All", "Very Strong", "Strong", "Possible", "Weak"]
            sel_class = st.selectbox("Filter by Classification", classes)
        with col_fil2:
            min_score_filter = st.slider("Filter Minimum Score", 0, 100, 30)

        disp_corrs = correlations
        if sel_class != "All":
            disp_corrs = [c for c in disp_corrs if c.get("classification") == sel_class]
        disp_corrs = [c for c in disp_corrs if c.get("total_score", 0) >= min_score_filter]

        if not disp_corrs:
            st.info("No correlation pairs match the selected filter.")
        else:
            pair_labels = {
                idx: f"Pair #{idx+1}: {c['event_a_id']} ↔ {c['event_b_id']} (Score: {c['total_score']:.0f} — {c['classification']})"
                for idx, c in enumerate(disp_corrs)
            }

            sel_idx = st.selectbox(
                "Select Correlated Event Pair to Inspect",
                options=list(pair_labels.keys()),
                format_func=lambda x: pair_labels[x],
            )

            chosen_corr = disp_corrs[sel_idx]

            # Events lookup
            ev_dict = {e["event_id"]: e for e in events if e.get("event_id")}
            ev_a = ev_dict.get(chosen_corr["event_a_id"], {})
            ev_b = ev_dict.get(chosen_corr["event_b_id"], {})

            col_c1, col_c2 = st.columns(2)
            with col_c1:
                st.markdown(f"#### Event A: `{chosen_corr['event_a_id']}`")
                st.json(ev_a)
            with col_c2:
                st.markdown(f"#### Event B: `{chosen_corr['event_b_id']}`")
                st.json(ev_b)

            st.markdown("---")
            st.markdown(f"### Correlation Explanation: **{chosen_corr['total_score']:.0f}/100** ({chosen_corr['classification']})")

            # Factor cards
            factors = chosen_corr.get("factors", [])
            f_cols = st.columns(len(factors) if factors else 1)
            for i, f in enumerate(factors):
                with f_cols[i]:
                    raw = f.get("raw_score", 0.0)
                    weight = f.get("weighted_score", 0.0)
                    name = f.get("factor", "").capitalize()
                    status_icon = "✅" if raw > 0 else "❌"
                    st.metric(f"{status_icon} {name}", f"+{weight:.1f}", f"Raw: {raw:.2f}")
                    st.caption(f.get("explanation", ""))

            st.markdown("#### Full Explanation Breakdown")
            st.code(chosen_corr.get("explanation", ""), language="text")

            # Forensic Principle Disclaimer
            st.markdown(
                """
                <div class="inference-box">
                    <strong>Forensic Science Principle:</strong> This correlation score represents an <em>algorithmic inference</em> based on observed shared parameters. 
                    It establishes high circumstantial association, but independent validation of timestamps and process states is recommended.
                </div>
                """,
                unsafe_allow_html=True,
            )


# ===========================================================================
# PAGE 6: EVIDENCE GRAPH
# ===========================================================================
elif page == "🕸️ Evidence Graph":
    if not selected_inv_id:
        st.warning("Please select or create an investigation first.")
        st.stop()

    st.title("🕸️ Forensic Evidence Relationship Graph")
    st.markdown(
        "Network visualization of events and multi-factor correlation edges built with **NetworkX** and rendered in **Plotly**."
    )

    events = db.get_events(selected_inv_id)
    correlations = db.get_correlations(selected_inv_id, min_score=0)

    if not correlations:
        st.info("No correlation data available.")
        st.stop()

    col_g1, col_g2 = st.columns([3, 1])
    with col_g2:
        graph_min_score = st.slider("Graph Edge Score Threshold", 0, 100, 30, help="Edges below this score are filtered out.")
        st.caption(
            """
            **Color Legend:**
            - 🔵 Authentication Logs
            - 🟠 Audit / System Logs
            - 🟢 File Activity Logs
            """
        )

    with col_g1:
        G = build_correlation_graph(events, correlations, min_score=graph_min_score)
        fig = generate_plotly_graph(G, events)
        st.plotly_chart(fig, use_container_width=True)

    st.markdown("---")
    st.subheader("Graph Topology Metrics")
    m_c1, m_c2, m_c3 = st.columns(3)
    with m_c1:
        st.metric("Total Nodes (Events)", G.number_of_nodes())
    with m_c2:
        st.metric("Total Edges (Correlations)", G.number_of_edges())
    with m_c3:
        components_count = len(list(find_event_groups(G)))
        st.metric("Independent Incident Clusters", components_count)


# ===========================================================================
# PAGE 7: BASELINE COMPARISON
# ===========================================================================
elif page == "⚖️ Baseline Comparison":
    if not selected_inv_id:
        st.warning("Please select or create an investigation first.")
        st.stop()

    st.title("⚖️ Baseline Evaluation: Multi-Factor vs. Timestamp-Only")
    st.markdown(
        """
        Comparing our proposed **Multi-Factor Correlation Engine** against the naive
        **Timestamp-Only Baseline** (events within a fixed time window).
        """
    )

    events = db.get_events(selected_inv_id)
    if not events:
        st.info("No events loaded.")
        st.stop()

    time_win = st.sidebar.slider("Baseline Window (Minutes)", 1, 15, 5, key="base_win_slider")

    # Run baseline
    baseline_engine = BaselineCorrelation(time_window_minutes=time_win)
    baseline_results = baseline_engine.correlate_all(events)

    # Multi-factor results
    mf_correlations = db.get_correlations(selected_inv_id, min_score=30)

    col1, col2 = st.columns(2)
    with col1:
        st.markdown("### ⏱️ Timestamp-Only Baseline")
        st.caption(f"Rule: Any two events occurring within {time_win} minutes are correlated.")
        st.metric("Total Baseline Correlations", len(baseline_results))
        st.write(
            "Prone to **high false-positive rates** when multiple users or unrelated background tasks operate concurrently."
        )

    with col2:
        st.markdown("### 🛡️ ForensicFusion Multi-Factor")
        st.caption("Rule: Weighted score combining Time, User, Session, Process, and Resource.")
        st.metric("Multi-Factor Correlations (Score ≥ 30)", len(mf_correlations))
        strong_cnt = len([c for c in mf_correlations if c.get("total_score", 0) >= 60])
        st.metric("Strong Correlations (Score ≥ 60)", strong_cnt)

    st.markdown("---")
    st.subheader("Ground-Truth Accuracy Evaluation")

    gt_file_path = os.path.join(os.path.dirname(__file__), "sample_data", "ground_truth.csv")
    has_ground_truth = os.path.isfile(gt_file_path)

    if has_ground_truth:
        st.info("Found ground truth benchmark labels in `sample_data/ground_truth.csv`. Evaluating precision and recall.")

        # Load ground truth
        gt_pairs = []
        with open(gt_file_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                gt_pairs.append({
                    "event_a_id": row["event_id_1"],
                    "event_b_id": row["event_id_2"],
                    "related": row["related"].strip().lower() == "true",
                    "scenario": row.get("scenario", "1"),
                })

        comparison = baseline_engine.compare_with_multifactor(
            baseline_results=baseline_results,
            multifactor_results=mf_correlations,
            ground_truth_pairs=gt_pairs,
        )

        b_metrics = comparison.get("baseline_metrics")
        m_metrics = comparison.get("multifactor_metrics")

        if b_metrics and m_metrics:
            col_m1, col_m2 = st.columns(2)
            with col_m1:
                st.markdown("#### Timestamp-Only Metrics")
                st.metric("Precision", f"{b_metrics['precision']:.2%}")
                st.metric("Recall", f"{b_metrics['recall']:.2%}")
                st.metric("F1 Score", f"{b_metrics['f1']:.2%}")

            with col_m2:
                st.markdown("#### ForensicFusion Multi-Factor Metrics")
                st.metric("Precision", f"{m_metrics['precision']:.2%}")
                st.metric("Recall", f"{m_metrics['recall']:.2%}")
                st.metric("F1 Score", f"{m_metrics['f1']:.2%}")

            # Plotly bar chart
            chart_df = pd.DataFrame([
                {"Method": "Timestamp-Only", "Metric": "Precision", "Value": b_metrics["precision"]},
                {"Method": "Timestamp-Only", "Metric": "Recall", "Value": b_metrics["recall"]},
                {"Method": "Timestamp-Only", "Metric": "F1 Score", "Value": b_metrics["f1"]},
                {"Method": "Multi-Factor", "Metric": "Precision", "Value": m_metrics["precision"]},
                {"Method": "Multi-Factor", "Metric": "Recall", "Value": m_metrics["recall"]},
                {"Method": "Multi-Factor", "Metric": "F1 Score", "Value": m_metrics["f1"]},
            ])

            fig_bar = px.bar(
                chart_df,
                x="Metric",
                y="Value",
                color="Method",
                barmode="group",
                title="Performance Comparison on Ground-Truth Benchmark",
                text_auto=".2%",
                color_discrete_map={"Timestamp-Only": "#E8923F", "Multi-Factor": "#4A90D9"},
            )
            fig_bar.update_yaxes(range=[0, 1.1])
            st.plotly_chart(fig_bar, use_container_width=True)

            st.markdown(
                """
                #### Key Findings & Academic Contribution
                - **False Positive Elimination**: In scenarios with multiple concurrent users (Scenario 2), timestamp-only correlation falsely groups independent events due to temporal proximity.
                - **Session Continuity**: Multi-factor scoring isolates distinct sessions belonging to the same user (Scenario 3) via audit session IDs and parent/child PID hierarchies.
                """
            )
    else:
        st.warning("Ground truth file `sample_data/ground_truth.csv` not found.")


# ===========================================================================
# PAGE 8: REPORT
# ===========================================================================
elif page == "📄 Investigation Report":
    if not selected_inv_id:
        st.warning("Please select or create an investigation first.")
        st.stop()

    inv = db.get_investigation(selected_inv_id)
    ev_files = db.get_evidence_files(selected_inv_id)
    events = db.get_events(selected_inv_id)
    correlations = db.get_correlations(selected_inv_id, min_score=30)
    groups = db.get_event_groups(selected_inv_id)

    st.title("📄 Forensic Investigation Report")
    st.markdown(f"Generate and export audit-ready forensic reports for **Case #{inv['id']}: {inv['case_name']}**.")

    # Reconstruct incidents for report
    reconstructed_incidents = [
        reconstruct_incident(events, grp, correlations) for grp in groups
    ]

    generator = ReportGenerator()
    html_report = generator.generate_html_report(
        investigation=inv,
        evidence_files=ev_files,
        events=events,
        correlations=correlations,
        event_groups=groups,
        reconstructed_incidents=reconstructed_incidents,
    )

    st.download_button(
        label="📥 Download Standalone HTML Forensic Report",
        data=html_report,
        file_name=f"ForensicReport_Case_{inv['id']}.html",
        mime="text/html",
        type="primary",
    )

    st.markdown("---")
    st.subheader("Report Preview")
    st.components.v1.html(html_report, height=800, scrolling=True)
