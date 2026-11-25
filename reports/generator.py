"""
ForensicFusion Report Generator — standalone HTML forensic reports.

Produces a self-contained HTML document with inline CSS that summarises
an investigation's evidence, timeline, correlations, and reconstructed
activity groups.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


class ReportGenerator:
    """Generate professional HTML reports from investigation data.

    All output is a single standalone HTML string with no external
    dependencies — suitable for archiving, printing, or emailing.
    """

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate_html_report(
        self,
        investigation: Dict[str, Any],
        evidence_files: List[Dict[str, Any]],
        events: List[Dict[str, Any]],
        correlations: List[Dict[str, Any]],
        event_groups: List[List[str]],
        reconstructed_incidents: List[Dict[str, Any]],
    ) -> str:
        """Build a complete HTML report.

        Parameters
        ----------
        investigation : dict
            Case metadata (``case_name``, ``investigator``, ``description``,
            ``created_at``).
        evidence_files : list of dict
            Evidence-file records (``filename``, ``source_type``,
            ``file_size``, ``sha256``, ``event_count``).
        events : list of dict
            All parsed events, each with at least ``event_id``,
            ``timestamp``, ``source_type``, ``event_type``, ``username``.
        correlations : list of dict
            Correlation results with ``event_a_id``, ``event_b_id``,
            ``total_score``, ``classification``, ``explanation``.
        event_groups : list of list of str
            Groups of correlated event IDs.
        reconstructed_incidents : list of dict
            High-level incident reconstructions (optional enrichment).

        Returns
        -------
        str
            A complete, self-contained HTML document.
        """
        generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        # Sort events chronologically for the timeline
        sorted_events = sorted(events, key=lambda e: e.get("timestamp", ""))

        # Build an event lookup for fast access inside groups
        event_lookup: Dict[str, Dict[str, Any]] = {
            e.get("event_id", ""): e for e in events if e.get("event_id")
        }

        # Strong correlations (score >= 60) for the detail section
        strong_correlations = [c for c in correlations if c.get("total_score", 0) >= 60]

        # Summary counts
        total_events = len(events)
        total_correlations = len(correlations)
        strong_count = len(strong_correlations)
        group_count = len(event_groups)

        # Assemble sections --------------------------------------------------
        sections: List[str] = [
            self._css(),
            self._header(),
            self._case_info(investigation),
            self._evidence_table(evidence_files),
            self._analysis_summary(total_events, total_correlations, strong_count, group_count),
            self._event_timeline(sorted_events),
            self._correlated_groups(event_groups, event_lookup, correlations),
            self._correlation_details(strong_correlations),
            self._reconstructed_incidents(reconstructed_incidents),
            self._limitations(),
            self._footer(generated_at),
        ]

        return (
            "<!DOCTYPE html>\n<html lang='en'>\n<head>\n"
            "<meta charset='UTF-8'>\n"
            "<meta name='viewport' content='width=device-width, initial-scale=1.0'>\n"
            "<title>ForensicFusion Report</title>\n"
            "</head>\n<body>\n"
            + "\n".join(sections)
            + "\n</body>\n</html>"
        )

    @staticmethod
    def save_report(html_content: str, filepath: str) -> None:
        """Write *html_content* to *filepath*.

        Parameters
        ----------
        html_content : str
            The full HTML string returned by :meth:`generate_html_report`.
        filepath : str
            Destination path (e.g. ``"report.html"``).
        """
        with open(filepath, "w", encoding="utf-8") as fh:
            fh.write(html_content)

    # ------------------------------------------------------------------
    # Private section builders
    # ------------------------------------------------------------------

    @staticmethod
    def _css() -> str:
        """Return the ``<style>`` block with inline CSS."""
        return """<style>
    :root {
        --primary: #1a237e;
        --primary-light: #3949ab;
        --accent: #00897b;
        --bg: #f5f5f5;
        --card-bg: #ffffff;
        --text: #212121;
        --text-light: #757575;
        --border: #e0e0e0;
        --danger: #c62828;
        --warning: #f57f17;
        --success: #2e7d32;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        background: var(--bg); color: var(--text);
        line-height: 1.6; padding: 20px;
    }
    .container { max-width: 1100px; margin: 0 auto; }
    h1 { color: var(--primary); font-size: 1.8rem; margin-bottom: 4px; }
    h2 {
        color: var(--primary-light); font-size: 1.3rem;
        border-bottom: 2px solid var(--primary-light);
        padding-bottom: 6px; margin: 28px 0 14px;
    }
    h3 { color: var(--accent); font-size: 1.1rem; margin: 16px 0 8px; }
    .subtitle { color: var(--text-light); font-size: 0.95rem; }
    .card {
        background: var(--card-bg); border: 1px solid var(--border);
        border-radius: 8px; padding: 18px 22px; margin-bottom: 18px;
        box-shadow: 0 1px 3px rgba(0,0,0,0.06);
    }
    table { width: 100%; border-collapse: collapse; margin-top: 10px; }
    th, td {
        text-align: left; padding: 8px 12px;
        border-bottom: 1px solid var(--border); font-size: 0.9rem;
    }
    th { background: var(--primary); color: #fff; }
    tr:nth-child(even) { background: #fafafa; }
    .stat-grid {
        display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
        gap: 14px;
    }
    .stat-box {
        background: var(--card-bg); border: 1px solid var(--border);
        border-radius: 8px; padding: 16px; text-align: center;
    }
    .stat-value { font-size: 1.8rem; font-weight: 700; color: var(--primary); }
    .stat-label { font-size: 0.85rem; color: var(--text-light); margin-top: 4px; }
    .badge {
        display: inline-block; padding: 2px 10px; border-radius: 12px;
        font-size: 0.8rem; font-weight: 600; color: #fff;
    }
    .badge-strong { background: var(--danger); }
    .badge-moderate { background: var(--warning); }
    .badge-weak { background: var(--text-light); }
    .badge-none { background: var(--border); color: var(--text); }
    .timeline-item {
        border-left: 3px solid var(--primary-light);
        padding: 8px 16px; margin-bottom: 6px;
    }
    .timeline-ts { font-weight: 600; color: var(--primary); font-size: 0.85rem; }
    .timeline-detail { font-size: 0.88rem; color: var(--text-light); }
    .correlation-card {
        background: #fff8e1; border: 1px solid #ffe082;
        border-radius: 8px; padding: 14px 18px; margin-bottom: 12px;
    }
    .group-card {
        background: #e8f5e9; border: 1px solid #a5d6a7;
        border-radius: 8px; padding: 14px 18px; margin-bottom: 14px;
    }
    .disclaimer {
        background: #fff3e0; border-left: 4px solid var(--warning);
        padding: 14px 18px; margin: 24px 0; font-size: 0.9rem;
    }
    .disclaimer li { margin-left: 18px; margin-bottom: 4px; }
    footer {
        text-align: center; padding: 18px 0; margin-top: 30px;
        color: var(--text-light); font-size: 0.82rem;
        border-top: 1px solid var(--border);
    }
</style>"""

    @staticmethod
    def _header() -> str:
        return (
            "<div class='container'>\n"
            "<h1>&#128270; ForensicFusion &mdash; Forensic Investigation Report</h1>\n"
            "<p class='subtitle'>Automated cross-source forensic event analysis</p>"
        )

    @staticmethod
    def _case_info(inv: Dict[str, Any]) -> str:
        return (
            "<h2>Case Information</h2>\n<div class='card'>\n"
            f"<p><strong>Case Name:</strong> {_esc(inv.get('case_name', 'N/A'))}</p>\n"
            f"<p><strong>Investigator:</strong> {_esc(inv.get('investigator', 'N/A'))}</p>\n"
            f"<p><strong>Description:</strong> {_esc(inv.get('description', 'N/A'))}</p>\n"
            f"<p><strong>Created:</strong> {_esc(inv.get('created_at', 'N/A'))}</p>\n"
            "</div>"
        )

    @staticmethod
    def _evidence_table(files: List[Dict[str, Any]]) -> str:
        if not files:
            return "<h2>Evidence Files</h2>\n<div class='card'><p>No evidence files.</p></div>"

        rows = ""
        for f in files:
            size = f.get("file_size", 0)
            size_str = f"{size:,} B" if isinstance(size, int) else str(size)
            rows += (
                f"<tr><td>{_esc(f.get('filename', ''))}</td>"
                f"<td>{_esc(f.get('source_type', ''))}</td>"
                f"<td>{size_str}</td>"
                f"<td><code>{_esc(f.get('sha256', '')[:16])}…</code></td>"
                f"<td>{f.get('event_count', 0)}</td></tr>\n"
            )

        return (
            "<h2>Evidence Files</h2>\n<div class='card'>\n"
            "<table><tr><th>Filename</th><th>Source Type</th><th>Size</th>"
            "<th>SHA-256 (truncated)</th><th>Events</th></tr>\n"
            f"{rows}</table></div>"
        )

    @staticmethod
    def _analysis_summary(
        total_events: int,
        total_corr: int,
        strong_corr: int,
        group_count: int,
    ) -> str:
        return (
            "<h2>Analysis Summary</h2>\n<div class='stat-grid'>\n"
            f"<div class='stat-box'><div class='stat-value'>{total_events}</div>"
            "<div class='stat-label'>Total Events</div></div>\n"
            f"<div class='stat-box'><div class='stat-value'>{total_corr}</div>"
            "<div class='stat-label'>Correlations Found</div></div>\n"
            f"<div class='stat-box'><div class='stat-value'>{strong_corr}</div>"
            "<div class='stat-label'>Strong Correlations</div></div>\n"
            f"<div class='stat-box'><div class='stat-value'>{group_count}</div>"
            "<div class='stat-label'>Event Groups</div></div>\n"
            "</div>"
        )

    @staticmethod
    def _event_timeline(events: List[Dict[str, Any]]) -> str:
        if not events:
            return "<h2>Event Timeline</h2>\n<div class='card'><p>No events.</p></div>"

        items = ""
        for e in events:
            ts = e.get("timestamp", "?")
            eid = e.get("event_id", "?")
            etype = e.get("event_type", "")
            user = e.get("username", "")
            src = e.get("source_type", "")
            action = e.get("action", "")
            detail_parts = [f"[{_esc(src)}]" if src else ""]
            if etype:
                detail_parts.append(_esc(etype))
            if user:
                detail_parts.append(f"user={_esc(user)}")
            if action:
                detail_parts.append(f"action={_esc(action)}")
            detail = " &middot; ".join(p for p in detail_parts if p)

            items += (
                f"<div class='timeline-item'>"
                f"<span class='timeline-ts'>{_esc(ts)}</span> "
                f"<strong>{_esc(eid)}</strong><br>"
                f"<span class='timeline-detail'>{detail}</span></div>\n"
            )

        return f"<h2>Event Timeline</h2>\n<div class='card'>\n{items}</div>"

    @staticmethod
    def _correlated_groups(
        groups: List[List[str]],
        event_lookup: Dict[str, Dict[str, Any]],
        correlations: List[Dict[str, Any]],
    ) -> str:
        if not groups:
            return (
                "<h2>Correlated Activity Groups</h2>\n"
                "<div class='card'><p>No event groups identified.</p></div>"
            )

        html = "<h2>Correlated Activity Groups</h2>\n"
        for idx, group in enumerate(groups, start=1):
            # Sort group events chronologically
            group_events = []
            for eid in group:
                evt = event_lookup.get(eid)
                if evt:
                    group_events.append(evt)
            group_events.sort(key=lambda e: e.get("timestamp", ""))

            event_rows = ""
            for ge in group_events:
                event_rows += (
                    f"<tr><td>{_esc(ge.get('event_id', ''))}</td>"
                    f"<td>{_esc(ge.get('timestamp', ''))}</td>"
                    f"<td>{_esc(ge.get('event_type', ''))}</td>"
                    f"<td>{_esc(ge.get('username', ''))}</td></tr>\n"
                )

            # Find correlations within this group
            group_set = set(group)
            group_corrs = [
                c
                for c in correlations
                if c.get("event_a_id") in group_set and c.get("event_b_id") in group_set
            ]

            rel_rows = ""
            for gc in sorted(group_corrs, key=lambda c: c.get("total_score", 0), reverse=True):
                badge_cls = _badge_class(gc.get("classification", ""))
                rel_rows += (
                    f"<p><strong>{_esc(gc.get('event_a_id', ''))} ↔ "
                    f"{_esc(gc.get('event_b_id', ''))}</strong> "
                    f"<span class='badge {badge_cls}'>"
                    f"{gc.get('total_score', 0):.0f} — "
                    f"{_esc(gc.get('classification', ''))}</span><br>"
                    f"<em>{_esc(gc.get('explanation', ''))}</em></p>\n"
                )

            html += (
                f"<div class='group-card'>\n"
                f"<h3>Group {idx} ({len(group)} events)</h3>\n"
                "<table><tr><th>Event ID</th><th>Timestamp</th>"
                "<th>Type</th><th>User</th></tr>\n"
                f"{event_rows}</table>\n"
                f"{rel_rows}</div>\n"
            )

        return html

    @staticmethod
    def _correlation_details(correlations: List[Dict[str, Any]]) -> str:
        if not correlations:
            return (
                "<h2>Correlation Details (score &ge; 60)</h2>\n"
                "<div class='card'><p>No strong correlations.</p></div>"
            )

        html = "<h2>Correlation Details (score &ge; 60)</h2>\n"
        for c in sorted(correlations, key=lambda x: x.get("total_score", 0), reverse=True):
            badge_cls = _badge_class(c.get("classification", ""))
            html += (
                f"<div class='correlation-card'>\n"
                f"<h3>{_esc(c.get('event_a_id', ''))} ↔ "
                f"{_esc(c.get('event_b_id', ''))}</h3>\n"
                f"<p>Score: <strong>{c.get('total_score', 0):.1f}</strong> "
                f"<span class='badge {badge_cls}'>"
                f"{_esc(c.get('classification', ''))}</span></p>\n"
                f"<p>{_esc(c.get('explanation', ''))}</p>\n"
                "</div>\n"
            )

        return html

    @staticmethod
    def _reconstructed_incidents(incidents: List[Dict[str, Any]]) -> str:
        if not incidents:
            return ""

        html = "<h2>Reconstructed Incidents</h2>\n"
        for inc in incidents:
            html += (
                f"<div class='card'>\n"
                f"<h3>{_esc(inc.get('title', 'Incident'))}</h3>\n"
                f"<p>{_esc(inc.get('summary', ''))}</p>\n"
                "</div>\n"
            )
        return html

    @staticmethod
    def _limitations() -> str:
        return (
            "<h2>Limitations &amp; Disclaimers</h2>\n"
            "<div class='disclaimer'>\n<ul>\n"
            "<li>This analysis identifies statistical correlations between forensic events.</li>\n"
            "<li>Correlation does not establish causation.</li>\n"
            "<li>Results should be validated by a qualified forensic examiner.</li>\n"
            "<li>Event timestamps depend on system clock accuracy.</li>\n"
            "</ul>\n</div>"
        )

    @staticmethod
    def _footer(generated_at: str) -> str:
        return (
            f"<footer>Report generated by <strong>ForensicFusion</strong> "
            f"on {generated_at}</footer>\n</div>"
        )


# ------------------------------------------------------------------
# Module-level helpers
# ------------------------------------------------------------------

def _esc(text: Any) -> str:
    """Escape HTML special characters in *text*."""
    s = str(text) if text is not None else ""
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _badge_class(classification: str) -> str:
    """Return CSS badge class for a correlation classification string."""
    cl = classification.lower()
    if "strong" in cl:
        return "badge-strong"
    if "moderate" in cl:
        return "badge-moderate"
    if "weak" in cl:
        return "badge-weak"
    return "badge-none"
