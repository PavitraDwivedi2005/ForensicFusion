"""
ForensicFusion — Event Graph & Visualisation
=============================================

Builds a NetworkX graph from correlated events and provides:

* Connected-component detection to identify incident clusters.
* Chronological incident reconstruction.
* Interactive Plotly network-graph visualisation.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

import networkx as nx
import plotly.graph_objects as go
from dateutil import parser as dateutil_parser


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Colour palette for node source types
_SOURCE_COLOURS: Dict[str, str] = {
    "authentication": "#4A90D9",   # blue
    "audit": "#E8923F",            # orange
    "file_activity": "#5CB85C",    # green
}
_DEFAULT_COLOUR: str = "#888888"


def _parse_ts(event: dict) -> Optional[datetime]:
    """Best-effort timestamp parse."""
    for key in ("normalized_timestamp", "timestamp"):
        raw = event.get(key)
        if raw:
            try:
                dt = dateutil_parser.parse(str(raw))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt
            except (ValueError, OverflowError):
                continue
    return None


def _event_label(event: dict) -> str:
    """Short human-readable label for an event node."""
    eid = event.get("event_id", "?")
    src = event.get("source_type", "?")
    etype = event.get("event_type") or event.get("action") or ""
    return f"{eid}\n({src}: {etype})"


# ---------------------------------------------------------------------------
# Graph construction
# ---------------------------------------------------------------------------

def build_correlation_graph(
    events: List[dict],
    correlations: List[dict],
    min_score: int = 30,
) -> nx.Graph:
    """Build a NetworkX graph from events and their correlations.

    Parameters
    ----------
    events:
        Standardised, normalised event dicts.
    correlations:
        Correlation result dicts (from
        :pymeth:`CorrelationEngine.correlate_all`).
    min_score:
        Minimum ``total_score`` required to add an edge.

    Returns
    -------
    nx.Graph
        Undirected graph. Each node has event attributes; each edge
        carries ``weight`` (score) and ``explanation``.
    """
    G = nx.Graph()

    # Build an index for quick look-up
    event_index: Dict[str, dict] = {}
    for ev in events:
        eid = ev.get("event_id")
        if eid is not None:
            event_index[eid] = ev

    # Add edges (and their endpoint nodes) for qualifying correlations
    for corr in correlations:
        score = corr.get("total_score", 0)
        if score < min_score:
            continue

        aid = corr["event_a_id"]
        bid = corr["event_b_id"]

        # Ensure nodes exist with event attributes
        for nid in (aid, bid):
            if nid not in G:
                ev = event_index.get(nid, {})
                G.add_node(
                    nid,
                    event_id=nid,
                    source_type=ev.get("source_type", "unknown"),
                    timestamp=ev.get("normalized_timestamp", ev.get("timestamp", "")),
                    event_type=ev.get("event_type", ""),
                    username=ev.get("username", ""),
                    label=_event_label(ev) if ev else nid,
                )

        G.add_edge(
            aid,
            bid,
            weight=score,
            classification=corr.get("classification", ""),
            explanation=corr.get("explanation_text", ""),
        )

    return G


# ---------------------------------------------------------------------------
# Group detection
# ---------------------------------------------------------------------------

def find_event_groups(graph: nx.Graph) -> List[List[str]]:
    """Identify clusters of related events via connected components.

    Parameters
    ----------
    graph:
        Graph produced by :func:`build_correlation_graph`.

    Returns
    -------
    list[list[str]]
        Each inner list contains the ``event_id`` strings of one
        connected component, sorted alphabetically.
    """
    components = nx.connected_components(graph)
    return [sorted(list(comp)) for comp in components]


# ---------------------------------------------------------------------------
# Incident reconstruction
# ---------------------------------------------------------------------------

def reconstruct_incident(
    events: List[dict],
    event_ids: List[str],
    correlations: List[dict],
) -> dict:
    """Reconstruct a chronological incident from a group of event IDs.

    Parameters
    ----------
    events:
        Full list of standardised events.
    event_ids:
        Event IDs belonging to one incident group (e.g. from
        :func:`find_event_groups`).
    correlations:
        Full list of correlation results.

    Returns
    -------
    dict
        ``{ events, relationships, summary }``

        * **events** — chronologically sorted event dicts.
        * **relationships** — list of dicts describing the link between
          consecutive events.
        * **summary** — human-readable incident summary string.
    """
    id_set = set(event_ids)

    # Gather matching events
    group_events = [ev for ev in events if ev.get("event_id") in id_set]

    # Sort chronologically
    def _sort_key(ev: dict) -> str:
        dt = _parse_ts(ev)
        return dt.isoformat() if dt else ""

    group_events.sort(key=_sort_key)

    # Index correlations by pair key for quick look-up
    corr_index: Dict[Tuple[str, str], dict] = {}
    for c in correlations:
        key = tuple(sorted([c["event_a_id"], c["event_b_id"]]))
        corr_index[key] = c  # type: ignore[assignment]

    # Build relationships between consecutive events
    relationships: List[dict] = []
    for i in range(len(group_events) - 1):
        ev_curr = group_events[i]
        ev_next = group_events[i + 1]
        key = tuple(sorted([
            ev_curr.get("event_id", ""),
            ev_next.get("event_id", ""),
        ]))
        corr = corr_index.get(key)  # type: ignore[arg-type]
        relationships.append(
            {
                "from_event": ev_curr.get("event_id"),
                "to_event": ev_next.get("event_id"),
                "score": corr.get("total_score") if corr else None,
                "classification": corr.get("classification") if corr else None,
                "explanation": (corr.get("explanation_text") or corr.get("explanation")) if corr else "No direct correlation",
            }
        )

    # Build summary
    n_events = len(group_events)
    source_types = sorted({ev.get("source_type", "?") for ev in group_events})
    usernames = sorted({ev.get("username", "?") for ev in group_events if ev.get("username")})

    summary_parts = [
        f"Incident group of {n_events} event(s) spanning source types: "
        f"{', '.join(source_types)}.",
    ]
    if usernames:
        summary_parts.append(f"Involved user(s): {', '.join(usernames)}.")
    if group_events:
        first_ts = group_events[0].get("normalized_timestamp", group_events[0].get("timestamp", "?"))
        last_ts = group_events[-1].get("normalized_timestamp", group_events[-1].get("timestamp", "?"))
        summary_parts.append(f"Time span: {first_ts} → {last_ts}.")

    return {
        "events": group_events,
        "relationships": relationships,
        "summary": " ".join(summary_parts),
    }


# ---------------------------------------------------------------------------
# Plotly visualisation
# ---------------------------------------------------------------------------

def generate_plotly_graph(
    graph: nx.Graph,
    events: List[dict],
) -> go.Figure:
    """Create an interactive Plotly network-graph figure.

    Parameters
    ----------
    graph:
        NetworkX graph (from :func:`build_correlation_graph`).
    events:
        Full list of standardised event dicts (used for colour mapping).

    Returns
    -------
    plotly.graph_objects.Figure
    """
    if graph.number_of_nodes() == 0:
        fig = go.Figure()
        fig.update_layout(
            title="Event Correlation Graph (no data)",
            annotations=[
                dict(
                    text="No correlated events to display.",
                    showarrow=False,
                    xref="paper", yref="paper",
                    x=0.5, y=0.5,
                    font=dict(size=18),
                )
            ],
        )
        return fig

    # Spring layout
    pos = nx.spring_layout(graph, seed=42, k=1.5)

    # --- Edge traces ---
    edge_traces: List[go.Scatter] = []
    for u, v, data in graph.edges(data=True):
        x0, y0 = pos[u]
        x1, y1 = pos[v]
        weight = data.get("weight", 30)
        # Map score to line width (1–6) and opacity (0.3–1.0)
        norm_weight = max(0, min(weight, 100)) / 100.0
        line_width = 1 + 5 * norm_weight
        opacity = 0.3 + 0.7 * norm_weight

        edge_traces.append(
            go.Scatter(
                x=[x0, x1, None],
                y=[y0, y1, None],
                mode="lines",
                line=dict(
                    width=line_width,
                    color=f"rgba(136,136,136,{opacity})",
                ),
                hoverinfo="text",
                text=f"{u} ↔ {v}<br>Score: {weight:.0f} ({data.get('classification', '')})",
                showlegend=False,
            )
        )

    # --- Node trace ---
    # Build look-up for source_type
    event_index: Dict[str, dict] = {ev["event_id"]: ev for ev in events if "event_id" in ev}

    node_x, node_y, node_text, node_color, node_hover = [], [], [], [], []
    for node in graph.nodes():
        x, y = pos[node]
        node_x.append(x)
        node_y.append(y)
        node_data = graph.nodes[node]
        source_type = node_data.get("source_type", "unknown")
        node_color.append(_SOURCE_COLOURS.get(source_type, _DEFAULT_COLOUR))
        label = node_data.get("label", node)
        node_text.append(label)
        hover = (
            f"<b>{node}</b><br>"
            f"Type: {source_type}<br>"
            f"Event: {node_data.get('event_type', '')}<br>"
            f"User: {node_data.get('username', 'N/A')}<br>"
            f"Time: {node_data.get('timestamp', '')}"
        )
        node_hover.append(hover)

    node_trace = go.Scatter(
        x=node_x,
        y=node_y,
        mode="markers+text",
        marker=dict(
            size=20,
            color=node_color,
            line=dict(width=2, color="white"),
        ),
        text=node_text,
        textposition="top center",
        textfont=dict(size=9),
        hoverinfo="text",
        hovertext=node_hover,
        showlegend=False,
    )

    # --- Legend traces (one per source type) ---
    legend_traces: List[go.Scatter] = []
    seen_types = set()
    for node in graph.nodes():
        st = graph.nodes[node].get("source_type", "unknown")
        if st not in seen_types:
            seen_types.add(st)
            legend_traces.append(
                go.Scatter(
                    x=[None], y=[None],
                    mode="markers",
                    marker=dict(
                        size=12,
                        color=_SOURCE_COLOURS.get(st, _DEFAULT_COLOUR),
                    ),
                    name=st,
                    showlegend=True,
                )
            )

    # --- Assemble figure ---
    fig = go.Figure(data=edge_traces + [node_trace] + legend_traces)

    fig.update_layout(
        title=dict(text="ForensicFusion — Event Correlation Graph", font=dict(size=16)),
        showlegend=True,
        hovermode="closest",
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        plot_bgcolor="white",
        margin=dict(l=20, r=20, t=50, b=20),
    )

    return fig
