"""
ForensicFusion Core Module
==========================

Exports the main engine components for multi-source digital forensic
evidence parsing, normalisation, integrity verification, correlation,
and visualisation.
"""

from core.parser import (
    LogParser,
    AuthenticationParser,
    AuditParser,
    FileActivityParser,
    ParserFactory,
)
from core.normalizer import normalize_timestamp, normalize_events
from core.integrity import calculate_sha256, create_evidence_record
from core.correlation import CorrelationEngine
from core.baseline import BaselineCorrelation
from core.graph_engine import (
    build_correlation_graph,
    find_event_groups,
    reconstruct_incident,
    generate_plotly_graph,
)

__all__ = [
    # parser
    "LogParser",
    "AuthenticationParser",
    "AuditParser",
    "FileActivityParser",
    "ParserFactory",
    # normalizer
    "normalize_timestamp",
    "normalize_events",
    # integrity
    "calculate_sha256",
    "create_evidence_record",
    # correlation
    "CorrelationEngine",
    # baseline
    "BaselineCorrelation",
    # graph_engine
    "build_correlation_graph",
    "find_event_groups",
    "reconstruct_incident",
    "generate_plotly_graph",
]
