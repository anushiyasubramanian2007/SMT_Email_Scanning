"""
PhishingGuard Correlation & Threat Intelligence Subpackage
"""
from app.correlation.attribution import attribute_threat_origin
from app.correlation.graph import build_case_graph, build_single_forensic_graph
from app.correlation.engine import (
    extract_indicators_from_analysis,
    record_and_correlate_email,
    create_case,
    list_cases,
    get_case_by_id,
    update_case
)
