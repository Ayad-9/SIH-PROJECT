"""
AE-Forensics: Core Detection & Analytical Pipeline
Modules for parsing, protocol authentication, geo-tracing, NLP intent classification,
VPN/proxy detection, and multi-factor mathematical scoring.
"""

from .parser import parse_email_bytes
from .auth import evaluate_protocol_auth
from .geo_tracer import trace_hops_and_origin
from .nlp_engine import analyze_semantic_intent
from .proxy_detector import detect_vpn_or_proxy
from .scorer import compute_threat_score
from .pdf_generator import generate_forensic_pdf

__all__ = [
    "parse_email_bytes",
    "evaluate_protocol_auth",
    "trace_hops_and_origin",
    "analyze_semantic_intent",
    "detect_vpn_or_proxy",
    "compute_threat_score",
    "generate_forensic_pdf",
]
