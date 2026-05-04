"""Agent Blackbox: JEP/HJS/JAC runtime trace recorder."""

from .core import AgentBlackbox, TraceRecord, IncidentReview
from .jep import JEPEvent, Verb, JAC_CHAIN_EXT

# Backward-compatible alias for older examples.
BlameFinder = AgentBlackbox

__all__ = [
    "AgentBlackbox",
    "BlameFinder",
    "TraceRecord",
    "IncidentReview",
    "JEPEvent",
    "Verb",
    "JAC_CHAIN_EXT",
]
