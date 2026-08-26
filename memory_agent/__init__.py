"""
Memory Analysis Agent
─────────────────────────────────────────────────────────────────────
A modular, evidence-integrity-first memory dump analysis agent for the
AI-based multi-agent digital forensics framework.

Architecture (see docs/DESIGN.md):

    TIER 1  acquisition & execution   -- seals evidence, runs Volatility
    TIER 2  normalisation             -- plugin rows -> observations
    TIER 3  detection & synthesis     -- rules -> findings, timeline, IOCs

Tier 1 never interprets. Tier 3 never touches the dump.

This package has no dependency on AutoGen, on any LLM, or on the Node
backend. It is driven from the command line and, from Phase 6, from a
thin AutoGen adapter.
"""

from .verify import AGENT_NAME, AGENT_VERSION, SCHEMA_VERSION, run_verify

__all__ = ["AGENT_NAME", "AGENT_VERSION", "SCHEMA_VERSION", "run_verify"]
__version__ = AGENT_VERSION
