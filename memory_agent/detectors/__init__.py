"""
memory_agent.detectors
─────────────────────────────────────────────────────────────────────
Tier 3: deterministic detection.

No LLM lives here, and that is a design commitment rather than a
limitation. The correlation agent downstream does the probabilistic
reasoning; if its input were itself probabilistic, confidence values
would compound into numbers that mean nothing and no disputed finding
could be re-derived by hand.

Everything in this tier is a pure function of the observations handed to
it. Same observations, same rule pack version, same findings -- on any
machine, with no memory image present.
"""

from __future__ import annotations

from .engine import (
    CORROBORATION_BONUS,
    MAX_CORROBORATION,
    DetectionContext,
    Rule,
    RuleEngine,
    RuleHit,
    RuleOutcome,
)
from .rules import RULE_IDS, RULE_PACK

__all__ = [
    "DetectionContext", "Rule", "RuleEngine", "RuleHit", "RuleOutcome",
    "RULE_PACK", "RULE_IDS", "CORROBORATION_BONUS", "MAX_CORROBORATION",
    "default_engine",
]


def default_engine() -> RuleEngine:
    """The engine loaded with rule pack v1."""
    return RuleEngine(RULE_PACK)
