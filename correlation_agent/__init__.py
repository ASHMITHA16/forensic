"""
Correlation & Reasoning Agent
─────────────────────────────────────────────────────────────────────
The downstream consumer named in memory_agent/docs/DESIGN.md: takes the
outputs of the log, network, memory and disk agents and works out which
findings describe the same activity.

    C1 normalise   findings -> evidence items        normalise.py
    C2 link        shared entities across domains    linking.py
    C3 correlate   rule pack COR-v1                  rules.py, engine.py
    C4 timeline    real timestamps only              timeline.py
    C5 reason      ATT&CK chain + H1 / H0            reasoning.py
    C6 assess      risk, confidence, limitations     assess.py

Zero third-party dependencies and no LLM. AutoGen is reached only
through autogen_adapter.py. See docs/DESIGN.md.
"""

from .core.constants import AGENT_NAME, AGENT_VERSION, RULE_PACK_VERSION, SCHEMA_VERSION
from .correlate import run_correlation

__all__ = ["AGENT_NAME", "AGENT_VERSION", "RULE_PACK_VERSION", "SCHEMA_VERSION", "run_correlation"]
__version__ = AGENT_VERSION
