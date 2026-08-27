"""
memory_agent.detectors.rules
─────────────────────────────────────────────────────────────────────
Rule pack v1 -- seventeen rules across six artifact families.

The pack is versioned as a whole (``RULE_PACK_VERSION`` in
``core.schema``) and each rule carries its own ``version``. Both appear
in the output envelope, so a finding can always be traced to the exact
logic that produced it. Changing a threshold means changing a rule
version; that is the contract that makes "same dump + same rule pack ⇒
same findings" a checkable claim rather than a slogan.

Coverage by family:

    process     MEM-P-001 .. MEM-P-006    hiding, masquerading, lineage
    injection   MEM-I-001 .. MEM-I-003    injected code, unlinked modules,
                                          hollowing
    network     MEM-N-001 .. MEM-N-003    external connections, listeners,
                                          tooling ports
    command     MEM-C-001 .. MEM-C-003    obfuscated PowerShell, LOLBins,
                                          discovery
    module      MEM-M-001                 hidden kernel modules
    service     MEM-S-001                 persistence via service binary
"""

from __future__ import annotations

from ..engine import Rule
from .command import RULES as COMMAND_RULES
from .injection import RULES as INJECTION_RULES
from .module import RULES as MODULE_RULES
from .network import RULES as NETWORK_RULES
from .process import RULES as PROCESS_RULES

RULE_PACK: tuple[Rule, ...] = (
    *PROCESS_RULES,
    *INJECTION_RULES,
    *NETWORK_RULES,
    *COMMAND_RULES,
    *MODULE_RULES,
)

RULE_IDS: tuple[str, ...] = tuple(sorted(rule.rule_id for rule in RULE_PACK))

__all__ = ["RULE_PACK", "RULE_IDS", "Rule"]
