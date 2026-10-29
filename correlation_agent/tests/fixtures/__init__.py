"""
Fixture corpus.

``demo_case`` is captured output of the log, network and disk agents for
the same synthetic Windows incident the memory agent's ``windows_case``
replay describes (host WS01, user jdoe). It is built to trigger every
rule in pack COR-v1 *and* to contain look-alikes the rules must survive:
``mimikatz.exe`` exists only on disk and must stay unlinked, and
Chrome's connection to Google must rank last.

``log.json`` is the Node log agent's output for ``security.log``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

FIXTURE_ROOT = Path(__file__).resolve().parent
DEMO_CASE = FIXTURE_ROOT / "demo_case"


def load(name: str) -> Any:
    return json.loads((DEMO_CASE / name).read_text(encoding="utf-8"))


# Memory findings in the raw memory_agent_output.json shape
MEM_C2 = {
    "finding_id": "FND-0010", "rule_id": "MEM-N-001", "title": "Established connection to an external host",
    "severity": "MEDIUM", "confidence": 0.55, "first_seen_utc": "2026-04-12T02:18:09Z",
    "entities": {"pids": [2456], "processes": ["data_transfer.exe"], "ips": ["185.77.22.90"], "ports": [4444]},
    "observation_statement": "PID 2456 (data_transfer.exe) holds an ESTABLISHED TCP socket to 185.77.22.90:4444.",
    "interpretation": "Outbound connection to a public address.",
    "alternative_explanations": ["Legitimate application traffic."], "mitre_attack": ["T1071"],
}
MEM_HOLLOW = {
    "finding_id": "FND-0007", "rule_id": "MEM-I-003", "title": "Process hollowing indicator",
    "severity": "CRITICAL", "confidence": 0.8, "first_seen_utc": None,
    "entities": {"pids": [3600], "processes": ["stage2.exe"],
                 "files": [r"C:\Users\jdoe\AppData\Roaming\stage2.exe"]},
    "observation_statement": "VAD-backed path differs from EPROCESS image path for PID 3600.",
    "interpretation": "Hollowing.", "alternative_explanations": ["Packed binary."], "mitre_attack": ["T1055.012"],
}
VALID_MEMORY_ENVELOPE = {
    "schema_version": "1.0.0",
    "agent": {"status": "COMPLETE", "status_basis": "Evidence verified."},
    "integrity": {"integrity_verified": True},
    "environment": {"clock_skew_seconds": 0},
    "findings": [MEM_C2, MEM_HOLLOW],
    "timeline": [], "limitations": [],
    "evidence": {"hashes": {"sha256_before": "ab" * 32}},
}


def memory(*findings: dict[str, Any], **agent: Any) -> dict[str, Any]:
    """A memory input built from an envelope with the given findings."""
    env = json.loads(json.dumps(VALID_MEMORY_ENVELOPE))
    env["findings"] = list(findings)
    env["agent"].update(agent)
    return {"envelope": env}
