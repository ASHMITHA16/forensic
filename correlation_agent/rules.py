"""
correlation_agent.rules  (rule pack COR-v1)
─────────────────────────────────────────────────────────────────────
Eight correlation rules. Each states which domains it joins, which
entity types it may link on, its base confidence, the adjustments it
applies, and -- mandatory -- the benign explanations that remain open.

Three kinds:

  pair          fires once per shared entity between two named domains
  cooccurrence  joins two domains with NO shared entity, and says so
  pivot         one entity seen in three or more domains

``Side`` is a mapping domain -> evidence items of that domain within
the candidate correlation; bonus functions receive it and return
``(value, reason)`` terms that go verbatim into ``confidence_basis``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable

from .core.constants import SEVERITY_RANK

Side = dict[str, list[dict[str, Any]]]
Term = tuple[float, str]


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    kind: str                       # pair | cooccurrence | pivot
    category: str
    base: float
    interpretation: Callable[[dict[str, Any]], str]
    alternatives: tuple[str, ...]
    action: str
    domains: tuple[str, ...] = ()
    entity_types: tuple[str, ...] = ()
    min_domains: int = 0
    mitre: tuple[str, ...] = ()
    version: str = "1.0"
    bonuses: Callable[[Side], list[Term]] = field(default=lambda side: [])
    title_for: Callable[[Side], str | None] = field(default=lambda side: None)
    extra_mitre: Callable[[Side], list[str]] = field(default=lambda side: [])
    select: Callable[[Side], Side] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.id, "version": self.version, "title": self.title, "kind": self.kind,
            "category": self.category, "domains": list(self.domains),
            "entity_types": list(self.entity_types), "min_domains": self.min_domains or None,
            "base_confidence": self.base, "mitre_attack": list(self.mitre),
            "alternative_explanations": list(self.alternatives),
        }


def _types(items: list[dict[str, Any]]) -> list[str]:
    return [i["type"] for i in items]


def _any_at_least(items: list[dict[str, Any]], severity: str) -> bool:
    return any(SEVERITY_RANK[i["severity"]] >= SEVERITY_RANK[severity] for i in items)


# ── bonus functions ───────────────────────────────────────────────────


def _cor001_bonus(side: Side) -> list[Term]:
    out: list[Term] = []
    types = _types(side["network"])
    if "Known Malicious IP" in types:
        out.append((0.15, "network agent matched the address to threat intelligence"))
    if "Beaconing Activity" in types:
        out.append((0.10, "network agent observed repeated traffic to the address (beaconing)"))
    return out


def _cor002_bonus(side: Side) -> list[Term]:
    out: list[Term] = []
    if any(i["deleted"] for i in side["disk"]):
        out.append((0.15, "the disk copy is deleted while the image is still loaded in memory"))
    if _any_at_least(side["memory"], "critical"):
        out.append((0.05, "a memory finding on the process is CRITICAL"))
    return out


def _cor003_bonus(side: Side) -> list[Term]:
    out: list[Term] = []
    log_types = _types(side["log"])
    if "Brute Force Activity" in log_types:
        out.append((0.15, "logs show a brute-force burst from the address"))
    elif any(re.search(r"Failed Login|Unauthorized", t) for t in log_types):
        out.append((0.10, "logs show failed or unauthorised access from the address"))
    net_types = _types(side["network"])
    if "Potential Port Scan" in net_types:
        out.append((0.10, "network agent saw the address scanning ports"))
    if "Known Malicious IP" in net_types:
        out.append((0.10, "network agent matched the address to threat intelligence"))
    return out


def _cor004_bonus(side: Side) -> list[Term]:
    out: list[Term] = []
    if any(re.search(r"Suspicious Command|Malware|Persistence", t) for t in _types(side["log"])):
        out.append((0.10, "the log event is itself a suspicious-command, persistence or malware detection"))
    if _any_at_least(side["memory"], "high"):
        out.append((0.05, "the memory finding on that program is HIGH or above"))
    return out


def _cor006_bonus(side: Side) -> list[Term]:
    out: list[Term] = []
    if any(i["deleted"] for i in side["disk"]):
        out.append((0.10, "the file has since been deleted"))
    if any(re.search(r"Persistence|Suspicious Command|Malware", t) for t in _types(side["log"])):
        out.append((0.10, "the log event is a persistence, suspicious-command or malware detection"))
    return out


def _cor007_select(by_domain: Side) -> Side:
    return {
        "log": [i for i in by_domain["log"] if i["type"] == "Log Tampering"],
        "disk": [i for i in by_domain["disk"] if i["deleted"] and SEVERITY_RANK[i["severity"]] >= SEVERITY_RANK["high"]],
    }


# ── the pack ──────────────────────────────────────────────────────────

RULE_PACK: tuple[Rule, ...] = (
    Rule(
        id="COR-001", kind="pair", domains=("memory", "network"), entity_types=("ip", "domain"),
        title="Network activity attributable to a process in memory",
        category="command_and_control", base=0.55, mitre=("T1071",),
        bonuses=_cor001_bonus,
        interpretation=lambda c: (
            f"Traffic to {c['entity_text']} in the capture is plausibly generated by "
            f"{c['memory_processes'] or 'the process(es) named in the memory finding'} "
            "— consistent with command-and-control or payload retrieval."),
        alternatives=(
            "The address belongs to shared hosting, a CDN or a NAT gateway, so the same IP can serve unrelated traffic.",
            "The capture and the memory image may come from different hosts or different time windows; a shared address does not by itself prove they observed the same connection.",
            "Legitimate software (updaters, telemetry) can talk to the same infrastructure.",
        ),
        action="Confirm the capture and memory image are from the same host and window, then match socket tuples (local port, PID) in the memory netscan against the flows in the capture.",
    ),
    Rule(
        id="COR-002", kind="pair", domains=("disk", "memory"), entity_types=("path", "image"),
        title="Executable on disk is resident in memory",
        category="execution", base=0.50, mitre=("T1204",),
        bonuses=_cor002_bonus,
        title_for=lambda side: "Running process backed by a deleted file" if any(i["deleted"] for i in side["disk"]) else None,
        extra_mitre=lambda side: ["T1070.004"] if any(i["deleted"] for i in side["disk"]) else [],
        interpretation=lambda c: (
            f"{c['entity_text']} was written to disk and is executing or mapped in memory, tying the "
            "file-system artifact to live activity"
            + ("; deleting the file while it runs is a common anti-forensic step" if c["any_deleted"] else "")
            + "."),
        alternatives=(
            "Two unrelated files can share a name; a name match without a full-path match is weaker.",
            "An installer or updater may delete its own temporary copy after launching.",
            "The disk image and the memory image may not be from the same host.",
        ),
        action="Recover the file (icat on the MFT entry), hash it, and compare against the image dumped from memory (windows.pslist --dump / dlllist --dump).",
    ),
    Rule(
        id="COR-003", kind="pair", domains=("log", "network"), entity_types=("ip", "domain"),
        title="Same address in system logs and network traffic",
        category="initial_access", base=0.45,
        bonuses=_cor003_bonus,
        interpretation=lambda c: (
            f"The host at {c['entity_text']} that appears in the logs is also active in the capture; "
            "together they describe one actor's reconnaissance and access attempts rather than two separate events."),
        alternatives=(
            "A scanner or monitoring system legitimately probes and logs in to many hosts.",
            "Users behind one NAT address share it; the log entries and the traffic may be different people.",
        ),
        action="Line up the log timestamps against the capture for this address and check whether a successful logon follows the failures.",
    ),
    Rule(
        id="COR-004", kind="pair", domains=("log", "memory"), entity_types=("image", "path"),
        title="Program named in logs is resident in memory",
        category="execution", base=0.45, mitre=("T1059",),
        bonuses=_cor004_bonus,
        interpretation=lambda c: (
            f"{c['entity_text']} is recorded in the logs and is running in memory, linking the logged "
            "action to the live process the memory agent flagged."),
        alternatives=(
            "The program name is generic, so the log entry may describe a different instance.",
            "The log event may predate the process by days; check the timestamps.",
        ),
        action="Compare the logged command line with windows.cmdline for the PID, and the log time with the process create time.",
    ),
    Rule(
        id="COR-005", kind="pair", domains=("log", "memory"), entity_types=("ip", "domain"),
        title="Address in logs matches a memory network artifact",
        category="command_and_control", base=0.45, mitre=("T1071",),
        interpretation=lambda c: (
            f"{c['entity_text']} is recorded in the logs and is held by {c['memory_processes'] or 'a process'} "
            "in memory, suggesting the logged access and the live connection are the same activity."),
        alternatives=(
            "Logs routinely record addresses of benign peers (update servers, DNS).",
            "The address may have been reassigned between the logged event and the memory capture.",
        ),
        action="Check which process owned the socket (windows.netscan) and whether the logged event used the same port.",
    ),
    Rule(
        id="COR-006", kind="pair", domains=("log", "disk"), entity_types=("path", "image", "file"),
        title="File referenced in logs is present on disk",
        category="persistence", base=0.45,
        bonuses=_cor006_bonus,
        interpretation=lambda c: (
            f"The file {c['entity_text']} that the logs refer to exists on disk, connecting the logged "
            "action to a concrete artifact."),
        alternatives=(
            "The log may mention a file that a legitimate tool created or scanned.",
            "A name-only match may refer to a different file with the same name.",
        ),
        action="Pull the file's MAC times from the MFT and check they bracket the log event.",
    ),
    Rule(
        id="COR-007", kind="cooccurrence", domains=("log", "disk"),
        title="Anti-forensic activity in more than one domain",
        category="defense_evasion", base=0.35, mitre=("T1070",),
        select=_cor007_select,
        interpretation=lambda c: (
            "Log clearing and deletion of executables or scripts both occurred; together they are "
            "consistent with an attacker removing traces."),
        alternatives=(
            "Routine log rotation or an administrator clearing logs is common.",
            "Deleted files are normal on any used file system; this correlation rests on co-occurrence, not on a shared entity.",
        ),
        action="Establish who cleared the logs (event 1102 / 104) and when, and compare with the deleted files' MFT timestamps.",
    ),
    Rule(
        id="COR-008", kind="pivot", min_domains=3,
        title="Entity observed across multiple evidence domains",
        category="pivot", base=0.55,
        interpretation=lambda c: (
            f"{c['entity_text']} is the common thread across {', '.join(c['domains'])} evidence and is "
            "the strongest pivot for scoping the incident."),
        alternatives=(
            "Widely shared infrastructure or a generic name can surface in several sources without a common cause.",
        ),
        action="Use this entity as the starting point for scoping: search every source for it and build its full activity history.",
    ),
)


def list_rules() -> list[dict[str, Any]]:
    return [r.to_dict() for r in RULE_PACK]
