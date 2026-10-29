"""
correlation_agent.core.schema
─────────────────────────────────────────────────────────────────────
THE CONTRACT -- validated by hand, zero dependencies (as the memory
agent does, DESIGN §8.1).

Besides shape, it enforces the properties the design depends on:

* every correlation cites evidence that exists in the envelope,
* ``alternative_explanations`` is never empty,
* confidence never exceeds the 0.95 ceiling,
* a co-occurrence correlation claims no linking entity and a
  shared-entity correlation names at least one,
* no timeline event lacks a real timestamp, and no evidence item claims
  a precision its timestamp does not support,
* every domain that was not supplied is named in ``limitations``.
"""

from __future__ import annotations

from typing import Any, Mapping

from .constants import CONFIDENCE_CEILING, DOMAINS, SEVERITIES

REQUIRED_TOP = (
    "schema_version", "agent", "case", "rule_pack", "window_seconds", "inputs", "evidence_items",
    "entity_links", "correlations", "attack_chain", "hypotheses", "timeline", "untimed_findings",
    "assessment", "coverage", "limitations", "summary",
)
REQUIRED_CORRELATION = (
    "correlation_id", "rule_id", "rule_version", "title", "category", "severity", "confidence",
    "confidence_basis", "link_basis", "domains", "linking_entities", "evidence_refs", "mitre_attack",
    "admissible", "observation_statement", "interpretation", "alternative_explanations", "analyst_action",
)
STATUSES = ("COMPLETE", "PARTIAL", "INSUFFICIENT")


def validate_correlation(c: Mapping[str, Any], known_refs: set[str]) -> list[str]:
    cid = c.get("correlation_id", "?")
    problems = [f"{cid}: missing field '{k}'" for k in REQUIRED_CORRELATION if k not in c]
    if problems:
        return problems
    if not c["alternative_explanations"]:
        problems.append(f"{cid}: alternative_explanations is empty")
    if not 0.0 <= c["confidence"] <= CONFIDENCE_CEILING:
        problems.append(f"{cid}: confidence {c['confidence']} outside [0, {CONFIDENCE_CEILING}]")
    if c["severity"] not in SEVERITIES:
        problems.append(f"{cid}: unknown severity {c['severity']!r}")
    if not c["evidence_refs"]:
        problems.append(f"{cid}: cites no evidence")
    missing = [r for r in c["evidence_refs"] if r not in known_refs]
    if missing:
        problems.append(f"{cid}: cites evidence not in the envelope: {', '.join(missing[:5])}")
    if c["link_basis"] == "co-occurrence" and c["linking_entities"]:
        problems.append(f"{cid}: a co-occurrence correlation must not claim linking entities")
    if c["link_basis"] == "shared-entity" and not c["linking_entities"]:
        problems.append(f"{cid}: a shared-entity correlation names no entity")
    if c["link_basis"] not in ("co-occurrence", "shared-entity"):
        problems.append(f"{cid}: unknown link_basis {c['link_basis']!r}")
    if c["admissible"] not in (True, False, None):
        problems.append(f"{cid}: admissible must be true, false or null")
    return problems


def validate_envelope(env: Mapping[str, Any]) -> list[str]:
    """Every way ``env`` breaks the contract; an empty list means valid."""
    problems = [f"missing top-level field '{k}'" for k in REQUIRED_TOP if k not in env]
    if problems:
        return problems

    if env["agent"].get("status") not in STATUSES:
        problems.append(f"agent.status {env['agent'].get('status')!r} not in {STATUSES}")

    refs = set()
    for item in env["evidence_items"]:
        refs.add(item.get("ref"))
        has_time = bool(item.get("timestamp_utc"))
        if has_time != (item.get("precision") == "exact"):
            problems.append(f"{item.get('ref')}: precision {item.get('precision')!r} does not match its timestamp")

    for c in env["correlations"]:
        problems += validate_correlation(c, refs)

    for e in env["timeline"]:
        if not e.get("timestamp_utc"):
            problems.append(f"{e.get('event_id')}: timeline event without a timestamp")
        if e.get("precision") not in ("exact", "approximate"):
            problems.append(f"{e.get('event_id')}: precision {e.get('precision')!r} may not be placed on the timeline")

    a = env["assessment"]
    if a.get("risk_level") not in ("LOW", "MEDIUM", "HIGH"):
        problems.append(f"assessment.risk_level {a.get('risk_level')!r} invalid")
    if not 0.0 <= a.get("confidence", -1) <= CONFIDENCE_CEILING:
        problems.append("assessment.confidence outside [0, 0.95]")

    if [h.get("hypothesis_id") for h in env["hypotheses"]] != ["H1", "H0"]:
        problems.append("hypotheses must be exactly H1 and H0")

    limitations = " ".join(env["limitations"])
    for d in DOMAINS:
        if not env["inputs"].get(d, {}).get("supplied") and f"No {d} evidence was supplied" not in limitations:
            problems.append(f"domain '{d}' was not supplied but limitations do not say so")
    return problems
