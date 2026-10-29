"""
correlation_agent.reasoning  (stage C5)
─────────────────────────────────────────────────────────────────────
From correlations to an account of the incident, without an LLM.

Attack chain
    Findings map to ATT&CK tactics. Phases are listed in ATT&CK order --
    the order an intrusion usually unfolds -- and the narrative says so.
    Where phases carry real timestamps they are compared, and every
    disagreement is listed in ``order_inversions`` instead of presenting
    the textbook order as what happened.

Hypotheses
    Always two, always competing: H1 (one coordinated intrusion) against
    H0 (independent, routine or unrelated events). H1's confidence is
    arithmetic with a written basis; H0 is its complement.
"""

from __future__ import annotations

from typing import Any

from .core.constants import DOMAINS, SEVERITY_RANK, TACTIC_ORDER, TECHNIQUE_TACTIC
from .core.entities import clamp, max_severity, round2, uniq
from .engine import format_basis


def build_attack_chain(items: list[dict[str, Any]], correlations: list[dict[str, Any]]) -> dict[str, Any]:
    phases = []
    for tactic in TACTIC_ORDER:
        members = [i for i in items if tactic in i["tactics"] and SEVERITY_RANK[i["severity"]] >= SEVERITY_RANK["low"]]
        if not members:
            continue
        refs = {m["ref"] for m in members}
        timestamps = sorted(m["timestamp_utc"] for m in members if m["timestamp_utc"])
        phases.append({
            "tactic": tactic,
            "domains": [d for d in DOMAINS if any(m["domain"] == d for m in members)],
            "evidence_refs": sorted(refs),
            "techniques": sorted(t for t in uniq(t for m in members for t in m["mitre_attack"])
                                 if TECHNIQUE_TACTIC.get(t.split(".")[0]) == tactic),
            "correlation_refs": [c["correlation_id"] for c in correlations if refs.intersection(c["evidence_refs"])],
            "first_seen_utc": timestamps[0] if timestamps else None,
            "max_severity": max_severity(m["severity"] for m in members),
        })

    timed = [p for p in phases if p["first_seen_utc"]]
    inversions = [f"{timed[i]['tactic']} is first seen before {timed[i - 1]['tactic']}"
                  for i in range(1, len(timed)) if timed[i]["first_seen_utc"] < timed[i - 1]["first_seen_utc"]]

    if not phases:
        narrative = "No finding maps to an ATT&CK tactic, so no attack chain can be proposed."
    else:
        chain = " → ".join(f"{p['tactic']} ({'/'.join(p['domains'])})" for p in phases)
        if len(timed) < 2:
            order = "Too few phases carry real timestamps to check that order against the evidence."
        elif inversions:
            order = f"Observed timestamps disagree in places: {'; '.join(inversions)}."
        else:
            order = "Where phases carry real timestamps, the observed order agrees with the ATT&CK order."
        narrative = (f"Findings map to {len(phases)} ATT&CK tactic(s): {chain}. Phases are listed in ATT&CK "
                     f"order, the order an intrusion usually unfolds, not the order observed. {order}")

    return {"phases": phases, "narrative": narrative, "order_inversions": inversions}


def build_hypotheses(chain: dict[str, Any], correlations: list[dict[str, Any]],
                     supplied: list[str]) -> list[dict[str, Any]]:
    linked = [c for c in correlations if c["link_basis"] == "shared-entity"]
    strong = [c for c in linked if c["confidence"] >= 0.6]
    phases = chain["phases"]
    cross_domain_phases = sum(1 for p in phases if len(p["domains"]) >= 2)
    non_admissible = any(c["admissible"] is False for c in correlations)
    missing = [d for d in DOMAINS if d not in supplied]

    terms: list[tuple[float, str]] = [(0.25, "base 0.25")]
    if linked:
        terms.append((min(0.30, 0.10 * len(linked)), f"{len(linked)} entity-linked correlation(s)"))
    if strong:
        terms.append((0.10, f"{len(strong)} at confidence ≥ 0.60"))
    if len(phases) >= 3:
        terms.append((min(0.15, 0.03 * len(phases)), f"{len(phases)} ATT&CK tactics covered"))
    if cross_domain_phases:
        terms.append((0.05, f"{cross_domain_phases} tactic(s) evidenced in two or more domains"))
    if chain["order_inversions"]:
        terms.append((-0.05, "observed order partly contradicts the tactic order"))
    if non_admissible:
        terms.append((-0.15, "rests partly on non-admissible evidence"))
    if missing:
        terms.append((-0.05 * len(missing), f"{len(missing)} domain(s) not supplied"))
    raw = sum(v for v, _ in terms)
    h1 = round2(clamp(raw, 0.05, 0.9))

    pivots = uniq(e["value"] for c in linked for e in c["linking_entities"] if e["strength"] != "weak")[:6]

    return [
        {
            "hypothesis_id": "H1",
            "statement": ("The findings describe one coordinated intrusion, connected through shared entities "
                          "across evidence sources." if linked else "The findings describe one coordinated intrusion."),
            "confidence": h1,
            "confidence_basis": format_basis(terms, raw, 0.9),
            "supporting": [
                *([f"{len(linked)} correlation(s) link findings through shared entities"
                   + (f": {', '.join(pivots)}." if pivots else ".")] if linked else []),
                *([f"Evidence covers {len(phases)} ATT&CK tactic(s)."] if phases else []),
            ],
            "weakening": [
                *(["No entity is shared between domains; any connection is co-occurrence only."] if not linked else []),
                *chain["order_inversions"],
                *(["Some cited evidence is not admissible."] if non_admissible else []),
                *(f"No {d} evidence was supplied." for d in missing),
            ],
        },
        {
            "hypothesis_id": "H0",
            "statement": "The findings are independent: routine activity and unrelated alerts that happen to share a case.",
            "confidence": round2(clamp(1 - h1, 0.05, 0.9)),
            "confidence_basis": "complement of H1 — the two are competing explanations, not independent estimates",
            "supporting": [
                "Every correlation lists benign alternative explanations that have not been ruled out.",
                *(["No entity links the domains."] if not linked else []),
            ],
            "weakening": [f"{c['correlation_id']}: {c['title']} ({c['confidence']})" for c in strong[:5]],
        },
    ]
