"""
correlation_agent.assess  (stage C6)
─────────────────────────────────────────────────────────────────────
Risk, the agent's confidence in its own assessment, and limitations.

    risk_score = min(40, Σ per-domain highest severity)
               + min(45, Σ correlation severity × confidence)   (non-admissible halved)
               + min(15, ATT&CK tactics × 2.5)

``confidence`` measures how much evidence the assessment stands on --
domain coverage, admissibility, timestamp coverage -- not how alarming
that evidence is.

``limitations`` is where absence is made explicit. A domain that was not
supplied, a rule that could not run, an INVALID memory envelope: each is
written out so that no consumer reads a missing correlation as "clean".
"""

from __future__ import annotations

from typing import Any, Mapping

from .core.constants import (
    CONFIDENCE_CEILING,
    CORRELATION_SEVERITY_POINTS,
    DOMAIN_SEVERITY_POINTS,
    DOMAINS,
)
from .core.entities import clamp, max_severity, round2


def assess(items: list[dict[str, Any]], correlations: list[dict[str, Any]], chain: Mapping[str, Any],
           inputs: Mapping[str, Mapping[str, Any]], supplied: list[str]) -> dict[str, Any]:
    basis: list[str] = []

    domain_pts = 0
    for d in supplied:
        sev = max_severity(i["severity"] for i in items if i["domain"] == d)
        domain_pts += DOMAIN_SEVERITY_POINTS[sev]
        basis.append(f"{d}: highest severity {sev.upper()} (+{DOMAIN_SEVERITY_POINTS[sev]})")
    if domain_pts > 40:
        basis.append(f"domain severity total {domain_pts} capped at 40")
    domain_pts = min(40, domain_pts)

    corr_pts = sum(CORRELATION_SEVERITY_POINTS[c["severity"]] * c["confidence"] * (0.5 if c["admissible"] is False else 1)
                   for c in correlations)
    corr_pts = min(45.0, corr_pts)
    halved = " (non-admissible halved)" if any(c["admissible"] is False for c in correlations) else ""
    basis.append(f"{len(correlations)} correlation(s): Σ severity × confidence{halved} = {round2(corr_pts):g} (cap 45)")

    breadth_pts = min(15.0, len(chain["phases"]) * 2.5)
    basis.append(f"{len(chain['phases'])} ATT&CK tactic(s) × 2.5 = {breadth_pts:g} (cap 15)")

    risk_score = round(clamp(domain_pts + corr_pts + breadth_pts, 0, 100))
    risk_level = "HIGH" if risk_score >= 65 else "MEDIUM" if risk_score >= 35 else "LOW"

    coverage = len(supplied) / len(DOMAINS)
    admissible_share = (sum(1 for d in supplied if inputs[d]["admissible"] is True) / len(supplied)) if supplied else 0.0
    timed_share = (sum(1 for i in items if i["timestamp_utc"]) / len(items)) if items else 0.0
    confidence = round2(clamp(coverage * 0.5 + admissible_share * 0.25 + timed_share * 0.25, 0, CONFIDENCE_CEILING))

    if any(inputs[d]["admissible"] is False for d in supplied):
        admissible: bool | None = False
    elif supplied and all(inputs[d]["admissible"] is True for d in supplied):
        admissible = True
    else:
        admissible = None

    return {
        "risk_level": risk_level,
        "risk_score": risk_score,
        "risk_basis": basis,
        "confidence": confidence,
        "confidence_basis": (f"domain coverage {len(supplied)}/4 × 0.50 + admissible domains "
                             f"{round2(admissible_share):g} × 0.25 + timestamped findings {round2(timed_share):g} × 0.25"),
        "admissible": admissible,
    }


def build_limitations(inputs: Mapping[str, Mapping[str, Any]], supplied: list[str],
                      not_evaluated: list[dict[str, str]], errored: list[dict[str, str]],
                      memory: Mapping[str, Any] | None, items: list[dict[str, Any]],
                      input_notes: list[str]) -> list[str]:
    out: list[str] = list(input_notes)
    if len(supplied) < 2:
        out.append("Fewer than two evidence domains were supplied, so no cross-domain correlation is possible. "
                   "The result describes the single domain only.")
    for d in DOMAINS:
        if d not in supplied:
            out.append(f"No {d} evidence was supplied. Correlations that need it were NOT evaluated; their "
                       "absence is not evidence that the activity did not occur.")
    out += [f"{r['rule_id']} ({r['title']}) was not evaluated: {r['reason']}." for r in not_evaluated]
    out += [f"{r['rule_id']} raised an error and produced no output: {r['error']}." for r in errored]

    if "memory" in supplied and inputs["memory"]["admissible"] is False:
        replay = " (demo replay of captured plugin output)" if (memory or {}).get("mode") == "replay" else ""
        out.append(f"The memory envelope is {(memory or {}).get('status') or 'INVALID'}{replay}. Correlations "
                   "citing memory findings are marked admissible: false and their confidence is reduced.")
    out += [f"[memory agent] {l}" for l in ((memory or {}).get("limitations") or [])[:5]]
    skew = (memory or {}).get("clock_skew_seconds")
    if "memory" in supplied and not isinstance(skew, (int, float)):
        out.append("Memory clock skew is unknown; cross-domain ordering assumes every source reports true UTC.")
    if "log" in supplied and "syslog" in str((inputs["log"]["meta"] or {}).get("format", "")).lower():
        out.append("Syslog timestamps carry no year or zone; the log agent inferred them, so log times may be "
                   "offset from other sources.")
    if "network" in supplied:
        if not any(i["timestamp_utc"] for i in items if i["domain"] == "network"):
            out.append("Network findings carry no timestamps, so network activity cannot be placed on the unified "
                       "timeline; network correlations rest on shared entities only.")
        out.append("The network agent reports one finding per type and address; packet counts, ports and flow "
                   "tuples are not available to correlate on.")
    if "disk" in supplied and not any(i["timestamp_utc"] for i in items if i["domain"] == "disk"):
        out.append("Disk findings carry no MAC times, so file-system activity cannot be placed on the unified timeline.")
    if len(supplied) >= 2:
        out.append("The agent cannot verify that every source comes from the same host and incident window; it "
                   "assumes so. A correlation between evidence from different hosts is meaningless.")
    return out
