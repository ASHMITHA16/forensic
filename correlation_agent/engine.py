"""
correlation_agent.engine  (stage C3)
─────────────────────────────────────────────────────────────────────
Runs the rule pack over the entity links and produces correlations.

Confidence is arithmetic, never learned:

    confidence = clamp(base + Σ adjustments, 0.0, 0.95)

and every term is written into ``confidence_basis`` in plain text. A
reviewer can disagree with a weight; they cannot be unsure what was done.

Each correlation keeps the four-field split the memory agent uses:
``observation_statement`` (facts, citing evidence refs),
``interpretation`` (a hypothesis), ``alternative_explanations`` (never
empty) and ``analyst_action``.

Rules are isolated: one that raises is recorded in ``rules_errored`` and
the others still run.
"""

from __future__ import annotations

from typing import Any, Iterable

from .core.constants import (
    CONFIDENCE_CEILING,
    DOMAINS,
    FAR_APART_S,
    SEVERITY_RANK,
    STRENGTH_RANK,
    TACTIC_ORDER,
)
from .core.entities import basename, clamp, max_severity, parse_iso, round2, techniques_to_tactics, uniq
from .rules import RULE_PACK, Rule, Term

Item = dict[str, Any]
Link = dict[str, Any]


# ── scoring ───────────────────────────────────────────────────────────


def describe_entities(links: Iterable[Link]) -> str:
    return ", ".join(f"{'program' if l['type'] == 'image' else l['type']} {l['value']}" for l in links)


def format_basis(terms: list[Term], raw: float, ceiling: float) -> str:
    parts = [why if i == 0 else f"{'+' if v >= 0 else '−'}{abs(round2(v)):.2f} {why}"
             for i, (v, why) in enumerate(terms)]
    text = "; ".join(parts)
    return text + (f"; capped at {ceiling}" if raw > ceiling else "")


def temporal_adjustment(side_a: list[Item], side_b: list[Item], window_s: int) -> Term | None:
    ta = [parse_iso(i["timestamp_utc"]) for i in side_a if i["timestamp_utc"]]
    tb = [parse_iso(i["timestamp_utc"]) for i in side_b if i["timestamp_utc"]]
    if not ta or not tb:
        return None
    best = min(abs(a - b) for a in ta for b in tb)
    if best <= window_s:
        return (0.10, f"nearest timestamps are {round(best)}s apart (within the {window_s}s window)")
    if best >= FAR_APART_S:
        return (-0.10, f"nearest timestamps are {round2(best / 3600)}h apart")
    return None


def score_correlation(rule: Rule, members: list[Item], links: list[Link], window_s: int,
                      bonuses: list[Term]) -> tuple[float, str]:
    terms: list[Term] = [(rule.base, f"base {rule.base:.2f} ({rule.id})")]
    strongest = max((STRENGTH_RANK[l["strength"]] for l in links), default=0)
    if strongest == STRENGTH_RANK["strong"]:
        terms.append((0.10, "linked by a strong identifier (public address, domain or full path)"))
    if len(links) > 1:
        terms.append((min(0.15, 0.05 * (len(links) - 1)), f"{len(links)} independent shared entities"))
    if links and all(l.get("scope") == "private" for l in links):
        terms.append((-0.10, "the only shared address is private (RFC1918) and is expected to appear in several sources"))
    terms.extend(bonuses)

    domains = uniq(m["domain"] for m in members)
    # A link cannot be more trustworthy than the findings it joins
    for d in domains:
        known = [m["source_confidence"] for m in members if m["domain"] == d and m["source_confidence"] is not None]
        if known and max(known) < 0.4:
            terms.append((-0.15, f"the {d} finding(s) are themselves low-confidence (max {max(known)})"))
    if len(domains) == 2:
        t = temporal_adjustment([m for m in members if m["domain"] == domains[0]],
                                [m for m in members if m["domain"] == domains[1]], window_s)
        if t:
            terms.append(t)
    if any(m["admissible"] is False for m in members):
        terms.append((-0.20, "cites non-admissible evidence (memory envelope INVALID — demo replay or failed integrity check)"))

    raw = sum(v for v, _ in terms)
    return round2(clamp(raw, 0.0, CONFIDENCE_CEILING)), format_basis(terms, raw, CONFIDENCE_CEILING)


def correlation_severity(members: list[Item], confidence: float) -> str:
    sev = max_severity(m["severity"] for m in members)
    # A low-confidence link cannot carry a critical/high source to the top of the list
    if confidence < 0.4 and SEVERITY_RANK[sev] > SEVERITY_RANK["medium"]:
        return "medium"
    return sev


def admissibility_of(members: list[Item]) -> bool | None:
    if any(m["admissible"] is False for m in members):
        return False
    if all(m["admissible"] is True for m in members):
        return True
    return None


# ── building one correlation ─────────────────────────────────────────


def _memory_processes(members: list[Item]) -> str:
    mem = [m for m in members if m["domain"] == "memory"]
    procs = uniq(p for m in mem for p in m["entities"]["images"])
    pids = uniq(p for m in mem for p in m["entities"]["pids"])
    if not procs:
        return ""
    return ", ".join(procs) + (f" (PID {', '.join(str(p) for p in pids)})" if pids else "")


def _observation(members: list[Item], links: list[Link], co_occurrence: bool) -> str:
    parts = []
    for d in DOMAINS:
        group = [m for m in members if m["domain"] == d]
        if not group:
            continue
        types = uniq(m["type"] for m in group)
        refs = [m["ref"] for m in group]
        parts.append(
            f"{len(group)} {d} finding(s) [{', '.join(refs[:6])}{', …' if len(refs) > 6 else ''}] "
            f"({'; '.join(types[:3])}{'; …' if len(types) > 3 else ''})")
    if co_occurrence:
        return f"Present in the same case: {' and '.join(parts)}. No entity is shared between them."
    return f"{describe_entities(links)} appears in {' and '.join(parts)}."


def make_correlation(rule: Rule, members: list[Item], links: list[Link], window_s: int, *,
                     co_occurrence: bool = False, title_override: str | None = None,
                     extra_bonuses: list[Term] | None = None) -> dict[str, Any]:
    side = {d: [m for m in members if m["domain"] == d] for d in DOMAINS}
    bonuses = [*rule.bonuses(side), *(extra_bonuses or [])]
    confidence, basis = score_correlation(rule, members, links, window_s, bonuses)
    domains = [d for d in DOMAINS if side[d]]
    ctx = {
        "entity_text": describe_entities(links) or "the activity",
        "memory_processes": _memory_processes(members),
        "any_deleted": any(i["deleted"] for i in side["disk"]),
        "domains": domains,
    }
    entities: dict[str, list[Any]] = {}
    for m in members:
        for k, v in m["entities"].items():
            entities[k] = uniq([*entities.get(k, []), *v])
    entities = {k: v for k, v in entities.items() if v}

    timestamps = sorted(m["timestamp_utc"] for m in members if m["timestamp_utc"])
    mitre = sorted(uniq([*rule.mitre, *rule.extra_mitre(side), *(t for m in members for t in m["mitre_attack"])]))
    tactics = techniques_to_tactics(mitre)

    return {
        "correlation_id": None,  # assigned after sorting
        "rule_id": rule.id,
        "rule_version": rule.version,
        "title": rule.title_for(side) or title_override or rule.title,
        "category": rule.category,
        "severity": correlation_severity(members, confidence),
        "confidence": confidence,
        "confidence_basis": basis,
        "link_basis": "co-occurrence" if co_occurrence else "shared-entity",
        "domains": domains,
        "linking_entities": [{"type": l["type"], "value": l["value"], "strength": l["strength"]} for l in links],
        "evidence_refs": sorted(m["ref"] for m in members),
        "entities": entities,
        "first_seen_utc": timestamps[0] if timestamps else None,
        "last_seen_utc": timestamps[-1] if timestamps else None,
        "mitre_attack": mitre,
        "tactics": [t for t in TACTIC_ORDER if t in tactics],
        "admissible": admissibility_of(members),
        "observation_statement": _observation(members, links, co_occurrence),
        "interpretation": rule.interpretation(ctx),
        "alternative_explanations": list(rule.alternatives),
        "analyst_action": rule.action,
    }


# ── grouping ──────────────────────────────────────────────────────────


def merge_overlapping(groups: list[dict[str, Any]], min_shared_domains: int) -> list[dict[str, Any]]:
    """
    Merge link groups that describe the same activity.

    Two groups merge when they share a finding in at least
    ``min_shared_domains`` domains -- e.g. ``stage2.exe`` linked by both its
    full path and its name. Sharing on one side only is not enough: a
    private address present in every network finding would otherwise fuse
    unrelated correlations into one.
    """
    parent = list(range(len(groups)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    ref_sets = [{m["ref"] for m in g["members"]} for g in groups]
    for i in range(len(groups)):
        for j in range(i + 1, len(groups)):
            shared = {m["domain"] for m in groups[j]["members"] if m["ref"] in ref_sets[i]}
            if len(shared) >= min_shared_domains:
                parent[find(j)] = find(i)

    merged: dict[int, dict[str, Any]] = {}
    for i, g in enumerate(groups):
        bucket = merged.setdefault(find(i), {"members": {}, "links": {}})
        for m in g["members"]:
            bucket["members"][m["ref"]] = m
        for l in g["links"]:
            bucket["links"][l["key"]] = l
    out = []
    for bucket in merged.values():
        links = sorted(bucket["links"].values(), key=lambda l: (-STRENGTH_RANK[l["strength"]], l["key"]))
        out.append({"members": list(bucket["members"].values()), "links": links})
    return out


def _run_pair(rule: Rule, links: list[Link], by_ref: dict[str, Item], window_s: int) -> list[dict[str, Any]]:
    a, b = rule.domains
    groups = []
    for link in links:
        if link["type"] not in rule.entity_types or link["strength"] == "weak":
            continue  # weak links are reported, never correlated on alone
        if a not in link["domains"] or b not in link["domains"]:
            continue
        members = [by_ref[r] for r in link["evidence_refs"] if by_ref[r]["domain"] in (a, b)]
        groups.append({"members": members, "links": [link]})
    return [make_correlation(rule, g["members"], g["links"], window_s) for g in merge_overlapping(groups, 2)]


def _run_cooccurrence(rule: Rule, by_domain: dict[str, list[Item]], window_s: int) -> list[dict[str, Any]]:
    assert rule.select is not None
    selected = rule.select(by_domain)
    if not all(selected.get(d) for d in rule.domains):
        return []
    members = [m for d in rule.domains for m in selected[d]]
    return [make_correlation(rule, members, [], window_s, co_occurrence=True)]


def _run_pivot(rule: Rule, links: list[Link], by_ref: dict[str, Item], window_s: int) -> list[dict[str, Any]]:
    groups = [{"members": [by_ref[r] for r in l["evidence_refs"]], "links": [l]}
              for l in links if len(l["domains"]) >= rule.min_domains and l["strength"] != "weak"]
    out = []
    for g in merge_overlapping(groups, 2):
        domain_count = len({m["domain"] for m in g["members"]})
        extra = ([(0.10 * (domain_count - rule.min_domains), f"seen in {domain_count} domains")]
                 if domain_count > rule.min_domains else [])
        lead = g["links"][0]
        noun = {"image": "Program", "ip": "Address", "path": "File"}.get(lead["type"], "Entity")
        value = basename(lead["value"]) if lead["type"] == "path" else lead["value"]
        out.append(make_correlation(rule, g["members"], g["links"], window_s, extra_bonuses=extra,
                                    title_override=f"{noun} {value} observed across {domain_count} evidence domains"))
    return out


# ── the runner ───────────────────────────────────────────────────────


def _not_evaluated_reason(rule: Rule, supplied: list[str]) -> str | None:
    if rule.kind == "pivot":
        if len(supplied) < rule.min_domains:
            return f"needs {rule.min_domains} domains, {len(supplied)} supplied"
        return None
    missing = [d for d in rule.domains if d not in supplied]
    return f"no {' / '.join(missing)} evidence supplied" if missing else None


def run_rules(items: list[Item], links: list[Link], supplied: list[str], window_s: int,
              rule_pack: Iterable[Rule] = RULE_PACK) -> dict[str, Any]:
    by_ref = {i["ref"]: i for i in items}
    by_domain = {d: [i for i in items if i["domain"] == d] for d in DOMAINS}
    correlations: list[dict[str, Any]] = []
    evaluated: list[str] = []
    not_evaluated: list[dict[str, str]] = []
    errored: list[dict[str, str]] = []

    for rule in rule_pack:
        reason = _not_evaluated_reason(rule, supplied)
        if reason:
            not_evaluated.append({"rule_id": rule.id, "title": rule.title, "reason": reason})
            continue
        try:
            if rule.kind == "pair":
                out = _run_pair(rule, links, by_ref, window_s)
            elif rule.kind == "cooccurrence":
                out = _run_cooccurrence(rule, by_domain, window_s)
            else:
                out = _run_pivot(rule, links, by_ref, window_s)
        except Exception as exc:  # noqa: BLE001 - one broken rule must not take the others down
            errored.append({"rule_id": rule.id, "error": f"{type(exc).__name__}: {exc}"})
            continue
        correlations.extend(out)
        evaluated.append(rule.id)

    correlations.sort(key=lambda c: (-SEVERITY_RANK[c["severity"]], -c["confidence"], c["rule_id"],
                                     ",".join(c["evidence_refs"])))
    for n, c in enumerate(correlations, 1):
        c["correlation_id"] = f"COR-F-{n:04d}"
    return {"correlations": correlations, "evaluated": evaluated,
            "not_evaluated": not_evaluated, "errored": errored}
