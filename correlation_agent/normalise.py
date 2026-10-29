"""
correlation_agent.normalise  (stage C1)
─────────────────────────────────────────────────────────────────────
Findings from four agents -> one list of *evidence items*.

Each agent reports in its own shape. An evidence item carries, for every
finding: a stable ref (``LOG-0001``, ``MEM-0014`` ...), the source
agent's own observation and interpretation kept apart, a real timestamp
or none, the entities it names, and whether its domain is admissible.

Nothing is judged here. Severity and confidence are copied from the
source agent; ATT&CK techniques are copied, or inferred from the
finding type and flagged ``mitre_inferred`` when the agent emits none.
"""

from __future__ import annotations

from typing import Any, Callable, Mapping

from .core.constants import DOMAIN_PREFIX, DOMAINS, INFERRED_TECHNIQUES, NETWORK_TYPE_SEVERITY
from .core.entities import (
    as_list,
    empty_entities,
    entities_from_text,
    finish_entities,
    norm_severity,
    round2,
    techniques_to_tactics,
    to_iso,
)


def _num(v: Any) -> float | None:
    try:
        f = float(v)
    except (TypeError, ValueError):
        return None
    return f if f == f else None  # NaN -> None


# ── per-domain normalisers ────────────────────────────────────────────


def normalise_log(f: Mapping[str, Any]) -> dict[str, Any]:
    e = empty_entities()
    e["ips"] += [*as_list(f.get("allIps")), *as_list(f.get("indicators")), *as_list(f.get("ip"))]
    e["users"] += as_list(f.get("user"))
    e["hosts"] += as_list(f.get("host"))
    if f.get("process"):
        e["images"].append(f["process"])
    entities_from_text(f.get("rawLine") or f.get("line"), e)
    line_no = f.get("lineNumber")
    raw = f.get("rawLine")
    return {
        "source_id": f"line {line_no}" if line_no else ("aggregate" if f.get("aggregate") else None),
        "type": f.get("type") or "Log event",
        "category": f.get("category"),
        "severity": norm_severity(f.get("severity")),
        "source_confidence": _num(f.get("ruleConfidence")),
        "timestamp": to_iso(f.get("timestamp")),
        "fact": f"Log line {line_no if line_no is not None else '?'}: {raw}" if raw
                else str(f.get("explanation") or f.get("line") or f.get("type") or ""),
        "interpretation": f.get("explanation"),
        "alternatives": [],
        "mitre": [],
        "entities": finish_entities(e),
    }


def normalise_network(f: Mapping[str, Any]) -> dict[str, Any]:
    e = empty_entities()
    e["ips"] += [*as_list(f.get("ip")), *as_list(f.get("src")), *as_list(f.get("dst"))]
    e["ports"] += as_list(f.get("port"))
    entities_from_text(f.get("detail"), e)
    ftype = f.get("type") or "Network event"
    return {
        "source_id": f"{ftype} {f['ip']}" if f.get("ip") else ftype,
        "type": ftype,
        "category": f.get("category") or "Network",
        "severity": norm_severity(f["severity"]) if f.get("severity") else NETWORK_TYPE_SEVERITY.get(ftype, "info"),
        "source_confidence": None,
        "timestamp": to_iso(f.get("timestamp")),
        "fact": f"{ftype}: {f.get('ip') or '-'}" + (f" — {f['detail']}" if f.get("detail") else ""),
        "interpretation": None,
        "alternatives": [],
        "mitre": [],
        "entities": finish_entities(e),
    }


def normalise_disk(f: Mapping[str, Any]) -> dict[str, Any]:
    e = empty_entities()
    file_path = f.get("filePath") or f.get("path")
    if file_path:
        e["paths"].append(file_path)
    e["files"] += as_list(f.get("fileName") or f.get("name") or f.get("file"))
    deleted = bool(f.get("deleted"))
    return {
        "source_id": file_path or f.get("fileName"),
        "type": f.get("type") or "Disk artifact",
        "category": f.get("category"),
        "severity": norm_severity(f.get("severity") or ("medium" if deleted else "info")),
        "source_confidence": None,
        "timestamp": to_iso(f.get("timestamp")),
        "fact": f"{'Deleted file' if deleted else 'File'} {file_path or f.get('fileName') or '?'} "
                f"is present in the file system listing ({f.get('type') or 'artifact'}).",
        "interpretation": f.get("explanation"),
        "alternatives": [],
        "mitre": [],
        "deleted": deleted,
        "entities": finish_entities(e),
    }


def normalise_memory(f: Mapping[str, Any]) -> dict[str, Any]:
    """Accepts the raw ``memory_agent_output.json`` finding and the Node UI shape."""
    ent = f.get("entities") or {}
    e = empty_entities()
    e["ips"] += as_list(f.get("ips") or ent.get("ips"))
    processes = f.get("processes") or ent.get("processes")
    e["images"] += as_list(processes)
    if not processes and f.get("process"):
        e["images"] += [p.strip() for p in str(f["process"]).split(",")]
    e["pids"] += as_list(f.get("pids") or ent.get("pids"))
    e["paths"] += as_list(f.get("files") or ent.get("files"))
    e["urls"] += as_list(f.get("urls") or ent.get("urls"))
    e["ports"] += as_list(f.get("ports") or ent.get("ports"))
    conf = _num(f.get("confidence"))
    return {
        "source_id": " ".join(x for x in (f.get("findingId") or f.get("finding_id"),
                                          f.get("ruleId") or f.get("rule_id")) if x) or None,
        "type": f.get("title") or f.get("type") or "Memory finding",
        "category": f.get("category"),
        "severity": norm_severity(f.get("severity")),
        "source_confidence": None if conf is None else round2(conf / 100 if conf > 1 else conf),
        "timestamp": to_iso(f.get("first_seen_utc") or f.get("timestamp")),
        "fact": f.get("observation_statement") or f.get("observation") or f.get("type") or "",
        "interpretation": f.get("interpretation") or f.get("explanation"),
        "alternatives": as_list(f.get("alternative_explanations") or f.get("alternatives")),
        "mitre": as_list(f.get("mitre_attack") or f.get("mitre")),
        "entities": finish_entities(e),
    }


NORMALISERS: dict[str, Callable[[Mapping[str, Any]], dict[str, Any]]] = {
    "log": normalise_log,
    "network": normalise_network,
    "memory": normalise_memory,
    "disk": normalise_disk,
}


# ── memory context and admissibility ─────────────────────────────────


def memory_context(meta: Mapping[str, Any] | None, envelope: Mapping[str, Any] | None) -> dict[str, Any] | None:
    """
    What the correlation stages need to know about the memory run.

    Read from the memory agent's own envelope when it is available -- it
    carries the complete timeline and the authoritative status -- and
    otherwise from the summary the Node bridge stores in History.
    """
    if envelope:
        agent = envelope.get("agent") or {}
        basis = str(agent.get("status_basis") or "")
        return {
            "source": "envelope",
            "status": agent.get("status"),
            "mode": "replay" if "replay" in basis.lower() else "analyze",
            "status_basis": basis,
            "integrity_verified": (envelope.get("integrity") or {}).get("integrity_verified"),
            "clock_skew_seconds": (envelope.get("environment") or {}).get("clock_skew_seconds"),
            "timeline": [
                {"timestamp": t.get("timestamp_utc"), "precision": t.get("precision"),
                 "type": t.get("artifact_type"), "detail": t.get("description")}
                for t in envelope.get("timeline") or []
            ],
            "limitations": list(envelope.get("limitations") or []),
            "evidence_sha256": ((envelope.get("evidence") or {}).get("hashes") or {}).get("sha256_before"),
        }
    if meta:
        return {
            "source": "summary",
            "status": meta.get("status"),
            "mode": meta.get("mode"),
            "status_basis": meta.get("statusBasis"),
            "integrity_verified": meta.get("integrityVerified"),
            "clock_skew_seconds": meta.get("clockSkewSeconds"),
            "timeline": list(meta.get("timeline") or []),
            "limitations": list(meta.get("limitations") or []),
            "evidence_sha256": (meta.get("evidence") or {}).get("sha256"),
        }
    return None


def domain_admissibility(domain: str, mem: Mapping[str, Any] | None, provenance: Mapping[str, Any]) -> bool | None:
    """true / false / None (not established)."""
    if domain == "memory" and mem:
        if mem.get("status") == "INVALID" or mem.get("integrity_verified") is False:
            return False
        if mem.get("status") in ("COMPLETE", "PARTIAL"):
            return True
    if provenance.get("evidenceHash"):
        return True  # the backend hash-checked the evidence before analysis
    return None


# ── evidence items ────────────────────────────────────────────────────


def build_evidence_items(inputs: Mapping[str, Mapping[str, Any]]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for domain in DOMAINS:
        source = inputs[domain]
        if not source["supplied"]:
            continue
        for index, finding in enumerate(source["findings"]):
            n = NORMALISERS[domain](finding if isinstance(finding, Mapping) else {})
            mitre = n["mitre"]
            inferred = False
            if not mitre:
                mitre = INFERRED_TECHNIQUES.get(domain, {}).get(n["type"], [])
                inferred = bool(mitre)
            items.append({
                "ref": f"{DOMAIN_PREFIX[domain]}-{index + 1:04d}",
                "domain": domain,
                "source": {"index": index, "id": n["source_id"],
                           "analysis_id": source["provenance"].get("analysisId")},
                "type": n["type"],
                "category": n["category"],
                "severity": n["severity"],
                "source_confidence": n["source_confidence"],
                "timestamp_utc": n["timestamp"],
                "precision": "exact" if n["timestamp"] else "unknown",
                "observation": n["fact"],
                "interpretation": n["interpretation"],
                "alternative_explanations": n["alternatives"],
                "mitre_attack": list(mitre),
                "mitre_inferred": inferred,
                "tactics": techniques_to_tactics(mitre),
                "deleted": n.get("deleted", False),
                "admissible": source["admissible"],
                "entities": n["entities"],
            })
    return items
