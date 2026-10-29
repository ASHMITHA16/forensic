"""
correlation_agent.correlate
─────────────────────────────────────────────────────────────────────
The pipeline, C1–C6, and the input contract.

Input payload (JSON)::

    {
      "case_id":  "DF-2026-001",                     optional
      "log":      { "findings": [...], "meta": {...}, "provenance": {...} },
      "network":  { "findings": [...] },
      "memory":   { "envelope_path": ".../memory_agent_output.json" }
                | { "envelope": { ...memory_agent_output... } }
                | { "findings": [...], "meta": {...} },   Node summary shape
      "disk":     { "findings": [...] }
    }

The memory agent's own envelope is the preferred memory input: it is the
documented contract between the two agents, carries the complete
timeline, and states its own status. ``meta.envelopePath`` (what the Node
backend stores) is followed automatically.

The legacy flat shape ``{logData, networkData, memoryData, diskData,
*Meta}`` is accepted too. A domain counts as supplied only when it has
findings, metadata or an envelope: an empty list with nothing else is
"not supplied", because the old UI sends ``[]`` for agents it never ran,
and reading that as "ran clean" would be wrong.
"""

from __future__ import annotations

import json
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from .assess import assess, build_limitations
from .core.constants import (
    AGENT_NAME,
    AGENT_VERSION,
    DEFAULT_WINDOW_S,
    DOMAINS,
    RULE_PACK_VERSION,
    SCHEMA_VERSION,
    SEVERITIES,
)
from .core.errors import DemoUnavailable, InputError, InputNotFound, InputNotJson, SchemaViolation
from .core.schema import validate_envelope
from .engine import run_rules
from .linking import build_entity_index
from .normalise import build_evidence_items, domain_admissibility, memory_context
from .reasoning import build_attack_chain, build_hypotheses
from .report import core_digest, sha256_of
from .timeline import build_timeline

DEMO_CASE = Path(__file__).resolve().parent / "tests" / "fixtures" / "demo_case"
DEMO_CASE_ID = "DF-DEMO-CORRELATION"
MEMORY_DEMO_RAW = Path(__file__).resolve().parent.parent / "memory_agent" / "tests" / "fixtures" / "windows_case"


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def load_json(path: str | Path) -> Any:
    p = Path(path)
    if not p.is_file():
        raise InputNotFound(f"input file not found: {p}", path=p)
    try:
        return json.loads(p.read_text(encoding="utf-8-sig"))
    except json.JSONDecodeError as exc:
        raise InputNotJson(f"{p.name} is not valid JSON: {exc}", path=p) from exc


# ── inputs ────────────────────────────────────────────────────────────


def _memory_envelope(source: Mapping[str, Any], meta: Mapping[str, Any] | None,
                     notes: list[str]) -> tuple[dict[str, Any] | None, str | None]:
    if isinstance(source.get("envelope"), Mapping):
        return dict(source["envelope"]), None
    explicit = source.get("envelope_path")
    if explicit:
        return load_json(explicit), str(explicit)  # asked for explicitly: missing is an error
    stored = (meta or {}).get("envelopePath") or (meta or {}).get("envelope_path")
    if stored:
        if Path(stored).is_file():
            return load_json(stored), str(stored)
        notes.append(f"The memory envelope recorded for this run ({stored}) is no longer on disk; the stored "
                     "findings summary was used instead, so the memory timeline may be truncated.")
    return None, None


def read_inputs(payload: Mapping[str, Any]) -> tuple[dict[str, dict[str, Any]], dict[str, Any] | None, list[str]]:
    if not isinstance(payload, Mapping):
        raise InputError("the input payload must be a JSON object")
    inputs: dict[str, dict[str, Any]] = {}
    memory: dict[str, Any] | None = None
    notes: list[str] = []

    for d in DOMAINS:
        raw = payload.get(d)
        structured = raw if isinstance(raw, Mapping) else {}
        findings = structured.get("findings")
        if findings is None:
            findings = payload.get(f"{d}Data", raw if isinstance(raw, list) else [])
        meta = structured.get("meta", payload.get(f"{d}Meta")) or None
        provenance = dict(structured.get("provenance") or payload.get(f"{d}Provenance") or {})

        envelope = None
        if d == "memory":
            envelope, envelope_path = _memory_envelope(structured, meta, notes)
            if envelope is not None:
                if envelope.get("record_type") == "error":
                    raise InputError("the memory envelope is an error record: the memory analysis did not run",
                                     message=(envelope.get("error") or {}).get("message"))
                findings = envelope.get("findings") or []
                provenance.setdefault("envelopePath", envelope_path)
            memory = memory_context(meta, envelope)

        if not isinstance(findings, list):
            raise InputError(f"{d}.findings must be a list", got=type(findings).__name__)
        supplied = bool(findings) or bool(meta) or envelope is not None
        mem = memory if d == "memory" else None
        inputs[d] = {
            "supplied": supplied,
            "findings": findings,
            "meta": meta,
            "provenance": provenance,
            "admissible": domain_admissibility(d, mem, provenance) if supplied else None,
        }
        if d == "memory" and not supplied:
            memory = None
    return inputs, memory, notes


def describe_inputs(inputs: Mapping[str, Mapping[str, Any]], memory: Mapping[str, Any] | None) -> dict[str, Any]:
    out = {}
    for d in DOMAINS:
        i = inputs[d]
        risk = (i["meta"] or {}).get("risk") or i["provenance"].get("risk")
        out[d] = {
            "supplied": i["supplied"],
            "findings": len(i["findings"]),
            "file_name": i["provenance"].get("fileName"),
            "analysis_id": i["provenance"].get("analysisId"),
            "evidence_sha256": i["provenance"].get("evidenceHash")
                               or ((memory or {}).get("evidence_sha256") if d == "memory" else None),
            "source_risk": str(risk).upper() if risk else None,
            "source_status": (memory or {}).get("status") if d == "memory" and i["supplied"] else None,
            "memory_source": (memory or {}).get("source") if d == "memory" and i["supplied"] else None,
            "admissible": i["admissible"],
            "input_sha256": sha256_of(i["findings"]) if i["supplied"] else None,
        }
    return out


# ── the pipeline ──────────────────────────────────────────────────────


def run_correlation(payload: Mapping[str, Any], window_seconds: int | None = None, mode: str = "analyze",
                    case_id: str | None = None) -> dict[str, Any]:
    """C1–C6 over ``payload``; returns a validated envelope (schema 1.0.0)."""
    started = _utc_now()
    window_s = int(window_seconds) if window_seconds and int(window_seconds) > 0 else DEFAULT_WINDOW_S
    inputs, memory, notes = read_inputs(payload)
    supplied = [d for d in DOMAINS if inputs[d]["supplied"]]

    items = build_evidence_items(inputs)                                      # C1
    links = build_entity_index(items)                                         # C2
    rules = run_rules(items, links, supplied, window_s)                       # C3
    correlations = rules["correlations"]
    timeline, untimed = build_timeline(items, correlations, memory)           # C4
    chain = build_attack_chain(items, correlations)                           # C5
    hypotheses = build_hypotheses(chain, correlations, supplied)
    assessment = assess(items, correlations, chain, inputs, supplied)         # C6
    limitations = build_limitations(inputs, supplied, rules["not_evaluated"], rules["errored"],
                                    memory, items, notes)

    status = ("INSUFFICIENT" if len(supplied) < 2
              else "PARTIAL" if len(supplied) < len(DOMAINS) or rules["errored"] else "COMPLETE")
    usable_links = sum(1 for l in links if l["strength"] != "weak")
    if not items:
        summary = ("No findings were supplied by any agent; nothing to correlate. This is not evidence that "
                   "the system is clean.")
    else:
        summary = (f"{len(correlations)} correlation(s) across {len(supplied)} domain(s) [{', '.join(supplied)}] "
                   f"from {len(items)} finding(s); {usable_links} cross-domain entity link(s). "
                   f"Risk {assessment['risk_level']} ({assessment['risk_score']}/100), assessment confidence "
                   f"{round(assessment['confidence'] * 100)}%"
                   + (" — includes non-admissible evidence" if assessment["admissible"] is False else "")
                   + (" — demo case, not evidence" if mode == "demo" else "") + ".")

    env: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "agent": {
            "name": AGENT_NAME, "version": AGENT_VERSION, "rule_pack": RULE_PACK_VERSION,
            "run_id": str(uuid.uuid4()), "mode": mode, "status": status,
            "started_utc": started, "completed_utc": _utc_now(),
        },
        "case": {"case_id": case_id or payload.get("case_id") or f"DF-CORR-{int(time.time())}"},
        "rule_pack": RULE_PACK_VERSION,
        "window_seconds": window_s,
        "inputs": describe_inputs(inputs, memory),
        "evidence_items": items,
        "entity_links": links,
        "correlations": correlations,
        "attack_chain": chain,
        "hypotheses": hypotheses,
        "timeline": timeline,
        "untimed_findings": untimed,
        "assessment": assessment,
        "coverage": {
            "domains_supplied": supplied,
            "domains_missing": [d for d in DOMAINS if d not in supplied],
            "rules_total": len(rules["evaluated"]) + len(rules["not_evaluated"]) + len(rules["errored"]),
            "rules_evaluated": rules["evaluated"],
            "rules_not_evaluated": rules["not_evaluated"],
            "rules_errored": rules["errored"],
            "correlations_by_severity": {s: sum(1 for c in correlations if c["severity"] == s) for s in SEVERITIES},
            "weak_links_ignored": len(links) - usable_links,
        },
        "limitations": limitations,
        "summary": summary,
    }
    problems = validate_envelope(env)
    if problems:
        raise SchemaViolation("the correlation envelope failed its own contract", problems="; ".join(problems[:10]))
    env["core_digest"] = core_digest(env)
    return env


# ── demo case ─────────────────────────────────────────────────────────


def build_demo_payload(memory_output_dir: str | Path | None = None) -> dict[str, Any]:
    """
    The bundled demo: captured log / network / disk agent output, plus the
    memory agent's own replay of its fixture corpus (status INVALID --
    which is the honest state of a replay, and exercises the
    non-admissible path end to end).
    """
    try:
        from memory_agent.analyze import replay_analysis
    except ImportError as exc:
        raise DemoUnavailable("memory_agent is not importable; run from the repository root") from exc

    def run_replay(out: str | Path) -> dict[str, Any]:
        try:
            return replay_analysis(raw_dir=MEMORY_DEMO_RAW, case_id=DEMO_CASE_ID, output_dir=out)
        except Exception as exc:  # noqa: BLE001
            raise DemoUnavailable(f"memory_agent replay failed: {exc}") from exc

    if memory_output_dir is None:
        with tempfile.TemporaryDirectory() as tmp:
            envelope = run_replay(tmp)
    else:
        envelope = run_replay(memory_output_dir)

    log = load_json(DEMO_CASE / "log.json")
    return {
        "case_id": DEMO_CASE_ID,
        "log": {**log, "provenance": {"fileName": "security.log (demo)"}},
        "network": {"findings": load_json(DEMO_CASE / "network_findings.json"),
                    "provenance": {"fileName": "network_findings.json (demo)"}},
        "memory": {"envelope": envelope, "provenance": {"fileName": "windows_case replay (demo)"}},
        "disk": {"findings": load_json(DEMO_CASE / "disk_findings.json"),
                 "provenance": {"fileName": "disk_findings.json (demo)"}},
    }
