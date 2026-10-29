"""
correlation_agent.report
─────────────────────────────────────────────────────────────────────
Envelope helpers: the reproducible core and its digest, compaction for
storage, the case workspace, and a plain-text summary.

Reproducibility is scoped the same way the memory agent scopes it
(DESIGN §8.2): the envelope carries a run id and wall-clock times that
legitimately differ between runs, so the claim is that
``core_digest(run_a) == core_digest(run_b)`` for the same input and rule
pack -- and a test checks it.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from .core.errors import WorkspaceError

ENVELOPE_NAME = "correlation_agent_output.json"
INPUT_NAME = "input.json"
_VOLATILE_AGENT = ("run_id", "started_utc", "completed_utc")
_VOLATILE_TOP = ("workspace", "core_digest", "evidence_items_total", "timeline_total")


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)


def sha256_of(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def deterministic_core(env: Mapping[str, Any]) -> dict[str, Any]:
    """The envelope minus everything that varies for reasons unrelated to the evidence."""
    core = {k: v for k, v in env.items() if k not in _VOLATILE_TOP}
    core["agent"] = {k: v for k, v in (env.get("agent") or {}).items() if k not in _VOLATILE_AGENT}
    return core


def core_digest(env: Mapping[str, Any]) -> str:
    return sha256_of(deterministic_core(env))


def compact_envelope(env: Mapping[str, Any], max_timeline: int = 1000) -> dict[str, Any]:
    """
    A smaller envelope for storage (MongoDB caps a document at 16 MB):
    only the evidence items something cites, and the first ``max_timeline``
    timeline events. The full envelope stays in the case workspace.
    """
    cited = {r for c in env["correlations"] for r in c["evidence_refs"]}
    cited |= {r for l in env["entity_links"] for r in l["evidence_refs"]}
    out = dict(env)
    out["evidence_items"] = [i for i in env["evidence_items"] if i["ref"] in cited]
    out["evidence_items_total"] = len(env["evidence_items"])
    out["timeline"] = list(env["timeline"][:max_timeline])
    out["timeline_total"] = len(env["timeline"])
    return out


def write_workspace(env: dict[str, Any], payload: Mapping[str, Any], output_dir: str | Path) -> dict[str, Any]:
    """
    ``<output_dir>/<case_id>/<run_id>/`` with the exact input and the envelope.

    Keeping the input beside the output is what makes a run re-checkable:
    ``python -m correlation_agent correlate --input input.json`` must
    reproduce the same ``core_digest``.
    """
    run_dir = Path(output_dir) / env["case"]["case_id"] / env["agent"]["run_id"]
    try:
        run_dir.mkdir(parents=True, exist_ok=False)
        input_path = run_dir / INPUT_NAME
        input_path.write_text(json.dumps(payload, indent=1, default=str), encoding="utf-8")
        env["workspace"] = {
            "run_dir": str(run_dir.resolve()),
            "input_path": str(input_path.resolve()),
            "input_sha256": hashlib.sha256(input_path.read_bytes()).hexdigest(),
            "envelope_path": str((run_dir / ENVELOPE_NAME).resolve()),
        }
        (run_dir / ENVELOPE_NAME).write_text(json.dumps(env, indent=1, ensure_ascii=False), encoding="utf-8")
    except OSError as exc:
        raise WorkspaceError(f"could not write the case workspace: {exc}", path=run_dir) from exc
    return env


def summarise(env: Mapping[str, Any], max_correlations: int = 20) -> str:
    """Plain-text rendering for the terminal and for an LLM with a small context."""
    a = env["assessment"]
    agent = env["agent"]
    lines = [
        f"CORRELATION ANALYSIS -- status {agent['status']} ({agent['mode']}), rule pack {env['rule_pack']}",
        f"  {env['summary']}",
        f"  risk {a['risk_level']} {a['risk_score']}/100 · assessment confidence {a['confidence']:.2f} · "
        f"admissible {a['admissible']}",
        f"  core digest {env.get('core_digest')}",
        "",
        "HYPOTHESES:",
    ]
    for h in env["hypotheses"]:
        lines.append(f"- {h['hypothesis_id']} [{h['confidence']:.2f}] {h['statement']}")
    lines += ["", f"ATTACK CHAIN: {env['attack_chain']['narrative']}", "",
              f"CORRELATIONS ({len(env['correlations'])}):"]
    for c in env["correlations"][:max_correlations]:
        lines.append(f"- {c['correlation_id']} [{c['severity'].upper()} {c['confidence']:.2f}] {c['rule_id']} "
                     f"{c['title']}{' (NOT ADMISSIBLE)' if c['admissible'] is False else ''}")
        lines.append(f"  FACT: {c['observation_statement']}")
        lines.append(f"  HYPOTHESIS: {c['interpretation']}")
        lines.append(f"  ALTERNATIVES: {'; '.join(c['alternative_explanations'])}")
        lines.append(f"  BASIS: {c['confidence_basis']}")
    lines += ["", f"LIMITATIONS ({len(env['limitations'])}) -- read before inferring anything from an absence:"]
    lines += [f"- {l}" for l in env["limitations"]]
    if env.get("workspace"):
        lines += ["", f"Envelope: {env['workspace']['envelope_path']}"]
    return "\n".join(lines)
