"""
memory_agent.report
─────────────────────────────────────────────────────────────────────
Assemble, validate and write the output envelope.

The envelope is what the correlation agent consumes, so this module's
job is to make sure nothing leaves that the contract does not allow --
and that what does leave is honest about its own gaps.

Two ideas do most of the work here.

**Status is derived, never asserted.**

    INVALID   the evidence did not verify. Findings are still emitted,
              because an investigator needs to see what was found even
              when the chain of custody broke -- but the whole envelope
              is stamped non-admissible.
    PARTIAL   a plugin failed, a rule could not be evaluated, or an
              extractor errored. Anything less than full coverage.
    COMPLETE  everything planned ran, every rule was evaluated, and the
              evidence verified.

The bar for COMPLETE is deliberately high. A tool that reports success
while three plugins timed out teaches its user that "COMPLETE" means
nothing.

**Determinism is scoped and testable.**
``deterministic_core`` strips everything that legitimately varies between
runs -- run id, wall-clock timestamps, durations, absolute paths, host
name -- and returns what must be byte-identical for the same input.
Claiming the whole envelope is reproducible would be false; claiming the
*analysis* is, and providing the function that proves it, is not.
"""

from __future__ import annotations

import copy
import json
import platform
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

from .core.schema import (
    RULE_PACK_VERSION,
    SCHEMA_VERSION,
    Finding,
    IOC,
    Observation,
    TimelineEvent,
    group_observations,
    validate_envelope,
)

AGENT_NAME = "memory_analysis_agent"
AGENT_VERSION = "1.0.0"

STATUS_COMPLETE = "COMPLETE"
STATUS_PARTIAL = "PARTIAL"
STATUS_INVALID = "INVALID"

#: Severity ordering for the findings sort. Highest first, so the reader
#: meets the most serious claim before anything else.
_SEVERITY_ORDER = {
    "CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4,
}

#: Keys stripped by ``deterministic_core``. Each varies legitimately
#: between two runs over the same evidence.
_NON_DETERMINISTIC = frozenset({
    "run_id", "started_utc", "completed_utc", "duration_s", "checked_utc",
    "computed_utc", "sealed_utc", "ts_utc", "probe_duration_s",
    "hash_duration_s", "log_sha256", "final_chain_hash", "entries",
    "log_path", "raw_output", "raw_bytes", "argv", "absolute_path",
    "workspace", "host", "st_atime_ns", "st_mtime_ns", "st_ino", "st_dev",
    "argv_ref", "stderr_excerpt",
})


def build_envelope(
    *,
    run_id: str,
    case_id: str,
    started_utc: str,
    completed_utc: str,
    investigator: str | None,
    evidence: Mapping[str, Any],
    integrity: Mapping[str, Any],
    environment: Mapping[str, Any],
    toolchain: Mapping[str, Any],
    execution: Sequence[Mapping[str, Any]],
    observations: Sequence[Observation],
    findings: Sequence[Finding],
    timeline: Sequence[TimelineEvent],
    iocs: Sequence[IOC],
    rule_outcomes: Sequence[Any] = (),
    plan: Mapping[str, Any] | None = None,
    limitations: Sequence[str] = (),
    audit: Mapping[str, Any] | None = None,
    custody: Mapping[str, Any] | None = None,
    precision_counts: Mapping[str, int] | None = None,
    extraction_counts: Mapping[str, int] | None = None,
) -> dict[str, Any]:
    """Assemble the envelope. Does not validate -- see :func:`finalise`."""
    execution = list(execution)
    integrity_ok = bool(integrity.get("integrity_verified"))

    attempted = len(execution)
    succeeded = sum(1 for r in execution if r.get("status") == "ok")
    failed = sum(1 for r in execution
                 if r.get("status") in ("failed", "timeout"))
    unavailable = sum(1 for r in execution if r.get("status") == "unavailable")

    outcomes = [o.to_dict() if hasattr(o, "to_dict") else dict(o)
                for o in rule_outcomes]
    rules_evaluated = sum(1 for o in outcomes if o.get("status") == "evaluated")
    rules_skipped = sum(1 for o in outcomes if o.get("status") == "not_evaluated")
    rules_errored = sum(1 for o in outcomes if o.get("status") == "error")

    # A replayed run is INVALID for a different reason than a failed
    # verification, and conflating them would tell an investigator their
    # evidence had been tampered with when in fact none was ever read.
    is_replay = bool(evidence.get("replay"))

    if not integrity_ok:
        status = STATUS_INVALID
    elif failed or unavailable or rules_skipped or rules_errored \
            or (plan or {}).get("skipped"):
        status = STATUS_PARTIAL
    else:
        status = STATUS_COMPLETE

    invalid_reason = (
        "This run replayed previously captured plugin output. No memory image "
        "was read and no chain of custody exists, so nothing here is "
        "admissible."
        if is_replay else None
    )

    all_limitations = list(limitations)
    if status == STATUS_INVALID and is_replay:
        all_limitations.insert(0, (
            "REPLAY RUN -- NOT EVIDENCE. The analysis below was derived from "
            "captured plugin output rather than from a sealed memory image. It "
            "is valid for development, demonstration and regression testing, "
            "and for nothing else."
        ))
    elif status == STATUS_INVALID:
        all_limitations.insert(0, (
            "EVIDENCE INTEGRITY FAILED. The memory image did not verify "
            "against its pre-analysis seal. Findings below are reported so "
            "that the investigator can see what was recovered, but they are "
            "NOT admissible and must not be relied upon without re-acquiring "
            "the evidence."
        ))
    elif status == STATUS_PARTIAL:
        all_limitations.insert(0, (
            f"COVERAGE IS PARTIAL: {succeeded} of {attempted} plugins "
            f"succeeded and {rules_evaluated} of {len(outcomes)} rules were "
            f"evaluated. Absence of a finding type listed below is not "
            f"evidence of its absence on the system."
        ))

    findings_sorted = sorted(
        findings,
        key=lambda f: (
            _SEVERITY_ORDER.get(f.severity, 9), -f.confidence, f.finding_id
        ),
    )

    envelope: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "agent": {
            "name": AGENT_NAME,
            "version": AGENT_VERSION,
            "run_id": run_id,
            "started_utc": started_utc,
            "completed_utc": completed_utc,
            "status": status,
            "status_basis": _status_basis(status, succeeded, attempted,
                                          rules_evaluated, len(outcomes),
                                          invalid_reason),
        },
        "case": {
            "case_id": case_id,
            "investigator": investigator,
        },
        "evidence": dict(evidence),
        "environment": {
            **dict(environment),
            "toolchain": {
                **dict(toolchain),
                "python": ".".join(str(v) for v in sys.version_info[:3]),
                "rule_pack": RULE_PACK_VERSION,
                "agent_version": AGENT_VERSION,
            },
            "analysis_host": {
                "os": f"{platform.system()} {platform.release()}",
                "machine": platform.machine(),
            },
        },
        "plan": dict(plan) if plan else None,
        "execution": execution,
        "observations": group_observations(observations),
        "findings": [f.to_dict() for f in findings_sorted],
        "timeline": [e.to_dict() for e in timeline],
        "iocs": [i.to_dict() for i in iocs],
        "coverage": {
            "plugins_attempted": attempted,
            "plugins_succeeded": succeeded,
            "plugins_failed": failed,
            "plugins_unavailable": unavailable,
            "rules_total": len(outcomes),
            "rules_evaluated": rules_evaluated,
            "rules_not_evaluated": rules_skipped,
            "rules_errored": rules_errored,
            "rule_outcomes": outcomes,
            "artifact_counts": dict(sorted((extraction_counts or {}).items())),
            "timeline_precision": dict(sorted((precision_counts or {}).items())),
            "findings_by_severity": _severity_counts(findings_sorted),
        },
        "limitations": all_limitations,
        "integrity": dict(integrity),
        "chain_of_custody": dict(custody) if custody else None,
        "audit": dict(audit) if audit else {},
    }

    return envelope


def _status_basis(
    status: str, succeeded: int, attempted: int, evaluated: int, total_rules: int,
    invalid_reason: str | None = None,
) -> str:
    if status == STATUS_INVALID:
        return invalid_reason or (
            "The post-analysis hash of the evidence did not match the "
            "pre-analysis seal."
        )
    if status == STATUS_PARTIAL:
        return (
            f"{succeeded}/{attempted} plugins succeeded; {evaluated}/"
            f"{total_rules} rules were evaluated. See limitations for what "
            f"could not be covered."
        )
    return (
        f"All {attempted} planned plugins succeeded, all {total_rules} rules "
        f"were evaluated, and the evidence verified against its seal."
    )


def _severity_counts(findings: Sequence[Finding]) -> dict[str, int]:
    counts = {name: 0 for name in _SEVERITY_ORDER}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    return counts


def finalise(envelope: Mapping[str, Any], strict: bool = True) -> dict[str, Any]:
    """Validate the envelope against the contract and return it."""
    validate_envelope(envelope, strict=strict)
    return dict(envelope)


def write_envelope(envelope: Mapping[str, Any], path: str | Path) -> Path:
    """
    Write the envelope as UTF-8 JSON with LF endings.

    Line endings are pinned for the same reason ``custody.json`` pins
    them: this file's bytes may be hashed as part of the record, and the
    default translation would give it a different digest on Windows than
    on the Linux host that later reads it.
    """
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", encoding="utf-8", newline="\n") as fh:
        json.dump(envelope, fh, indent=2, sort_keys=False, ensure_ascii=False)
        fh.write("\n")
    return target


# ── reproducibility ───────────────────────────────────────────────────


def deterministic_core(envelope: Mapping[str, Any]) -> dict[str, Any]:
    """
    The part of the envelope that must be byte-identical across runs.

    Strips run ids, wall-clock times, durations, absolute paths and host
    details -- everything that varies for reasons that have nothing to do
    with the evidence. What remains is the analysis: observations,
    findings, timeline, indicators, coverage and limitations.

    ``tests/test_reproducibility.py`` runs the pipeline twice over the
    same fixtures and asserts this function returns equal output. That is
    the concrete form of the reproducibility claim.
    """
    core = {
        "schema_version": envelope.get("schema_version"),
        "agent": {
            k: v for k, v in (envelope.get("agent") or {}).items()
            if k not in _NON_DETERMINISTIC
        },
        "environment": _strip(envelope.get("environment")),
        "execution": [
            {k: v for k, v in record.items()
             if k not in _NON_DETERMINISTIC and k != "duration_s"}
            for record in envelope.get("execution") or []
        ],
        "observations": _strip(envelope.get("observations")),
        "findings": _strip(envelope.get("findings")),
        "timeline": _strip(envelope.get("timeline")),
        "iocs": _strip(envelope.get("iocs")),
        "coverage": _strip(envelope.get("coverage")),
        "limitations": list(envelope.get("limitations") or []),
    }
    return copy.deepcopy(core)


def _strip(value: Any) -> Any:
    """Recursively drop keys that vary between runs."""
    if isinstance(value, Mapping):
        return {
            k: _strip(v) for k, v in value.items()
            if k not in _NON_DETERMINISTIC
        }
    if isinstance(value, list):
        return [_strip(v) for v in value]
    return value


def core_digest(envelope: Mapping[str, Any]) -> str:
    """
    A stable digest of the deterministic core.

    Two runs over the same evidence with the same rule pack must produce
    the same value. Publishing it in a report lets a reviewer confirm
    reproducibility without diffing two multi-megabyte JSON documents.
    """
    import hashlib

    canonical = json.dumps(
        deterministic_core(envelope),
        sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def summarise(envelope: Mapping[str, Any]) -> str:
    """A short human-readable summary for the CLI."""
    agent = envelope.get("agent") or {}
    coverage = envelope.get("coverage") or {}
    severities = coverage.get("findings_by_severity") or {}
    findings = envelope.get("findings") or []

    lines = [
        f"status        {agent.get('status')}",
        f"              {agent.get('status_basis')}",
        f"plugins       {coverage.get('plugins_succeeded')}/"
        f"{coverage.get('plugins_attempted')} succeeded",
        f"rules         {coverage.get('rules_evaluated')}/"
        f"{coverage.get('rules_total')} evaluated",
        f"observations  {sum(len(v) for v in (envelope.get('observations') or {}).values())}",
        f"findings      {len(findings)}"
        + (f"  (CRITICAL {severities.get('CRITICAL', 0)}, "
           f"HIGH {severities.get('HIGH', 0)}, "
           f"MEDIUM {severities.get('MEDIUM', 0)}, "
           f"LOW {severities.get('LOW', 0)}, "
           f"INFO {severities.get('INFO', 0)})" if findings else ""),
        f"timeline      {len(envelope.get('timeline') or [])} events "
        f"({(coverage.get('timeline_precision') or {}).get('exact', 0)} exact)",
        f"iocs          {len(envelope.get('iocs') or [])}",
    ]
    return "\n".join(lines)
