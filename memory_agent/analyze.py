"""
memory_agent.analyze
─────────────────────────────────────────────────────────────────────
The full pipeline, S0 through S8.

    S0  seal the evidence, open the audit trail
    S1  identify the OS and anchor its clock
    S2  build the plugin execution plan
    S3  execute plugins, capturing raw output
    S4  normalise rows into observations
    S5  evaluate the rule pack
    S6  reconstruct the timeline
    S7  extract indicators
    S8  re-verify the evidence, seal the trail, emit the envelope

Two things about the ordering matter.

**The post-analysis re-read is mandatory here, unlike in Phase 1's
``verify``.** In ``verify`` nothing happens between sealing and checking,
so re-reading tens of gigabytes proves only that two seconds passed
uneventfully. In a full analysis, an external tool has just been pointed
at the evidence twenty times. Confirming the file is byte-identical
afterwards is the entire basis for claiming the analysis did not alter
it, and it is not optional.

**The envelope is assembled after the re-verification, not before.** A
run whose evidence failed to verify still emits its findings -- an
investigator needs to see what was recovered -- but the whole document
is stamped INVALID and the limitation is placed first. Emitting findings
without that stamp, or suppressing them entirely, would each be wrong in
a different direction.

``replay_analysis`` runs S4-S8 against previously captured raw plugin
output. It exists so the analytical half of the pipeline can be
exercised, demonstrated and regression-tested without a memory image or
a Volatility install. A replayed run is always INVALID: no evidence was
sealed, so nothing about it is admissible, and the envelope says so.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

from .core.audit import AuditLog, utc_now_iso
from .core.errors import MemoryAgentError
from .core.evidence import (
    ChainOfCustody,
    seal_evidence,
    validate_evidence_path,
    verify_seal,
)
from .core.planner import build_plan, missing_rule_coverage
from .core.profile import OSProfile, WINDOWS, identify
from .core.runner import (
    STATUS_OK,
    STATUS_SKIPPED,
    PluginResult,
    VolatilityRunner,
    load_raw_results,
)
from .core.schema import IdFactory
from .core.workspace import create_workspace, new_run_id
from .detectors import DetectionContext, default_engine
from .extractors import extract_all
from .report import build_envelope, finalise, write_envelope
from .synthesis import build_timeline, extract_iocs, timeline_summary
from .verify import host_fingerprint


def run_analysis(
    dump_path: str | os.PathLike[str],
    case_id: str,
    evidence_id: str | None = None,
    investigator: str | None = None,
    acquisition: dict[str, Any] | None = None,
    deep: bool = False,
    plugin_timeout_s: int = 300,
    output_dir: str | os.PathLike[str] | None = None,
    vol_command: str | Sequence[str] | None = None,
    only: Sequence[str] | None = None,
    allowlist_vendor: bool = False,
    progress: Any = None,
) -> dict[str, Any]:
    """Run the complete pipeline over ``dump_path`` and return the envelope."""
    started = datetime.now(timezone.utc)
    started_utc = started.isoformat(timespec="milliseconds").replace("+00:00", "Z")
    run_id = new_run_id()

    evidence_path = validate_evidence_path(dump_path)
    workspace = create_workspace(
        case_id=case_id, run_id=run_id, output_dir=output_dir,
        evidence_path=evidence_path,
    )

    custody = ChainOfCustody(
        case_id=case_id, evidence_id=evidence_id or "", run_id=run_id,
        investigator=investigator, acquisition=acquisition or {},
    )

    limitations: list[str] = list(workspace.warnings)
    results: dict[str, PluginResult] = {}
    execution: list[dict[str, Any]] = []

    with AuditLog(workspace.audit_path, run_id=run_id, case_id=case_id) as audit:
        audit.record(
            "run.begin", command="analyze", agent_version="1.0.0",
            host=host_fingerprint(), argv=sys.argv[1:], deep=deep,
        )

        # ── S0: seal ─────────────────────────────────────────────────
        audit.record("evidence.seal.begin", algorithm=["sha256", "md5"])
        seal = seal_evidence(evidence_path, evidence_id=evidence_id,
                             progress=progress)
        object.__setattr__(custody, "evidence_id", seal.evidence_id)
        audit.record(
            "evidence.seal.complete", evidence_id=seal.evidence_id,
            sha256=seal.sha256, size_bytes=seal.size_bytes,
        )
        custody.add_event("evidence_sealed", evidence_id=seal.evidence_id,
                          sha256=seal.sha256)
        limitations.extend(seal.warnings)

        # ── S1: identify ─────────────────────────────────────────────
        runner = VolatilityRunner(
            evidence_path=evidence_path,
            raw_dir=workspace.raw_dir,
            cache_dir=workspace.cache_dir,
            vol_command=vol_command,
            default_timeout_s=plugin_timeout_s,
            audit=audit,
        )
        toolchain = runner.probe()
        audit.record("toolchain.ready", **toolchain.to_dict())

        profile, attempts = identify(
            runner, str(evidence_path),
            acquisition_utc=(acquisition or {}).get("acquired_utc"),
            audit=audit,
        )
        for attempt in attempts:
            results.setdefault(attempt.plugin, attempt)
            execution.append(attempt.to_execution_record())
        custody.add_event("os_identified", family=profile.family,
                          determined_by=profile.determined_by)
        limitations.extend(profile.notes)

        # ── S2: plan ─────────────────────────────────────────────────
        plan = build_plan(
            profile.family, deep=deep, base_timeout_s=plugin_timeout_s,
            available=toolchain.available_plugins or None, only=only,
        )
        audit.record("plan.built", **plan.to_dict())
        limitations.extend(plan.limitations)

        for item in plan.skipped:
            execution.append({
                "plugin": item["plugin"], "argv": [], "exit_code": None,
                "duration_s": 0.0, "row_count": 0, "status": STATUS_SKIPPED,
                "raw_output": None, "raw_bytes": 0, "parsed": False,
                "stderr_excerpt": "", "error": item["reason"], "notes": [],
            })

        # ── S3: execute ──────────────────────────────────────────────
        for entry in plan.entries:
            if entry.plugin in results and results[entry.plugin].ok:
                continue  # already run during identification
            result = runner.run(
                entry.plugin, plugin_args=entry.args,
                timeout_s=entry.timeout_s(plan.base_timeout_s),
            )
            results[entry.plugin] = result
            execution.append(result.to_execution_record())
            if result.status != STATUS_OK:
                limitations.append(
                    f"{entry.plugin} ({entry.purpose}) ended with status "
                    f"{result.status}"
                    + (f": {result.error}" if result.error else "")
                    + (f". Rules affected: {', '.join(entry.degrades)}."
                       if entry.degrades else ".")
                )

        custody.add_event("plugins_executed", count=len(execution))

        envelope = _analyse_results(
            results=results, plan=plan, profile=profile, audit=audit,
            limitations=limitations, allowlist_vendor=allowlist_vendor,
        )

        # ── S8: re-verify ────────────────────────────────────────────
        audit.record("evidence.verify.begin", stage="post_analysis",
                     method="reread")
        integrity = verify_seal(seal, evidence_path, progress=progress)
        audit.record(
            "evidence.verify.complete",
            integrity_verified=integrity.integrity_verified,
            discrepancies=integrity.discrepancies,
            metadata_notes=integrity.metadata_notes,
        )
        custody.add_event("integrity_verified",
                          integrity_verified=integrity.integrity_verified,
                          discrepancies=integrity.discrepancies)

        audit.record("run.end", status="see envelope", duration_s=round(
            (datetime.now(timezone.utc) - started).total_seconds(), 3))

    audit_seal = audit.seal_info or {}

    evidence_block = {
        **seal.to_dict(),
        "hashes": {
            "sha256_before": integrity.sha256_before,
            "sha256_after": integrity.sha256_after,
            "md5": seal.md5,
            "integrity_verified": integrity.integrity_verified,
        },
        "read_only_enforced": True,
        "read_only_note": (
            "The agent opened this file with O_RDONLY only, and Volatility "
            "received it as an input argument with every cache and temporary "
            "path redirected into the case workspace. This detects "
            "modification; it does not prevent it."
        ),
        "acquisition": acquisition or {
            "acquired_utc": None, "tool": None, "method": None,
        },
    }

    final = build_envelope(
        run_id=run_id, case_id=case_id, started_utc=started_utc,
        completed_utc=utc_now_iso(), investigator=investigator,
        evidence=evidence_block, integrity=integrity.to_dict(),
        environment=profile.to_dict(), toolchain=toolchain.to_dict(),
        execution=execution,
        observations=envelope["observations"],
        findings=envelope["findings"],
        timeline=envelope["timeline"],
        iocs=envelope["iocs"],
        rule_outcomes=envelope["rule_outcomes"],
        plan=plan.to_dict(),
        limitations=envelope["limitations"],
        audit=audit_seal,
        custody=custody.to_dict(),
        precision_counts=envelope["precision_counts"],
        extraction_counts=envelope["extraction_counts"],
    )

    finalise(final)
    write_envelope(final, workspace.envelope_path)
    final["workspace"] = {
        "root": str(workspace.root),
        "envelope_path": str(workspace.envelope_path),
        "audit_path": str(workspace.audit_path),
        "raw_dir": str(workspace.raw_dir),
    }
    return final


def _analyse_results(
    results: dict[str, PluginResult],
    plan: Any,
    profile: OSProfile,
    audit: Any,
    limitations: list[str],
    allowlist_vendor: bool = False,
) -> dict[str, Any]:
    """S4-S7. Shared by ``run_analysis`` and ``replay_analysis``."""
    ids = IdFactory()

    # S4 ── normalise
    audit.record("extract.begin")
    observations, extract_limits, extraction_counts = extract_all(
        results, profile=profile, plan=plan, ids=ids, audit=audit,
    )
    limitations.extend(extract_limits)
    audit.record("extract.end", observations=len(observations))

    # S5 ── detect
    audit.record("detect.begin", rule_pack="v1")
    not_evaluable = missing_rule_coverage(plan, results) if plan else {}
    engine = default_engine()
    context = DetectionContext(observations, environment=profile.to_dict())
    findings, rule_outcomes, rule_limits = engine.run(
        context, ids=ids, not_evaluable=not_evaluable, audit=audit,
    )
    limitations.extend(rule_limits)
    audit.record("detect.end", findings=len(findings))

    # S6 ── timeline
    timeline, precision_counts = build_timeline(observations, findings, ids=ids)
    limitations.append(timeline_summary(precision_counts))
    audit.record("timeline.built", events=len(timeline), **precision_counts)

    # S7 ── indicators
    iocs, ioc_notes = extract_iocs(
        observations, findings, ids=ids, allowlist_vendor=allowlist_vendor,
    )
    limitations.extend(ioc_notes)
    audit.record("iocs.extracted", count=len(iocs))

    return {
        "observations": observations,
        "findings": findings,
        "timeline": timeline,
        "iocs": iocs,
        "rule_outcomes": rule_outcomes,
        "limitations": limitations,
        "precision_counts": precision_counts,
        "extraction_counts": extraction_counts,
    }


# ── replay ────────────────────────────────────────────────────────────
#
# ``load_raw_results`` lives in core.runner -- reconstructing PluginResults
# from captured stdout is a runner concern -- and is re-exported here so
# that ``from memory_agent.analyze import load_raw_results`` keeps working.


def replay_analysis(
    raw_dir: str | os.PathLike[str],
    case_id: str,
    os_family: str = WINDOWS,
    deep: bool = False,
    output_dir: str | os.PathLike[str] | None = None,
    investigator: str | None = None,
    allowlist_vendor: bool = False,
    profile: OSProfile | None = None,
) -> dict[str, Any]:
    """
    Run S4-S8 against captured raw output, with no memory image.

    The resulting envelope is always ``INVALID``: no evidence was sealed,
    so nothing in it is admissible. That is the correct status rather
    than an inconvenience -- a replayed analysis is a development and
    demonstration artifact, and labelling it anything else would invite
    it to be mistaken for a real result.
    """
    started = datetime.now(timezone.utc)
    started_utc = started.isoformat(timespec="milliseconds").replace("+00:00", "Z")
    run_id = new_run_id()

    workspace = create_workspace(case_id=case_id, run_id=run_id,
                                 output_dir=output_dir)
    results = load_raw_results(raw_dir)
    if not results:
        raise MemoryAgentError(
            f"No raw plugin output found in {raw_dir}. Replay needs a "
            f"directory of <plugin>.json files, such as the raw/ directory of "
            f"a previous run's case workspace."
        )

    profile = profile or OSProfile(
        family=os_family, confidence=0.0, determined_by="supplied_by_caller",
        notes=["replay mode: the OS family was supplied, not determined from "
               "an image"],
    )

    limitations: list[str] = [
        "REPLAY MODE. This run analysed previously captured plugin output. No "
        "memory image was read, no evidence was sealed, and no chain of "
        "custody was established. The envelope is stamped INVALID for that "
        "reason and must not be presented as an analysis of evidence.",
        f"Plugins replayed: {', '.join(sorted(results))}.",
    ]

    with AuditLog(workspace.audit_path, run_id=run_id, case_id=case_id) as audit:
        audit.record("run.begin", command="replay", raw_dir=str(raw_dir),
                     plugins=sorted(results))

        plan = build_plan(
            profile.family, deep=deep, base_timeout_s=300,
            available=tuple(sorted(results)) or None,
        )
        limitations.extend(plan.limitations)

        analysed = _analyse_results(
            results=results, plan=plan, profile=profile, audit=audit,
            limitations=limitations, allowlist_vendor=allowlist_vendor,
        )
        audit.record("run.end", status="INVALID (replay)")

    audit_seal = audit.seal_info or {}
    execution = [r.to_execution_record() for _, r in sorted(results.items())]

    envelope = build_envelope(
        run_id=run_id, case_id=case_id, started_utc=started_utc,
        completed_utc=utc_now_iso(), investigator=investigator,
        evidence={
            "evidence_id": "REPLAY",
            "file_name": None,
            "size_bytes": 0,
            "hashes": {
                "sha256_before": None, "sha256_after": None, "md5": None,
                "integrity_verified": False,
            },
            "read_only_enforced": True,
            "replay": True,
            "acquisition": {"acquired_utc": None, "tool": None, "method": None},
        },
        integrity={
            "integrity_verified": False,
            "verification_method": "not_applicable_replay",
            "discrepancies": [
                "No evidence was sealed or verified: this run analysed "
                "captured plugin output, not a memory image."
            ],
        },
        environment=profile.to_dict(),
        toolchain={"volatility": "not invoked (replay)"},
        execution=execution,
        observations=analysed["observations"],
        findings=analysed["findings"],
        timeline=analysed["timeline"],
        iocs=analysed["iocs"],
        rule_outcomes=analysed["rule_outcomes"],
        plan=plan.to_dict(),
        limitations=analysed["limitations"],
        audit=audit_seal,
        precision_counts=analysed["precision_counts"],
        extraction_counts=analysed["extraction_counts"],
    )

    finalise(envelope)
    write_envelope(envelope, workspace.envelope_path)
    envelope["workspace"] = {
        "root": str(workspace.root),
        "envelope_path": str(workspace.envelope_path),
        "audit_path": str(workspace.audit_path),
    }
    return envelope
