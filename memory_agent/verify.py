"""
memory_agent.verify
─────────────────────────────────────────────────────────────────────
Phase 1 entry point: seal a piece of memory evidence and produce a
chain-of-custody record.

This runs standalone -- no Volatility, no third-party packages. It is
the step that must succeed before any analysis is permitted to begin,
and it is independently useful: an investigator can seal evidence on
intake and verify it later without analysing anything.

The record it writes (``custody.json``) is the same structure that will
be embedded in the ``evidence`` and ``audit`` blocks of the full output
envelope in Phase 5, so nothing produced here is throwaway.
"""

from __future__ import annotations

import json
import os
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .core.audit import AuditLog, utc_now_iso
from .core.evidence import (
    ChainOfCustody,
    EvidenceSeal,
    seal_evidence,
    validate_evidence_path,
    verify_from_seal,
    verify_seal,
)
from .core.workspace import create_workspace, new_run_id

SCHEMA_VERSION = "1.0.0"
AGENT_NAME = "memory_analysis_agent"
AGENT_VERSION = "1.0.0-phase1"


def host_fingerprint() -> dict[str, Any]:
    """
    Identify the analysis host.

    Recorded so that a reviewer can tell which machine produced a given
    result -- part of establishing who had custody of the evidence and
    where the work was done.
    """
    return {
        "hostname": platform.node(),
        "os": f"{platform.system()} {platform.release()}",
        "machine": platform.machine(),
        "python": platform.python_version(),
        "user": os.environ.get("USERNAME") or os.environ.get("USER") or "unknown",
    }


def run_verify(
    dump_path: str | os.PathLike[str],
    case_id: str,
    evidence_id: str | None = None,
    investigator: str | None = None,
    acquisition: dict[str, Any] | None = None,
    output_dir: str | os.PathLike[str] | None = None,
    progress: Any = None,
    reread: bool = False,
) -> dict[str, Any]:
    """
    Seal ``dump_path`` and write a chain-of-custody record.

    ``reread`` controls post-seal verification. Nothing happens between
    sealing and verifying in this phase, so re-reading the dump doubles a
    potentially multi-minute pass over tens of gigabytes to prove that
    the intervening two seconds changed nothing. It is therefore off by
    default and available via ``--paranoid``. From Phase 2, where plugins
    run in between, the re-read becomes mandatory.

    Returns the custody record as a dict. Raises ``MemoryAgentError``
    subclasses on failure; the CLI converts those into structured output
    and meaningful exit codes.
    """
    started = datetime.now(timezone.utc)
    run_id = new_run_id()

    # Validate before creating anything on disk, so a bad path does not
    # leave an empty case directory behind.
    evidence_path = validate_evidence_path(dump_path)

    workspace = create_workspace(
        case_id=case_id,
        run_id=run_id,
        output_dir=output_dir,
        evidence_path=evidence_path,
    )

    custody = ChainOfCustody(
        case_id=case_id,
        evidence_id=evidence_id or "",
        run_id=run_id,
        investigator=investigator,
        acquisition=acquisition or {},
    )

    with AuditLog(workspace.audit_path, run_id=run_id, case_id=case_id) as audit:
        audit.record(
            "run.begin",
            command="verify",
            agent=AGENT_NAME,
            agent_version=AGENT_VERSION,
            host=host_fingerprint(),
            argv=sys.argv[1:],
        )

        audit.record(
            "evidence.validated",
            path=str(evidence_path),
            size_bytes=evidence_path.stat().st_size,
        )
        custody.add_event(
            "evidence_received",
            path=str(evidence_path),
            size_bytes=evidence_path.stat().st_size,
        )

        audit.record("evidence.seal.begin", algorithm=["sha256", "md5"])
        seal: EvidenceSeal = seal_evidence(
            evidence_path, evidence_id=evidence_id, progress=progress
        )
        object.__setattr__(custody, "evidence_id", seal.evidence_id)

        audit.record(
            "evidence.seal.complete",
            evidence_id=seal.evidence_id,
            sha256=seal.sha256,
            md5=seal.md5,
            size_bytes=seal.size_bytes,
            duration_s=seal.hash_duration_s,
            warnings=seal.warnings,
        )
        custody.add_event(
            "evidence_sealed",
            evidence_id=seal.evidence_id,
            sha256=seal.sha256,
            md5=seal.md5,
        )

        for warning in seal.warnings + workspace.warnings:
            audit.record("evidence.warning", message=warning)

        audit.record(
            "evidence.verify.begin",
            stage="post_seal",
            method="reread" if reread else "seal_only",
        )
        integrity = (
            verify_seal(seal, evidence_path, progress=progress)
            if reread
            else verify_from_seal(seal)
        )
        audit.record(
            "evidence.verify.complete",
            method=integrity.verification_method,
            integrity_verified=integrity.integrity_verified,
            discrepancies=integrity.discrepancies,
            metadata_notes=integrity.metadata_notes,
        )
        custody.add_event(
            "integrity_verified",
            method=integrity.verification_method,
            integrity_verified=integrity.integrity_verified,
            discrepancies=integrity.discrepancies,
        )

        audit.record(
            "run.end",
            status="COMPLETE" if integrity.integrity_verified else "INVALID",
            duration_s=round(
                (datetime.now(timezone.utc) - started).total_seconds(), 3
            ),
        )

    audit_seal = audit.seal_info or {}

    record: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "record_type": "chain_of_custody",
        "agent": {
            "name": AGENT_NAME,
            "version": AGENT_VERSION,
            "run_id": run_id,
            "started_utc": started.isoformat(timespec="milliseconds").replace(
                "+00:00", "Z"
            ),
            "completed_utc": utc_now_iso(),
            "status": "COMPLETE" if integrity.integrity_verified else "INVALID",
        },
        "case": {
            "case_id": case_id,
            "investigator": investigator,
        },
        "host": host_fingerprint(),
        "evidence": {
            **seal.to_dict(),
            "read_only_enforced": True,
            "read_only_note": (
                "The agent opened this file with O_RDONLY only and never in a "
                "write mode. This detects modification; it does not prevent it. "
                "Use a hardware write blocker or a read-only mount for "
                "prevention."
            ),
            "acquisition": acquisition or {
                "acquired_utc": None,
                "tool": None,
                "method": None,
            },
        },
        "workspace_warnings": workspace.warnings,
        "integrity": integrity.to_dict(),
        "chain_of_custody": custody.to_dict(),
        "audit": audit_seal,
        "workspace": {
            "root": str(workspace.root),
            "audit_path": str(workspace.audit_path),
            "custody_path": str(workspace.custody_path),
        },
    }

    # newline="\n" pins the line endings: custody.json is a forensic
    # document whose bytes an examiner may hash, and the default
    # translation would give it a different digest on Windows than on the
    # Linux host that re-reads it.
    with Path(workspace.custody_path).open("w", encoding="utf-8", newline="\n") as fh:
        json.dump(record, fh, indent=2, sort_keys=False)
        fh.write("\n")

    return record
