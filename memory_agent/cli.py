"""
memory_agent.cli
─────────────────────────────────────────────────────────────────────
Command-line interface.

    python -m memory_agent verify <dump> --case-id DF-2026-001
    python -m memory_agent audit-verify <audit.jsonl>
    python -m memory_agent analyze <dump> --case-id ...     (Phase 5)

Exit codes are meaningful, so this can be driven from a script or from
the Node backend later without parsing prose:

    0  success
    1  operational error (bad path, unwritable workspace, ...)
    2  INTEGRITY FAILURE -- evidence or audit trail does not verify
    3  not yet implemented (reserved for later phases)
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .core.audit import AuditLog
from .core.errors import AuditError, MemoryAgentError
from .verify import AGENT_VERSION, run_verify

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_INTEGRITY_FAILURE = 2
EXIT_NOT_IMPLEMENTED = 3


# ── output helpers ────────────────────────────────────────────────────


def _human_size(n: int) -> str:
    step = 1024.0
    value = float(n)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if value < step:
            return f"{value:,.1f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= step
    return f"{value:,.1f} PiB"


class _Progress:
    """Throttled single-line progress indicator for long hashes."""

    def __init__(self, label: str, enabled: bool = True) -> None:
        self.label = label
        self.enabled = enabled and sys.stderr.isatty()
        self._last_pct = -1

    def __call__(self, done: int, total: int) -> None:
        if not self.enabled or total <= 0:
            return
        pct = int(done * 100 / total)
        if pct == self._last_pct:
            return
        self._last_pct = pct
        bar_width = 28
        filled = int(bar_width * pct / 100)
        bar = "#" * filled + "-" * (bar_width - filled)
        sys.stderr.write(
            f"\r  {self.label} [{bar}] {pct:3d}%  {_human_size(done)}"
        )
        sys.stderr.flush()

    def done(self) -> None:
        if self.enabled and self._last_pct >= 0:
            sys.stderr.write("\r" + " " * 78 + "\r")
            sys.stderr.flush()


def _print_verify_summary(record: dict[str, Any]) -> None:
    ev = record["evidence"]
    integ = record["integrity"]
    audit = record["audit"]
    ok = integ["integrity_verified"]

    print()
    print("=" * 72)
    print("  MEMORY EVIDENCE SEAL / CHAIN OF CUSTODY")
    print("=" * 72)
    print(f"  Case ID        : {record['case']['case_id']}")
    print(f"  Investigator   : {record['case']['investigator'] or '(not supplied)'}")
    print(f"  Run ID         : {record['agent']['run_id']}")
    print(f"  Evidence ID    : {ev['evidence_id']}")
    print("-" * 72)
    print(f"  File           : {ev['file_name']}")
    print(f"  Path           : {ev['absolute_path']}")
    print(f"  Size           : {_human_size(ev['size_bytes'])}  ({ev['size_bytes']:,} bytes)")
    print(f"  Hashed in      : {ev['hash_duration_s']}s")
    print("-" * 72)
    print(f"  SHA-256        : {ev['sha256']}")
    print(f"  MD5            : {ev['md5']}   (cross-check only)")
    print("-" * 72)
    status = "VERIFIED" if ok else "*** FAILED ***"
    method = {
        "seal_only": "seal only (use --paranoid to re-read the dump)",
        "reread": "full re-read after sealing",
    }.get(integ.get("verification_method", ""), integ.get("verification_method", ""))
    print(f"  Integrity      : {status}")
    print(f"  Method         : {method}")
    for d in integ.get("discrepancies", []):
        print(f"                   ! {d}")
    for n in integ.get("metadata_notes", []):
        print(f"                   . {n}   (informational)")
    print(f"  Identity check : {integ.get('inode_check', 'unknown')}")
    print(f"  Read-only      : enforced (O_RDONLY, no write mode used)")
    print("-" * 72)
    print(f"  Audit entries  : {audit.get('entries')}")
    print(f"  Audit SHA-256  : {audit.get('log_sha256')}")
    print("-" * 72)
    print(f"  Workspace      : {record['workspace']['root']}")
    print(f"  Custody record : {record['workspace']['custody_path']}")
    print("=" * 72)

    all_warnings = list(ev.get("warnings", [])) + list(
        record.get("workspace_warnings", [])
    )
    for w in all_warnings:
        print(f"  WARNING: {w}")
    if all_warnings:
        print("=" * 72)
    print()


# ── commands ──────────────────────────────────────────────────────────


def cmd_verify(args: argparse.Namespace) -> int:
    acquisition = {
        "acquired_utc": args.acquired_utc,
        "tool": args.acquisition_tool,
        "method": args.acquisition_method,
    }

    progress = _Progress("hashing", enabled=not args.json and not args.quiet)

    try:
        record = run_verify(
            dump_path=args.dump,
            case_id=args.case_id,
            evidence_id=args.evidence_id,
            investigator=args.investigator,
            acquisition=acquisition,
            output_dir=args.output_dir,
            progress=progress,
            reread=args.paranoid,
        )
    except MemoryAgentError as exc:
        progress.done()
        _emit_error(exc, as_json=args.json)
        return EXIT_ERROR

    progress.done()

    if args.json:
        print(json.dumps(record, indent=2))
    elif not args.quiet:
        _print_verify_summary(record)

    return EXIT_OK if record["integrity"]["integrity_verified"] else EXIT_INTEGRITY_FAILURE


def _load_anchor(custody_path: Path) -> tuple[str | None, str | None, str | None]:
    """
    Read the external anchor out of a custody.json.

    The anchor is written at seal time and is what makes a full rewrite of
    audit.jsonl detectable -- the chain alone cannot catch that, because a
    hash chain has no secret, so anyone who can write the file can re-link
    every entry. Returns (final_chain_hash, log_sha256, source_path).
    """
    if not custody_path.is_file():
        return None, None, None
    try:
        data = json.loads(custody_path.read_text(encoding="utf-8"))
        audit_block = data.get("audit") or {}
        return (
            audit_block.get("final_chain_hash"),
            audit_block.get("log_sha256"),
            str(custody_path),
        )
    except (OSError, json.JSONDecodeError, AttributeError):
        return None, None, None


def cmd_audit_verify(args: argparse.Namespace) -> int:
    audit_path = Path(args.audit_log)

    expected_chain = expected_log = anchor_source = None
    if not args.no_anchor:
        custody_path = (
            Path(args.anchor) if args.anchor else audit_path.parent / "custody.json"
        )
        expected_chain, expected_log, anchor_source = _load_anchor(custody_path)

    try:
        report = AuditLog.verify_chain(
            audit_path,
            expected_final_hash=expected_chain,
            expected_log_sha256=expected_log,
        )
    except AuditError as exc:
        _emit_error(exc, as_json=args.json)
        return EXIT_ERROR

    report = {**report, "anchor_source": anchor_source}

    passed = report["valid"] and report["complete"] and report["anchor_verified"] is not False

    if args.json:
        print(json.dumps({"audit_log": str(audit_path), **report}, indent=2))
    else:
        print()
        print("=" * 72)
        print("  AUDIT TRAIL VERIFICATION")
        print("=" * 72)
        print(f"  Trail          : {audit_path}")
        print(f"  Entries        : {report['entries']}")

        if not report["valid"]:
            print(f"  Chain          : *** BROKEN ***")
            print(f"  Broken at seq  : {report['broken_at_seq']}")
            print(f"  Reason         : {report['reason']}")
            print()
            print("  Entries before this sequence number remain provably intact.")
            print("  This entry and everything after it must be treated as suspect.")
        else:
            print(f"  Chain links    : consistent")
            print(
                f"  Completeness   : "
                f"{'complete (opens and closes correctly)' if report['complete'] else '*** INCOMPLETE ***'}"
            )
            if not report["complete"]:
                print(f"                   ! {report['reason']}")

            anchor = report["anchor_verified"]
            if anchor is True:
                print(f"  External anchor: VERIFIED against {report['anchor_source']}")
                print(f"  Final hash     : {report['final_chain_hash']}")
            elif anchor is False:
                print(f"  External anchor: *** MISMATCH ***")
                print(f"                   ! {report['reason']}")
            else:
                print(f"  External anchor: NOT CHECKED (no custody.json found)")
                print()
                print("  Without an anchor this proves only that the trail is")
                print("  internally consistent. It does NOT prove the trail was")
                print("  never rewritten -- a hash chain has no secret, so anyone")
                print("  who can write the file can re-link every entry.")

        print("=" * 72)
        print()

    return EXIT_OK if passed else EXIT_INTEGRITY_FAILURE


def cmd_analyze(args: argparse.Namespace) -> int:
    message = (
        "Full analysis is not implemented yet.\n"
        "\n"
        "Phase 1 (this build) provides evidence sealing and chain of custody:\n"
        "    python -m memory_agent verify <dump> --case-id <id>\n"
        "\n"
        "Still to come, per the approved design:\n"
        "    Phase 2  Volatility 3 runner, OS identification, plugin planner\n"
        "    Phase 3  Extractors -> normalised observations\n"
        "    Phase 4  Detection rule engine (rule pack v1)\n"
        "    Phase 5  Timeline, IOCs, full output envelope  <- 'analyze' works here\n"
        "    Phase 6  AutoGen adapter and test corpus\n"
    )
    if args.json:
        print(json.dumps({"error_code": "MA-E-900", "message": message.strip()}, indent=2))
    else:
        print(message, file=sys.stderr)
    return EXIT_NOT_IMPLEMENTED


def _emit_error(exc: MemoryAgentError, as_json: bool) -> None:
    if as_json:
        print(json.dumps(exc.to_dict(), indent=2))
    else:
        print(f"\nERROR {exc}\n", file=sys.stderr)


# ── argument parsing ──────────────────────────────────────────────────


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="memory_agent",
        description=(
            "Memory Analysis Agent -- evidence-integrity-first memory dump "
            "analysis for the multi-agent digital forensics framework."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "exit codes:\n"
            "  0  success\n"
            "  1  operational error\n"
            "  2  integrity failure (evidence or audit trail did not verify)\n"
            "  3  not implemented in this phase\n"
        ),
    )
    parser.add_argument(
        "--version", action="version", version=f"memory_agent {AGENT_VERSION}"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # verify ----------------------------------------------------------
    p_verify = sub.add_parser(
        "verify",
        help="seal a memory dump and write a chain-of-custody record",
        description=(
            "Compute SHA-256 and MD5 over the evidence, capture filesystem "
            "metadata, write a tamper-evident audit trail, and produce a "
            "chain-of-custody record. Requires no forensic toolchain."
        ),
    )
    p_verify.add_argument("dump", help="path to the memory dump (.raw, .mem, .dmp, ...)")
    p_verify.add_argument(
        "--case-id", required=True, help="case identifier, e.g. DF-2026-001"
    )
    p_verify.add_argument("--evidence-id", help="evidence identifier (auto-generated if omitted)")
    p_verify.add_argument("--investigator", help="name of the investigator taking custody")
    p_verify.add_argument("--acquired-utc", help="when the dump was acquired (RFC-3339)")
    p_verify.add_argument("--acquisition-tool", help="tool used to acquire the dump")
    p_verify.add_argument("--acquisition-method", help="acquisition method or notes")
    p_verify.add_argument(
        "-o", "--output-dir",
        help="where to create the case workspace (default: ./memory_agent_cases)",
    )
    p_verify.add_argument(
        "--paranoid",
        action="store_true",
        help=(
            "re-read and re-hash the dump after sealing to confirm nothing "
            "changed. Doubles the read time on large evidence."
        ),
    )
    p_verify.add_argument("--json", action="store_true", help="emit the custody record as JSON")
    p_verify.add_argument("-q", "--quiet", action="store_true", help="suppress the summary")
    p_verify.set_defaults(func=cmd_verify)

    # audit-verify ----------------------------------------------------
    p_audit = sub.add_parser(
        "audit-verify",
        help="re-walk the hash chain of an existing audit trail",
        description=(
            "Validate that an audit.jsonl trail has not been modified since it "
            "was written. Reports the exact sequence number at which the chain "
            "breaks, if it does."
        ),
    )
    p_audit.add_argument("audit_log", help="path to an audit.jsonl file")
    p_audit.add_argument(
        "--anchor",
        help=(
            "path to the custody.json holding the external anchor "
            "(default: the custody.json beside the trail)"
        ),
    )
    p_audit.add_argument(
        "--no-anchor",
        action="store_true",
        help="check internal consistency only, without an external anchor",
    )
    p_audit.add_argument("--json", action="store_true", help="emit the report as JSON")
    p_audit.set_defaults(func=cmd_audit_verify)

    # analyze ---------------------------------------------------------
    p_analyze = sub.add_parser(
        "analyze",
        help="full memory analysis (available from Phase 5)",
    )
    p_analyze.add_argument("dump", help="path to the memory dump")
    p_analyze.add_argument("--case-id", required=True)
    p_analyze.add_argument("--json", action="store_true")
    p_analyze.set_defaults(func=cmd_analyze)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return EXIT_ERROR
    except MemoryAgentError as exc:
        _emit_error(exc, as_json=getattr(args, "json", False))
        return EXIT_ERROR


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
