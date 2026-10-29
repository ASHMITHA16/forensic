"""
correlation_agent.cli
─────────────────────────────────────────────────────────────────────
Command-line interface.

    python -m correlation_agent correlate --input case.json [-o DIR] [--json]
    python -m correlation_agent correlate --input -            (payload on stdin)
    python -m correlation_agent demo [-o DIR] [--json]
    python -m correlation_agent rules [--json]
    python -m correlation_agent validate <correlation_agent_output.json>

Exit codes, so the Node backend can drive it without parsing prose:

    0  success
    1  operational error (bad or unreadable input, unwritable workspace)
    2  contract violation -- an envelope failed validation

With ``--json`` a failure is printed as a structured error record
(``{"error_code": "CA-E-…", "message": …}``) on stdout.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .core.constants import AGENT_VERSION, RULE_PACK_VERSION
from .core.errors import CorrelationAgentError, InputNotJson, SchemaViolation
from .core.schema import validate_envelope
from .correlate import DEMO_CASE_ID, build_demo_payload, load_json, run_correlation
from .report import compact_envelope, summarise, write_workspace
from .rules import list_rules

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_CONTRACT = 2


def _emit_error(exc: CorrelationAgentError, as_json: bool) -> int:
    if as_json:
        print(json.dumps(exc.to_dict()))
    else:
        print(f"error: [{exc.code}] {exc.message}", file=sys.stderr)
    return EXIT_CONTRACT if isinstance(exc, SchemaViolation) else EXIT_ERROR


def _read_payload(source: str) -> Any:
    if source == "-":
        raw = sys.stdin.buffer.read().decode("utf-8-sig")
        try:
            return json.loads(raw)
        except json.JSONDecodeError as exc:
            raise InputNotJson(f"stdin is not valid JSON: {exc}") from exc
    return load_json(source)


def _finish(env: dict[str, Any], payload: Any, args: argparse.Namespace) -> int:
    if args.output_dir:
        write_workspace(env, payload, args.output_dir)
    if args.json:
        out = compact_envelope(env) if args.compact else env
        sys.stdout.write(json.dumps(out, ensure_ascii=False))
        sys.stdout.write("\n")
    elif not args.quiet:
        print(summarise(env))
    return EXIT_OK


def cmd_correlate(args: argparse.Namespace) -> int:
    try:
        payload = _read_payload(args.input)
        env = run_correlation(payload, window_seconds=args.window, mode=args.mode, case_id=args.case_id)
        return _finish(env, payload, args)
    except CorrelationAgentError as exc:
        return _emit_error(exc, args.json)


def cmd_demo(args: argparse.Namespace) -> int:
    try:
        memory_dir = Path(args.output_dir) / DEMO_CASE_ID / "memory_replay" if args.output_dir else None
        payload = build_demo_payload(memory_dir)
        env = run_correlation(payload, window_seconds=args.window, mode="demo")
        # The memory agent wrote its own envelope; the stored input points at it
        # instead of embedding it, and still reproduces the same digest.
        stored_path = ((payload["memory"]["envelope"].get("workspace") or {}).get("envelope_path"))
        if stored_path:
            payload["memory"] = {"envelope_path": stored_path, "provenance": payload["memory"]["provenance"]}
        return _finish(env, payload, args)
    except CorrelationAgentError as exc:
        return _emit_error(exc, args.json)


def cmd_rules(args: argparse.Namespace) -> int:
    rules = list_rules()
    if args.json:
        print(json.dumps({"rule_pack": RULE_PACK_VERSION, "rules": rules}, indent=2))
        return EXIT_OK
    print(f"Rule pack {RULE_PACK_VERSION} — {len(rules)} rules")
    for r in rules:
        scope = " ↔ ".join(r["domains"]) if r["domains"] else f"any {r['min_domains']}+ domains"
        print(f"  {r['rule_id']}  base {r['base_confidence']:.2f}  {r['kind']:<12} {scope:<18} {r['title']}")
    return EXIT_OK


def cmd_validate(args: argparse.Namespace) -> int:
    try:
        env = load_json(args.envelope)
    except CorrelationAgentError as exc:
        return _emit_error(exc, args.json)
    problems = validate_envelope(env)
    if args.json:
        print(json.dumps({"valid": not problems, "problems": problems}))
    else:
        print("VALID" if not problems else "INVALID\n" + "\n".join(f"  - {p}" for p in problems))
    return EXIT_OK if not problems else EXIT_CONTRACT


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="correlation_agent",
        description="Correlate log, network, memory and disk agent findings into one evidence-cited account.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {AGENT_VERSION} ({RULE_PACK_VERSION})")
    sub = parser.add_subparsers(dest="command", required=True)

    def common(p: argparse.ArgumentParser) -> None:
        p.add_argument("-o", "--output-dir", help="write <dir>/<case_id>/<run_id>/ with input.json and the envelope")
        p.add_argument("--window", type=int, default=None, help="seconds within which timestamps corroborate (default 900)")
        p.add_argument("--json", action="store_true", help="print the envelope as JSON on stdout")
        p.add_argument("--compact", action="store_true", help="with --json: only cited evidence items, timeline capped at 1000")
        p.add_argument("-q", "--quiet", action="store_true", help="no human-readable output")

    p = sub.add_parser("correlate", help="correlate an input payload")
    p.add_argument("--input", required=True, help="payload JSON file, or - for stdin")
    p.add_argument("--case-id", default=None)
    p.add_argument("--mode", choices=("analyze", "demo"), default="analyze")
    common(p)
    p.set_defaults(func=cmd_correlate)

    p = sub.add_parser("demo", help="correlate the bundled demo case (not evidence)")
    common(p)
    p.set_defaults(func=cmd_demo)

    p = sub.add_parser("rules", help="list the rule pack")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_rules)

    p = sub.add_parser("validate", help="check an envelope against the contract")
    p.add_argument("envelope")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_validate)
    return parser


def main(argv: list[str] | None = None) -> int:
    # Evidence text and the report use non-ASCII characters; a Windows
    # console defaults to cp1252 and would crash printing them.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    args = build_parser().parse_args(argv)
    return args.func(args)
