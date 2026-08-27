"""
memory_agent.autogen_adapter
─────────────────────────────────────────────────────────────────────
The only file in this package that knows AutoGen exists.

Everything else -- the runner, the extractors, the rule engine, the
report assembly -- has zero AutoGen and zero LLM dependency. That
separation is deliberate and worth defending in the report: the memory
agent can be demonstrated, tested and argued about without an API key,
and a failure in the multi-agent layer cannot corrupt the evidence
pipeline underneath it.

AutoGen is imported lazily, inside the registration function. Importing
it at module scope would make ``import memory_agent`` fail on a machine
that has no AutoGen installed, which is exactly the machine an examiner
is most likely to be sitting at.

What the correlation agent should do with the result
────────────────────────────────────────────────────
The tool returns the full envelope. Two fields govern how it should be
read, and the tool description passed to the LLM says so explicitly:

* ``agent.status`` -- ``INVALID`` means the evidence did not verify (or
  the run was a replay). Findings are present but not admissible.
* ``limitations`` -- what could not be evaluated. A rule listed here
  produced no findings because it could not run, not because the system
  was clean. Reasoning over an absence that appears in this list is the
  single easiest way for a downstream agent to be confidently wrong.

Within a finding, ``observation_statement`` is a fact and
``interpretation`` is a hypothesis. The correlation agent is instructed
to reason over the former and treat the latter as one hypothesis among
the ``alternative_explanations`` listed beside it.
"""

from __future__ import annotations

import json
from typing import Any, Callable, Sequence

from .analyze import replay_analysis, run_analysis
from .core.errors import MemoryAgentError
from .core.schema import RULE_PACK_VERSION, SCHEMA_VERSION
from .report import AGENT_VERSION, core_digest

TOOL_NAME = "analyze_memory_dump"

TOOL_DESCRIPTION = f"""\
Analyse a memory dump (RAM image) and return structured forensic findings.

Seals the evidence with SHA-256, identifies the OS, runs Volatility 3,
normalises the output into provenance-tagged observations, evaluates
deterministic detection rules (pack {RULE_PACK_VERSION}), reconstructs a
timeline and extracts indicators. Returns a schema-{SCHEMA_VERSION}
envelope.

HOW TO READ THE RESULT -- this matters for correctness:

1. Check `agent.status` first. INVALID means the evidence failed its
   integrity check or the run was a replay; findings must not be treated
   as admissible. PARTIAL means some plugins or rules did not run.

2. Read `limitations` before concluding anything from an absence. A rule
   listed there produced no findings because it could not be evaluated,
   NOT because the system was clean. Do not infer "no injection was
   found" from a run where MEM-I-001 is listed as not evaluated.

3. Within each finding, `observation_statement` is a verifiable fact
   about the image and `interpretation` is a hypothesis. Reason over the
   facts. Treat the interpretation as one candidate alongside the
   entries in `alternative_explanations`, which are always populated.

4. `confidence` is capped at 0.95 by design; this agent examines one
   evidence domain and never asserts certainty. `confidence_basis`
   states the arithmetic in plain text.

5. In `timeline`, only events with `precision: "exact"` carry a real
   timestamp. Events with precision `relative` or `unknown` have
   `timestamp_utc: null` and an inferred `sequence_hint`. Do not place
   them on a cross-domain timeline as though they were timed.
"""


def analyze_memory_dump(
    dump_path: str,
    case_id: str,
    evidence_id: str | None = None,
    investigator: str | None = None,
    acquired_utc: str | None = None,
    deep: bool = False,
    plugin_timeout_s: int = 300,
    output_dir: str | None = None,
) -> dict[str, Any]:
    """
    Analyse ``dump_path`` and return the output envelope.

    This is the callable registered with AutoGen. It never raises: an
    agent framework that receives an exception from a tool typically
    surfaces a stack trace to the model, which then reasons about a
    Python traceback instead of about the evidence. Failures come back as
    a structured error object the model can act on.
    """
    try:
        return run_analysis(
            dump_path=dump_path,
            case_id=case_id,
            evidence_id=evidence_id,
            investigator=investigator,
            acquisition={"acquired_utc": acquired_utc, "tool": None,
                         "method": None},
            deep=deep,
            plugin_timeout_s=plugin_timeout_s,
            output_dir=output_dir,
        )
    except MemoryAgentError as exc:
        return _error_envelope(exc.to_dict(), case_id)
    except Exception as exc:  # noqa: BLE001 - never hand a traceback to an LLM
        return _error_envelope(
            {
                "error_code": "MA-E-999",
                "error_type": type(exc).__name__,
                "message": str(exc),
                "context": {},
            },
            case_id,
        )


def replay_memory_output(
    raw_dir: str,
    case_id: str,
    os_family: str = "windows",
    output_dir: str | None = None,
) -> dict[str, Any]:
    """
    Analyse previously captured plugin output. Always returns INVALID.

    Registered alongside the real tool so the multi-agent workflow can be
    exercised end to end without a memory image. The INVALID status is
    what stops a demonstration run being mistaken for a real one.
    """
    try:
        return replay_analysis(
            raw_dir=raw_dir, case_id=case_id, os_family=os_family,
            output_dir=output_dir,
        )
    except MemoryAgentError as exc:
        return _error_envelope(exc.to_dict(), case_id)
    except Exception as exc:  # noqa: BLE001
        return _error_envelope(
            {"error_code": "MA-E-999", "error_type": type(exc).__name__,
             "message": str(exc), "context": {}},
            case_id,
        )


def _error_envelope(error: dict[str, Any], case_id: str) -> dict[str, Any]:
    """
    A failure, shaped so a language model reads it correctly.

    Deliberately not schema-valid: it carries no findings, no
    observations and no evidence block, so a consumer that treats it as
    an envelope will fail loudly rather than reason over empty lists as
    though they meant "nothing was found".
    """
    return {
        "schema_version": SCHEMA_VERSION,
        "record_type": "error",
        "agent": {
            "name": "memory_analysis_agent",
            "version": AGENT_VERSION,
            "status": "FAILED",
        },
        "case": {"case_id": case_id},
        "error": error,
        "guidance": (
            "The memory analysis did not run. This is NOT a result showing a "
            "clean system -- no evidence was examined. Do not report the "
            "absence of findings. Report that the analysis failed and why, "
            "and request that the underlying problem be resolved."
        ),
    }


def summarise_for_llm(envelope: dict[str, Any], max_findings: int = 20) -> str:
    """
    A compact text rendering for a model with a limited context window.

    The full envelope on a busy image runs to megabytes. This keeps what
    a reasoning agent needs -- status, coverage, the findings with their
    facts and their alternatives, and the limitations -- and drops the
    per-observation detail, which the agent can request separately.
    """
    if envelope.get("record_type") == "error":
        return (
            f"MEMORY ANALYSIS FAILED: "
            f"{envelope.get('error', {}).get('message')}\n"
            f"{envelope.get('guidance')}"
        )

    agent = envelope.get("agent") or {}
    coverage = envelope.get("coverage") or {}
    lines = [
        f"MEMORY ANALYSIS -- status {agent.get('status')}",
        f"  {agent.get('status_basis')}",
        f"  plugins {coverage.get('plugins_succeeded')}/"
        f"{coverage.get('plugins_attempted')}, rules "
        f"{coverage.get('rules_evaluated')}/{coverage.get('rules_total')}",
        "",
    ]

    findings = (envelope.get("findings") or [])[:max_findings]
    lines.append(f"FINDINGS ({len(envelope.get('findings') or [])}):")
    for finding in findings:
        lines.append(
            f"- [{finding['severity']} {finding['confidence']:.2f}] "
            f"{finding['rule_id']} {finding['title']}"
        )
        lines.append(f"  FACT: {finding['observation_statement']}")
        lines.append(f"  HYPOTHESIS: {finding['interpretation']}")
        lines.append(
            f"  ALTERNATIVES: "
            f"{'; '.join(finding['alternative_explanations'])}"
        )
        entities = {k: v for k, v in (finding.get("entities") or {}).items() if v}
        if entities:
            lines.append(f"  ENTITIES: {json.dumps(entities, default=str)}")
        lines.append("")

    limitations = envelope.get("limitations") or []
    lines.append(f"LIMITATIONS ({len(limitations)}) -- read before inferring "
                 f"anything from an absence:")
    lines.extend(f"- {item}" for item in limitations)

    iocs = envelope.get("iocs") or []
    if iocs:
        lines.append("")
        lines.append(f"INDICATORS ({len(iocs)}):")
        for ioc in iocs[:30]:
            lines.append(
                f"- {ioc['type']}: {ioc['value']}  "
                f"(fp risk {ioc['false_positive_risk']}) -- {ioc['context']}"
            )

    return "\n".join(lines)


# ── AutoGen registration ──────────────────────────────────────────────


def register(
    assistant: Any,
    executor: Any = None,
    include_replay: bool = False,
) -> list[Callable[..., Any]]:
    """
    Register the memory tools with an AutoGen agent pair.

    ``assistant`` proposes the call; ``executor`` (defaulting to
    ``assistant``) runs it. Works with ``autogen`` / ``pyautogen`` 0.2's
    ``register_for_llm`` / ``register_for_execution`` decorators.

    Returns the registered callables so a caller can invoke them directly
    in tests without going through the framework.
    """
    executor = executor or assistant
    registered: list[Callable[..., Any]] = []

    tools: Sequence[tuple[str, str, Callable[..., Any]]] = [
        (TOOL_NAME, TOOL_DESCRIPTION, analyze_memory_dump),
    ]
    if include_replay:
        tools = [
            *tools,
            (
                "replay_memory_output",
                "Analyse previously captured Volatility output without a "
                "memory image. Always returns status INVALID because no "
                "evidence was sealed; use for testing the workflow only.",
                replay_memory_output,
            ),
        ]

    for name, description, func in tools:
        try:
            assistant.register_for_llm(name=name, description=description)(func)
            executor.register_for_execution(name=name)(func)
        except AttributeError as exc:
            raise RuntimeError(
                f"The supplied agent does not expose AutoGen's "
                f"register_for_llm / register_for_execution API ({exc}). For "
                f"other frameworks, register "
                f"memory_agent.autogen_adapter.{func.__name__} as a plain "
                f"callable -- it has no framework dependency of its own."
            ) from exc
        registered.append(func)

    return registered


def build_assistant(
    llm_config: dict[str, Any],
    name: str = "memory_analysis_agent",
    system_message: str | None = None,
) -> Any:
    """
    Convenience constructor for a ready-to-use AutoGen AssistantAgent.

    AutoGen is imported here rather than at module scope so that the rest
    of the package remains importable without it.
    """
    try:
        from autogen import AssistantAgent  # type: ignore
    except ImportError as exc:  # pragma: no cover - depends on environment
        raise RuntimeError(
            "AutoGen is not installed. The memory agent itself does not "
            "require it: use memory_agent.analyze.run_analysis directly, or "
            "the CLI, for a standalone run."
        ) from exc

    return AssistantAgent(
        name=name,
        llm_config=llm_config,
        system_message=system_message or (
            "You are the memory analysis agent in a digital forensics "
            "workflow. Call analyze_memory_dump to examine a memory image. "
            "Report only what the returned envelope supports. Never state "
            "that a system is clean on the basis of an empty findings list "
            "without first checking the limitations block: a rule listed "
            "there did not run, and its silence means nothing. Distinguish "
            "observation_statement (fact) from interpretation (hypothesis) "
            "in everything you report onward."
        ),
    )


__all__ = [
    "analyze_memory_dump", "replay_memory_output", "summarise_for_llm",
    "register", "build_assistant", "core_digest",
    "TOOL_NAME", "TOOL_DESCRIPTION",
]
