"""
correlation_agent.autogen_adapter
─────────────────────────────────────────────────────────────────────
The only file in this package that knows AutoGen exists.

Everything else -- normalisation, linking, the rule pack, reasoning --
has zero AutoGen and zero LLM dependency, for the reason the memory
agent's design gives (DESIGN §1.3): a probabilistic step inside the
correlation would make every conclusion unreproducible, and confidence
built on another model's guess compounds into nothing. An LLM in the
wider AutoGen group can *read* this agent's envelope and write prose
about it; it does not produce the correlations.

AutoGen is imported lazily, so ``import correlation_agent`` works on a
machine without it.
"""

from __future__ import annotations

from typing import Any, Callable

from .core.constants import AGENT_NAME, AGENT_VERSION, RULE_PACK_VERSION, SCHEMA_VERSION
from .core.errors import CorrelationAgentError
from .correlate import run_correlation
from .report import summarise

TOOL_NAME = "correlate_findings"

TOOL_DESCRIPTION = f"""\
Correlate findings from the log, network, memory and disk agents.

Links findings across domains through shared entities (addresses, file
paths, program names, users), applies deterministic rule pack
{RULE_PACK_VERSION}, builds a timeline from real timestamps only, maps the
result to an ATT&CK tactic chain, and weighs H1 (one coordinated
intrusion) against H0 (unrelated events). Returns a schema-{SCHEMA_VERSION}
envelope.

HOW TO READ THE RESULT:

1. `agent.status` INSUFFICIENT means fewer than two domains were given,
   so nothing could be correlated. PARTIAL means some domains are missing.
2. Read `limitations` before concluding anything from an absence. A rule
   listed as not evaluated produced nothing because it could not run.
3. In each correlation `observation_statement` is fact (citing evidence
   refs); `interpretation` is a hypothesis to weigh against
   `alternative_explanations`, which are always populated.
4. `admissible: false` means the correlation cites evidence that failed
   its integrity check or came from a replay. Do not present it as proof.
5. `confidence` is arithmetic, capped at 0.95; `confidence_basis` shows it.
"""


def correlate_findings(
    log: dict[str, Any] | None = None,
    network: dict[str, Any] | None = None,
    memory: dict[str, Any] | None = None,
    disk: dict[str, Any] | None = None,
    memory_envelope_path: str | None = None,
    window_seconds: int = 900,
    case_id: str | None = None,
) -> dict[str, Any]:
    """
    The callable registered with AutoGen. Each domain argument is
    ``{"findings": [...], "meta": {...}}``; for memory, pass the memory
    agent's envelope path (``memory_envelope_path``) instead where possible.

    Never raises: a traceback handed to a model gets reasoned about
    instead of the evidence. Failures return a structured error record.
    """
    payload: dict[str, Any] = {k: v for k, v in (("log", log), ("network", network),
                                                 ("memory", memory), ("disk", disk)) if v}
    if memory_envelope_path:
        payload["memory"] = {**(memory or {}), "envelope_path": memory_envelope_path}
    try:
        return run_correlation(payload, window_seconds=window_seconds, case_id=case_id)
    except CorrelationAgentError as exc:
        return _error_record(exc.to_dict())
    except Exception as exc:  # noqa: BLE001 - never hand a traceback to an LLM
        return _error_record({"error_code": "CA-E-999", "error_type": type(exc).__name__,
                              "message": str(exc), "context": {}})


def _error_record(error: dict[str, Any]) -> dict[str, Any]:
    """Deliberately not a valid envelope, so it cannot be mistaken for 'no correlations'."""
    return {
        "schema_version": SCHEMA_VERSION,
        "record_type": "error",
        "agent": {"name": AGENT_NAME, "version": AGENT_VERSION, "status": "FAILED"},
        "error": error,
        "guidance": ("The correlation did not run. This is NOT a result showing that the findings are "
                     "unrelated. Report that correlation failed and why."),
    }


def summarise_for_llm(envelope: dict[str, Any], max_correlations: int = 15) -> str:
    if envelope.get("record_type") == "error":
        return f"CORRELATION FAILED: {envelope['error'].get('message')}\n{envelope['guidance']}"
    return summarise(envelope, max_correlations=max_correlations)


def register(assistant: Any, executor: Any = None) -> list[Callable[..., Any]]:
    """
    Register the tool with an AutoGen agent pair (``register_for_llm`` /
    ``register_for_execution``, autogen / pyautogen 0.2). Returns the
    registered callables so tests can call them without the framework.
    """
    executor = executor or assistant
    try:
        assistant.register_for_llm(name=TOOL_NAME, description=TOOL_DESCRIPTION)(correlate_findings)
        executor.register_for_execution(name=TOOL_NAME)(correlate_findings)
    except AttributeError as exc:
        raise RuntimeError(
            f"The supplied agent does not expose AutoGen's register_for_llm / register_for_execution API ({exc}). "
            "Register correlation_agent.autogen_adapter.correlate_findings as a plain callable instead."
        ) from exc
    return [correlate_findings]


def build_assistant(llm_config: dict[str, Any], name: str = "correlation_reasoning_agent",
                    system_message: str | None = None) -> Any:
    """A ready AutoGen AssistantAgent with the tool registered."""
    try:
        from autogen import AssistantAgent  # type: ignore
    except ImportError as exc:  # pragma: no cover - depends on environment
        raise RuntimeError("AutoGen is not installed. The correlation agent does not need it: use "
                           "correlation_agent.correlate.run_correlation or the CLI directly.") from exc
    assistant = AssistantAgent(
        name=name,
        llm_config=llm_config,
        system_message=system_message or (
            "You are the correlation and reasoning agent of a digital forensics team. Call "
            f"{TOOL_NAME} with the other agents' outputs. Report correlations as facts plus hypotheses, "
            "name the alternative explanations, flag anything not admissible, and read the limitations "
            "before saying anything about what was not found."),
    )
    register(assistant)
    return assistant
