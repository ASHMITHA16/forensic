"""
memory_agent.core.errors
─────────────────────────────────────────────────────────────────────
Exception hierarchy for the Memory Analysis Agent.

Every exception carries a stable machine-readable ``code`` so that
failures can be serialised into the output envelope instead of being
lost as free-text stack traces. A forensic tool that dies with an
unstructured traceback produces no record of *why* the analysis of a
given piece of evidence could not be completed -- which is itself a
fact the investigator needs.
"""

from __future__ import annotations


class MemoryAgentError(Exception):
    """Base class for every error raised by the memory analysis agent."""

    code = "MA-E-000"

    def __init__(self, message: str, **context: object) -> None:
        super().__init__(message)
        self.message = message
        self.context = context

    def to_dict(self) -> dict:
        """Serialise into the structured form used by the output envelope."""
        return {
            "error_code": self.code,
            "error_type": type(self).__name__,
            "message": self.message,
            "context": self.context,
        }

    def __str__(self) -> str:  # pragma: no cover - trivial
        if self.context:
            detail = ", ".join(f"{k}={v!r}" for k, v in self.context.items())
            return f"[{self.code}] {self.message} ({detail})"
        return f"[{self.code}] {self.message}"


# ── Evidence-handling errors ──────────────────────────────────────────

class EvidenceError(MemoryAgentError):
    """Base class for problems with the evidence file itself."""

    code = "MA-E-100"


class EvidenceNotFound(EvidenceError):
    """The supplied path does not exist."""

    code = "MA-E-101"


class EvidenceNotAFile(EvidenceError):
    """The supplied path exists but is a directory, socket, device, etc."""

    code = "MA-E-102"


class EvidenceUnreadable(EvidenceError):
    """The evidence exists but cannot be opened for reading."""

    code = "MA-E-103"


class EvidenceEmpty(EvidenceError):
    """The evidence file is zero bytes -- nothing can be analysed."""

    code = "MA-E-104"


class EvidenceTampered(EvidenceError):
    """
    The post-analysis hash does not match the pre-analysis hash.

    This is the most serious error the agent can raise. It means the
    evidence changed while under the agent's control, and any findings
    derived from it are not defensible.
    """

    code = "MA-E-105"


# ── Workspace errors ──────────────────────────────────────────────────

class WorkspaceError(MemoryAgentError):
    """The case workspace could not be created or is unusable."""

    code = "MA-E-200"


class UnsafeWorkspace(WorkspaceError):
    """
    The requested workspace would place agent output inside the same
    directory as the evidence. Refused: the agent must never write
    beside the evidence it is examining.
    """

    code = "MA-E-201"


# ── Audit-trail errors ────────────────────────────────────────────────

class AuditError(MemoryAgentError):
    """The audit trail could not be written or is inconsistent."""

    code = "MA-E-300"


class AuditChainBroken(AuditError):
    """
    The hash chain linking audit entries does not validate, meaning the
    audit trail was modified after it was written.
    """

    code = "MA-E-301"


# ── Toolchain errors ──────────────────────────────────────────────────

class ToolchainError(MemoryAgentError):
    """Base class for problems with the external forensic toolchain."""

    code = "MA-E-400"


class VolatilityNotFound(ToolchainError):
    """Volatility 3 is not installed or not on the configured path."""

    code = "MA-E-401"


class VolatilityUnusable(ToolchainError):
    """
    A Volatility executable was located but does not behave like one.

    Raised when the version probe fails, times out, or returns output that
    does not identify itself as Volatility 3. Running plugins against an
    unidentified binary and reporting the results as forensic findings
    would be indefensible -- the toolchain version is part of the record.
    """

    code = "MA-E-402"


class PluginExecutionError(ToolchainError):
    """
    A plugin could not be executed at all (not merely failed).

    Individual plugin *failures* are recorded in ``execution[]`` and
    degrade coverage; they do not raise. This is reserved for conditions
    that stop the runner functioning, such as the raw output directory
    becoming unwritable mid-run.
    """

    code = "MA-E-403"


# ── OS profiling errors ───────────────────────────────────────────────

class ProfileError(MemoryAgentError):
    """Base class for failures to characterise the memory image."""

    code = "MA-E-500"


class OSIdentificationFailed(ProfileError):
    """
    Every identification method failed.

    The run aborts here rather than continuing with a guessed plugin set.
    Executing Windows plugins against an unidentified image yields either
    nothing or -- worse -- rows carved out of coincidental byte patterns,
    which would enter the record as observations.
    """

    code = "MA-E-501"


class UnsupportedOS(ProfileError):
    """The image was identified, but this build has no plugin plan for it."""

    code = "MA-E-502"


# ── Normalisation errors ──────────────────────────────────────────────

class ExtractionError(MemoryAgentError):
    """Base class for failures converting plugin rows into observations."""

    code = "MA-E-600"


class MalformedPluginOutput(ExtractionError):
    """
    Plugin output parsed as JSON but is not the shape an extractor
    expects -- a bare scalar where a list of rows was required, say.

    Treated as a per-plugin failure and recorded in ``limitations``, never
    as a reason to abandon the whole run.
    """

    code = "MA-E-601"


# ── Detection errors ──────────────────────────────────────────────────

class DetectionError(MemoryAgentError):
    """Base class for failures inside the rule engine."""

    code = "MA-E-700"


class RuleFailed(DetectionError):
    """
    One rule raised while evaluating.

    The engine isolates this: the rule is recorded as errored, every other
    rule still runs, and the lost coverage is stated in the envelope. A
    single bad rule must not cost the investigator every other finding.
    """

    code = "MA-E-701"


class DuplicateRuleId(DetectionError):
    """Two rules claim the same rule_id -- a rule-pack packaging error."""

    code = "MA-E-702"


# ── Schema / contract errors ──────────────────────────────────────────

class SchemaError(MemoryAgentError):
    """Base class for violations of the published output contract."""

    code = "MA-E-800"


class SchemaValidationError(SchemaError):
    """
    The assembled envelope does not satisfy the contract.

    Raised at the end of a run, after the evidence has been re-sealed. The
    downstream correlation agent is entitled to assume the contract holds;
    emitting a malformed envelope would push the failure into another
    agent where it is far harder to diagnose.
    """

    code = "MA-E-801"
