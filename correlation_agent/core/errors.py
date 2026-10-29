"""
correlation_agent.core.errors
─────────────────────────────────────────────────────────────────────
Exception hierarchy with stable machine-readable codes, so a failure
reaches the Node backend or an LLM as a structured record rather than a
traceback. Same convention as ``memory_agent.core.errors``.
"""

from __future__ import annotations


class CorrelationAgentError(Exception):
    """Base class for every error raised by the correlation agent."""

    code = "CA-E-000"

    def __init__(self, message: str, **context: object) -> None:
        super().__init__(message)
        self.message = message
        self.context = context

    def to_dict(self) -> dict:
        return {
            "error_code": self.code,
            "error_type": type(self).__name__,
            "message": self.message,
            "context": {k: str(v) for k, v in self.context.items()},
        }

    def __str__(self) -> str:  # pragma: no cover - trivial
        return f"[{self.code}] {self.message}"


class InputError(CorrelationAgentError):
    """The input payload is malformed or unreadable."""

    code = "CA-E-100"


class InputNotFound(InputError):
    """An input file (payload or memory envelope) does not exist."""

    code = "CA-E-101"


class InputNotJson(InputError):
    """An input file is not valid JSON."""

    code = "CA-E-102"


class SchemaViolation(CorrelationAgentError):
    """The assembled envelope does not satisfy its own contract."""

    code = "CA-E-200"


class WorkspaceError(CorrelationAgentError):
    """The output workspace could not be created or written."""

    code = "CA-E-300"


class DemoUnavailable(CorrelationAgentError):
    """The demo case could not be built (memory_agent replay failed)."""

    code = "CA-E-400"
