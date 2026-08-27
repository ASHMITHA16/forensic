"""
memory_agent.extractors
─────────────────────────────────────────────────────────────────────
Tier 2: raw plugin rows → typed, provenance-tagged observations.

This tier is where the agent's central discipline lives. Extractors
convert and correlate; they never judge. ``ldrmodules`` reporting a
module absent from all three PEB lists produces an observation recording
those three booleans -- not a field called ``hidden``. Turning that into
"a DLL was unlinked from the PEB to evade enumeration" is MEM-I-002's
job in Tier 3, where the claim is attributable to a rule with a version
and a stated threshold.

The practical payoff is that this tier is a pure function. Given the
same rows it produces the same observations, on any machine, with no
memory image present. Every extractor here is unit-tested against JSON
fixtures.
"""

from __future__ import annotations

from typing import Any

from ..core.planner import ExecutionPlan
from ..core.profile import OSProfile, WINDOWS
from ..core.schema import IdFactory, Observation
from .base import ExtractionContext
from .commands import extract_commands
from .injection import extract_injections
from .modules import extract_modules
from .network import extract_network
from .processes import extract_processes
from .services import extract_services

#: Order matters only for id allocation, and id allocation must be
#: deterministic, so it is fixed here rather than left to dict order.
EXTRACTORS = (
    ("processes", extract_processes),
    ("network", extract_network),
    ("commands", extract_commands),
    ("modules", extract_modules),
    ("injections", extract_injections),
    ("services", extract_services),
)

__all__ = [
    "ExtractionContext", "extract_all", "EXTRACTORS",
    "extract_processes", "extract_network", "extract_commands",
    "extract_modules", "extract_injections", "extract_services",
]


def extract_all(
    results: dict[str, Any],
    profile: OSProfile | None = None,
    plan: ExecutionPlan | None = None,
    ids: IdFactory | None = None,
    audit: Any = None,
) -> tuple[list[Observation], list[str], dict[str, int]]:
    """
    Run every extractor. Returns ``(observations, limitations, counts)``.

    One extractor raising must not cost the investigator the other five,
    so each is isolated. A failure becomes a stated limitation, which is
    materially different from an empty result: "we could not look" and
    "we looked and found nothing" must never render identically.
    """
    context = ExtractionContext(results=results, ids=ids or IdFactory(),
                                profile=profile, plan=plan)

    if profile is not None and profile.family != WINDOWS:
        context.limit(
            f"Observation extraction is implemented for Windows images only. "
            f"This image was identified as {profile.family!r}; raw plugin "
            f"output was retained but no observations were derived from it."
        )
        return [], context.limitations, {}

    observations: list[Observation] = []
    counts: dict[str, int] = {}

    for name, extractor in EXTRACTORS:
        try:
            produced = list(extractor(context))
        except Exception as exc:  # noqa: BLE001 - isolation is the point
            context.limit(
                f"The {name} extractor failed with "
                f"{type(exc).__name__}: {exc}. No {name} observations were "
                f"produced, and any rule depending on them could not be "
                f"evaluated."
            )
            if audit is not None:
                audit.record(
                    "extract.failed", extractor=name,
                    error_type=type(exc).__name__, message=str(exc),
                )
            counts[name] = 0
            continue

        observations.extend(produced)
        counts[name] = len(produced)
        if audit is not None:
            audit.record("extract.complete", extractor=name, count=len(produced))

    return observations, context.limitations, counts
