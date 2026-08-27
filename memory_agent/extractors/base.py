"""
memory_agent.extractors.base
─────────────────────────────────────────────────────────────────────
Shared machinery for Tier 2.

The important idea here is :meth:`ExtractionContext.availability`. An
extractor must be able to distinguish three states for every plugin it
reads from:

* ``ran and produced rows``  → its absence from those rows is a fact
* ``ran and produced none``  → still a fact, but a weaker one
* ``did not run / failed``   → **not a fact at all**

Cross-view detection depends entirely on that distinction. "This process
is in psscan but not in pslist" is a hidden-process indicator. "This
process is in psscan and pslist timed out" is nothing whatsoever, and a
tool that renders the two identically will manufacture hidden processes
on every image where pslist happened to be slow.

So availability travels with the observation, and every cross-view field
is tri-state: True, False, or None for "not established".
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

from ..core.planner import ExecutionPlan
from ..core.profile import OSProfile
from ..core.rows import IndexedRow, as_str
from ..core.schema import IdFactory, Observation, Provenance

#: Cap on how many rows one plugin may contribute. A pool scanner on a
#: corrupted image can emit millions of carved rows; normalising all of
#: them would exhaust memory and bury any real signal. The cap is stated
#: as a limitation whenever it bites, never applied silently.
MAX_ROWS_PER_PLUGIN = 200_000

#: Longest string this tier will carry into an observation. Command
#: lines and console buffers can be enormous; the raw output keeps the
#: full text, and truncation is marked in the record.
MAX_TEXT = 8192


def clip(text: str | None, limit: int = MAX_TEXT) -> tuple[str | None, bool]:
    if text is None:
        return None, False
    if len(text) <= limit:
        return text, False
    return text[:limit], True


@dataclass
class ExtractionContext:
    """Everything an extractor needs, plus somewhere to put its caveats."""

    results: Mapping[str, Any]
    ids: IdFactory
    profile: OSProfile | None = None
    plan: ExecutionPlan | None = None
    limitations: list[str] = field(default_factory=list)

    def limit(self, message: str) -> None:
        if message not in self.limitations:
            self.limitations.append(message)

    # ── plugin access ─────────────────────────────────────────────────

    def availability(self, plugin: str) -> bool | None:
        """
        True if the plugin produced parsed rows, False if it ran and
        produced none, None if it did not run or could not be parsed.

        None is the value that keeps cross-view detection honest.
        """
        result = self.results.get(plugin)
        if result is None:
            return None
        if not getattr(result, "ok", False) or not getattr(result, "parsed", False):
            return None
        return bool(getattr(result, "rows", None))

    def rows(self, plugin: str) -> list[dict[str, Any]]:
        """Parsed rows for ``plugin``, capped, with the cap declared."""
        result = self.results.get(plugin)
        if result is None or not getattr(result, "parsed", False):
            return []
        rows = getattr(result, "rows", None) or []
        rows = [r for r in rows if isinstance(r, dict)]
        if len(rows) > MAX_ROWS_PER_PLUGIN:
            self.limit(
                f"{plugin} returned {len(rows)} rows; only the first "
                f"{MAX_ROWS_PER_PLUGIN} were normalised. The complete output is "
                f"retained in the case workspace. A row count this high usually "
                f"means the scanner is carving structures out of unallocated "
                f"memory, so treat the whole plugin's output with suspicion."
            )
            rows = rows[:MAX_ROWS_PER_PLUGIN]
        return rows

    def note_absent(self, plugin: str, consequence: str) -> None:
        """Record that a plugin's absence narrowed what could be derived."""
        result = self.results.get(plugin)
        status = getattr(result, "status", None) if result else None
        detail = f"{plugin} ({status})" if status else f"{plugin} (did not run)"
        self.limit(f"{detail}: {consequence}")

    # ── record construction ───────────────────────────────────────────

    def observation(
        self,
        obs_type: str,
        plugin: str,
        row_index: int,
        fields: dict[str, Any],
        offset: str | None = None,
        corroborating: Iterable[str] = (),
        notes: Iterable[str] = (),
    ) -> Observation:
        return Observation(
            obs_id=self.ids.observation(obs_type),
            type=obs_type,
            provenance=Provenance(
                plugin=plugin,
                row_index=row_index,
                offset=offset,
                argv_ref=self._argv_ref(plugin),
            ),
            fields=fields,
            corroborating_plugins=sorted(set(corroborating)),
            notes=[n for n in notes if n],
        )

    def _argv_ref(self, plugin: str) -> str | None:
        """
        Point at the execution record rather than copying the argv.

        The full command line is in ``execution[]`` once. Repeating it on
        every one of ten thousand observations would multiply the envelope
        size for no additional evidentiary value.
        """
        result = self.results.get(plugin)
        if result is None or not getattr(result, "argv", None):
            return None
        return f"execution[plugin={plugin}]"


def indexed(rows: Iterable[Mapping[str, Any]]) -> list[IndexedRow]:
    return [IndexedRow(r) for r in rows]


def collect_unmapped(
    context: ExtractionContext, plugin: str, rows: Iterable[IndexedRow]
) -> None:
    """
    Report columns no extractor read.

    This is the early-warning system for a Volatility upgrade renaming a
    column. Without it, a renamed ``ImageFileName`` produces observations
    with empty process names and no complaint at all -- and the resulting
    "no findings" looks exactly like a clean image.
    """
    # Intersection, not union. A field read conditionally -- only on the
    # first row for a given key, say -- is still a field this build knows
    # about, and reporting it as unmapped would bury a genuine rename in
    # noise. A column is unmapped only if no sampled row consumed it.
    unmapped: set[str] | None = None
    seen_any = False
    for index, row in enumerate(rows):
        seen_any = True
        row_unmapped = set(row.unmapped())
        unmapped = row_unmapped if unmapped is None else (unmapped & row_unmapped)
        if not unmapped or index >= 200:  # a sample is enough to spot a rename
            break

    if not seen_any or not unmapped:
        return

    ignorable = {"File output", "__depth", "__parent_index", "Disasm", "Hexdump"}
    unmapped -= ignorable
    if unmapped:
        context.limit(
            f"{plugin}: columns present in the plugin output but not read by "
            f"this build: {', '.join(sorted(unmapped))}. If a field you expected "
            f"is empty, a column rename in your Volatility version is the first "
            f"thing to check."
        )


def process_key(pid: Any, name: Any, create_time: str | None) -> tuple:
    """
    The identity of a process for cross-source merging.

    PID alone is not an identity: Windows reuses PIDs, and a pool scanner
    routinely returns both the live process and a terminated predecessor
    that held the same number. Including the creation time separates them.
    Where a source gives no creation time the key is deliberately partial,
    and :func:`merge_partial_keys` resolves it only when the resolution is
    unambiguous.
    """
    return (
        pid,
        (as_str(name) or "").lower(),
        create_time or "",
    )
