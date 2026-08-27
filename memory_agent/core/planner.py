"""
memory_agent.core.planner
─────────────────────────────────────────────────────────────────────
Turn an identified OS into an ordered plugin execution plan.

The plan is data, not control flow. It is built before anything runs,
recorded in the audit trail in full, and then executed. That ordering
matters for a forensic tool: an investigator can read what the agent
*intended* to do, compare it against ``execution[]`` for what actually
happened, and see the difference. A plan assembled implicitly by a
sequence of ``if`` statements offers nothing to compare against.

Three properties the plan carries per plugin:

* **timeout** -- proportional to what the plugin actually costs. A flat
  budget either kills ``windows.filescan`` on every real image or gives
  ``windows.info`` five minutes to hang.
* **required** -- whether losing it invalidates the analysis or merely
  narrows it. Only ``windows.info`` is required; everything else degrades
  coverage. This is what makes partial results the norm rather than an
  error path.
* **degrades** -- which rules stop being evaluable if it is missing. This
  is what lets the envelope say "MEM-P-001 could not be evaluated because
  psscan failed" instead of quietly reporting no hidden processes.

That last point is the one that matters most. A detection tool that
reports "no findings" when it actually means "the plugin that finds them
did not run" is worse than no tool at all.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Sequence

from .errors import UnsupportedOS
from .profile import LINUX, MAC, UNKNOWN, WINDOWS

#: Timeout multipliers relative to the base budget. Scanners that walk
#: the whole address space get more; readers of a single structure get
#: much less, so a hung `windows.info` fails fast instead of eating the
#: operator's patience before the real work starts.
FAST = 0.35
NORMAL = 1.0
SLOW = 2.0
VERY_SLOW = 4.0


@dataclass(frozen=True)
class PlannedPlugin:
    """One entry in the execution plan."""

    plugin: str
    domain: str
    purpose: str
    timeout_factor: float = NORMAL
    required: bool = False
    deep: bool = False
    args: tuple[str, ...] = ()
    degrades: tuple[str, ...] = ()

    def timeout_s(self, base_s: int) -> int:
        # Never below 30s: a tiny base budget with a FAST factor would
        # otherwise produce a timeout so short that process startup alone
        # exceeds it, and every plugin would "fail" for the wrong reason.
        return max(30, int(round(base_s * self.timeout_factor)))

    def to_dict(self, base_s: int) -> dict[str, Any]:
        return {
            "plugin": self.plugin,
            "domain": self.domain,
            "purpose": self.purpose,
            "timeout_s": self.timeout_s(base_s),
            "required": self.required,
            "deep_only": self.deep,
            "args": list(self.args),
            "rules_dependent_on_it": list(self.degrades),
        }


# ── Windows plugin map ────────────────────────────────────────────────

_WINDOWS_PLUGINS: tuple[PlannedPlugin, ...] = (
    PlannedPlugin(
        "windows.info", "environment",
        "OS build, architecture and the image's own system time",
        FAST, required=True,
    ),
    # Processes -----------------------------------------------------
    PlannedPlugin(
        "windows.pslist", "processes",
        "Processes reachable by walking the active process links",
        NORMAL, degrades=("MEM-P-001", "MEM-P-003", "MEM-P-005", "MEM-P-006"),
    ),
    PlannedPlugin(
        "windows.psscan", "processes",
        "Processes carved from pool tags, including exited and unlinked ones",
        SLOW, degrades=("MEM-P-001", "MEM-P-002"),
    ),
    PlannedPlugin(
        "windows.pstree", "processes",
        "Parent/child hierarchy",
        NORMAL, degrades=("MEM-P-003", "MEM-P-005"),
    ),
    PlannedPlugin(
        "windows.psxview", "processes",
        "Cross-view comparison across independent process enumeration sources",
        SLOW, degrades=("MEM-P-001",),
    ),
    # Commands ------------------------------------------------------
    PlannedPlugin(
        "windows.cmdline", "commands",
        "Full command line of each resident process",
        FAST, degrades=("MEM-C-001", "MEM-C-002", "MEM-C-003"),
    ),
    PlannedPlugin(
        "windows.consoles", "commands",
        "Console scrollback -- command output as the operator saw it",
        NORMAL, degrades=("MEM-C-001", "MEM-C-002", "MEM-C-003"),
    ),
    PlannedPlugin(
        "windows.cmdscan", "commands",
        "Typed command history carved from console history buffers",
        NORMAL, degrades=("MEM-C-003",),
    ),
    # Network -------------------------------------------------------
    PlannedPlugin(
        "windows.netscan", "network",
        "Sockets and connections carved from pool memory, with owning PID",
        SLOW, degrades=("MEM-N-001", "MEM-N-002", "MEM-N-003", "MEM-P-002"),
    ),
    PlannedPlugin(
        "windows.netstat", "network",
        "Connections reached by walking the network structures",
        SLOW, degrades=("MEM-N-001", "MEM-N-002"),
    ),
    # Modules and DLLs ----------------------------------------------
    PlannedPlugin(
        "windows.dlllist", "modules",
        "DLLs loaded per process",
        SLOW, degrades=("MEM-I-003",),
    ),
    PlannedPlugin(
        "windows.ldrmodules", "modules",
        "PEB loader-list membership, exposing unlinked modules",
        SLOW, degrades=("MEM-I-002",),
    ),
    PlannedPlugin(
        "windows.modules", "modules",
        "Kernel modules on the loaded-module list",
        FAST, degrades=("MEM-M-001",),
    ),
    PlannedPlugin(
        "windows.modscan", "modules",
        "Kernel modules carved from pool memory, including unlinked ones",
        SLOW, degrades=("MEM-M-001",),
    ),
    PlannedPlugin(
        "windows.driverscan", "modules",
        "Driver objects, including those absent from the module list",
        SLOW,
    ),
    # Injection -----------------------------------------------------
    PlannedPlugin(
        "windows.malfind", "injection",
        "Private executable memory regions holding code",
        SLOW, degrades=("MEM-I-001",),
    ),
    PlannedPlugin(
        "windows.vadinfo", "injection",
        "Virtual address descriptors -- protection, backing file, size",
        SLOW, degrades=("MEM-I-003",),
    ),
    PlannedPlugin(
        "windows.hollowprocesses", "injection",
        "Discrepancies between a process image path and its backing VAD",
        SLOW, degrades=("MEM-I-003",),
    ),
    # Services ------------------------------------------------------
    PlannedPlugin(
        "windows.svcscan", "services",
        "Registered services and the binaries behind them",
        SLOW, degrades=("MEM-S-001",),
    ),
    # Deep only -----------------------------------------------------
    PlannedPlugin(
        "windows.handles", "handles",
        "Open handles per process",
        VERY_SLOW, deep=True,
    ),
    PlannedPlugin(
        "windows.mutantscan", "handles",
        "Named mutexes -- frequently used as malware single-instance markers",
        SLOW, deep=True,
    ),
    PlannedPlugin(
        "windows.filescan", "files",
        "File objects resident in memory",
        VERY_SLOW, deep=True,
    ),
    PlannedPlugin(
        "windows.registry.hivelist", "registry",
        "Registry hives available in memory",
        NORMAL, deep=True,
    ),
)

# ── Linux plugin map ──────────────────────────────────────────────────
#
# Present so that an identified Linux image produces a structured,
# honest "not covered by this build" rather than an unhandled path.
# Extractors for these land in a later release; the plan is real, the
# normalisation is not, and the envelope says so.

_LINUX_PLUGINS: tuple[PlannedPlugin, ...] = (
    PlannedPlugin("linux.pslist.PsList", "processes", "Task list", NORMAL,
                  required=True),
    PlannedPlugin("linux.psscan.PsScan", "processes", "Carved task structures",
                  SLOW),
    PlannedPlugin("linux.pstree.PsTree", "processes", "Process hierarchy", NORMAL),
    PlannedPlugin("linux.bash.Bash", "commands", "Bash history from heap memory",
                  NORMAL),
    PlannedPlugin("linux.sockstat.Sockstat", "network", "Open sockets", SLOW),
    PlannedPlugin("linux.lsmod.Lsmod", "modules", "Loaded kernel modules", FAST),
    PlannedPlugin("linux.malfind.Malfind", "injection",
                  "Private executable mappings", SLOW),
    PlannedPlugin("linux.lsof.Lsof", "files", "Open files per task", VERY_SLOW,
                  deep=True),
)


@dataclass
class ExecutionPlan:
    """An ordered plan plus everything that was deliberately left out."""

    os_family: str
    base_timeout_s: int
    deep: bool
    entries: list[PlannedPlugin] = field(default_factory=list)
    skipped: list[dict[str, Any]] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)

    @property
    def plugins(self) -> list[str]:
        return [e.plugin for e in self.entries]

    def rules_at_risk(self) -> dict[str, list[str]]:
        """Rule id → plugins it depends on that are *in* the plan."""
        mapping: dict[str, list[str]] = {}
        for entry in self.entries:
            for rule in entry.degrades:
                mapping.setdefault(rule, []).append(entry.plugin)
        return {k: sorted(v) for k, v in sorted(mapping.items())}

    def to_dict(self) -> dict[str, Any]:
        return {
            "os_family": self.os_family,
            "base_timeout_s": self.base_timeout_s,
            "deep": self.deep,
            "plugins": [e.to_dict(self.base_timeout_s) for e in self.entries],
            "skipped": list(self.skipped),
            "limitations": list(self.limitations),
        }


def build_plan(
    os_family: str,
    deep: bool = False,
    base_timeout_s: int = 300,
    available: Sequence[str] | None = None,
    only: Sequence[str] | None = None,
) -> ExecutionPlan:
    """
    Build the plan for ``os_family``.

    ``available`` is the plugin list from the toolchain probe. When it is
    None the availability of every plugin is *unknown*, and the plan keeps
    them all: dropping a plugin we merely failed to enumerate would silently
    narrow the analysis while reporting full coverage.
    """
    if os_family == WINDOWS:
        catalogue = _WINDOWS_PLUGINS
    elif os_family == LINUX:
        catalogue = _LINUX_PLUGINS
    elif os_family in (MAC, UNKNOWN):
        raise UnsupportedOS(
            f"This build has no plugin plan for os_family={os_family!r}. "
            f"Windows is fully supported; Linux has a plan but no extractors "
            f"yet. Analysis is refused rather than run with a Windows plan "
            f"against a non-Windows image.",
            os_family=os_family,
        )
    else:
        raise UnsupportedOS(
            f"Unrecognised os_family {os_family!r}", os_family=os_family
        )

    plan = ExecutionPlan(os_family=os_family, base_timeout_s=int(base_timeout_s),
                         deep=deep)
    only_set = {p.strip() for p in only} if only else None
    available_set = set(available) if available else None

    for entry in catalogue:
        if only_set is not None and entry.plugin not in only_set:
            # Recorded, not silently dropped. A plugin excluded by --only
            # costs exactly the rules it feeds, and those rules must be
            # reported as not-evaluated rather than as having found
            # nothing. Skipping this record was a real bug: a three-plugin
            # triage run reported COMPLETE with fourteen rules starved of
            # input.
            plan.skipped.append({
                "plugin": entry.plugin,
                "reason": "not selected by --only",
                "rules_affected": list(entry.degrades),
            })
            continue

        if entry.deep and not deep:
            plan.skipped.append({
                "plugin": entry.plugin,
                "reason": "expensive; enable with --deep",
                "rules_affected": list(entry.degrades),
            })
            continue

        if available_set is not None and entry.plugin not in available_set:
            plan.skipped.append({
                "plugin": entry.plugin,
                "reason": "not provided by the installed Volatility build",
                "rules_affected": list(entry.degrades),
            })
            if entry.required:
                plan.limitations.append(
                    f"{entry.plugin} is required for {os_family} analysis but is "
                    f"not available in this Volatility build."
                )
            elif entry.degrades:
                plan.limitations.append(
                    f"{entry.plugin} is unavailable, so "
                    f"{', '.join(entry.degrades)} cannot be fully evaluated."
                )
            continue

        plan.entries.append(entry)

    if only_set is not None:
        unknown = only_set - {e.plugin for e in catalogue}
        for name in sorted(unknown):
            plan.limitations.append(
                f"{name} was requested with --only but is not in the "
                f"{os_family} plugin map; it was not run."
            )

    if available_set is None:
        plan.limitations.append(
            "The installed Volatility build's plugin list could not be "
            "enumerated, so plugin availability was not pre-checked. A plugin "
            "this build does not ship will be recorded as a failure rather "
            "than as unavailable."
        )

    if not deep:
        plan.limitations.append(
            "Expensive plugins (handles, filescan, mutantscan, registry) were "
            "not run. Rerun with --deep for handle-level and file-object "
            "coverage."
        )

    if os_family == LINUX:
        plan.limitations.append(
            "Linux images execute the plugin plan and retain raw output, but "
            "this build has no Linux extractors: no observations, findings, "
            "timeline or IOCs are derived. Windows is the supported path."
        )

    return plan


def missing_rule_coverage(
    plan: ExecutionPlan, results: dict[str, Any]
) -> dict[str, list[str]]:
    """
    Rules that cannot be soundly evaluated, and why.

    A rule is at risk when *any* plugin feeding it did not produce parsed
    rows. The engine uses this to mark such rules ``not_evaluated`` rather
    than reporting zero findings for them -- the distinction between "we
    looked and found nothing" and "we could not look" is the whole point.
    """
    at_risk: dict[str, list[str]] = {}
    for entry in plan.entries:
        result = results.get(entry.plugin)
        ok = bool(result is not None and getattr(result, "ok", False)
                  and getattr(result, "parsed", False))
        if ok:
            continue
        reason = (
            f"{entry.plugin} "
            + (f"({getattr(result, 'status', 'did not run')})" if result
               else "(did not run)")
        )
        for rule in entry.degrades:
            at_risk.setdefault(rule, []).append(reason)

    for item in plan.skipped:
        for rule in item.get("rules_affected", []):
            at_risk.setdefault(rule, []).append(
                f"{item['plugin']} ({item['reason']})"
            )

    return {k: sorted(set(v)) for k, v in sorted(at_risk.items())}
