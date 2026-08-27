"""
memory_agent.extractors.modules
─────────────────────────────────────────────────────────────────────
User-mode DLLs and kernel modules.

Two independent cross-view comparisons live here, and both are recorded
as raw booleans rather than as conclusions:

**PEB list membership** (``ldrmodules``). A loaded DLL is normally
present in all three PEB doubly-linked lists -- InLoad, InInit, InMem.
Unlinking a module from those lists hides it from ordinary enumeration
while it stays mapped and executing. The extractor records the three
booleans and the mapped path; MEM-I-002 decides what a mismatch means.

One honest caveat travels with every ldrmodules observation: the InInit
list legitimately excludes the process's own executable image, and
several loader-injected modules are absent from one list by design. A
rule that treats any mismatch as malicious will fire on every process on
a clean system, so the caveat belongs on the record where the rule can
see it.

**Kernel module cross-view** (``modules`` vs ``modscan``). Same pattern
one ring down: the loaded-module list versus a pool carve. A driver in
modscan but not modules is the kernel-mode equivalent of a hidden
process. Same tri-state discipline applies -- if ``modules`` did not run,
absence from it establishes nothing.
"""

from __future__ import annotations

from typing import Any, Iterable

from ..core.rows import IndexedRow, as_bool, as_hex, as_int, as_str, parse_timestamp
from ..core.schema import Observation
from .base import ExtractionContext, collect_unmapped, indexed

DLLLIST = "windows.dlllist"
LDRMODULES = "windows.ldrmodules"
MODULES = "windows.modules"
MODSCAN = "windows.modscan"
DRIVERSCAN = "windows.driverscan"

#: Modules legitimately absent from one or more PEB lists. Recorded on
#: the observation as context; the rule applies the exemption, so the
#: exemption itself is visible and arguable.
PEB_LIST_EXEMPTIONS = (
    "the process's own executable image is absent from the InInit list by "
    "design, not by evasion",
    "modules mapped as data or as images by the loader before initialisation "
    "can legitimately be missing from one list",
)


def _norm_path(value: str | None) -> str | None:
    if not value:
        return None
    return value.strip().replace("/", "\\")


def extract_modules(context: ExtractionContext) -> Iterable[Observation]:
    observations: list[Observation] = []

    # ── user-mode DLLs ───────────────────────────────────────────────
    ldr_available = context.availability(LDRMODULES)
    dll_available = context.availability(DLLLIST)

    if ldr_available is None:
        context.note_absent(
            LDRMODULES,
            "PEB loader-list membership is unknown, so MEM-I-002 (unlinked "
            "module) could not be evaluated",
        )

    # ldrmodules is keyed by (pid, base); dlllist adds the load time and
    # size. Index dlllist first so the merge below is a lookup.
    dll_index: dict[tuple[int | None, int | None], dict[str, Any]] = {}
    dll_rows = indexed(context.rows(DLLLIST))
    for i, row in enumerate(dll_rows):
        pid = as_int(row.get_field("PID", "Pid"))
        base = as_int(row.get_field("Base", "BaseAddress"))
        load_time, load_note = parse_timestamp(
            row.get_field("LoadTime", "Load Time")
        )
        dll_index[(pid, base)] = {
            "row_index": i,
            "name": as_str(row.get_field("Name", "BaseDllName", "Module")),
            "path": _norm_path(as_str(row.get_field("Path", "FullDllName"))),
            "size": as_int(row.get_field("Size")),
            "process": as_str(row.get_field("Process", "ImageFileName")),
            "load_time_utc": load_time,
            "note": load_note,
        }

    ldr_rows = indexed(context.rows(LDRMODULES))
    emitted_bases: set[tuple[int | None, int | None]] = set()

    for i, row in enumerate(ldr_rows):
        pid = as_int(row.get_field("Pid", "PID"))
        base = as_int(row.get_field("Base", "BaseAddress"))
        in_load = as_bool(row.get_field("InLoad"))
        in_init = as_bool(row.get_field("InInit"))
        in_mem = as_bool(row.get_field("InMem"))
        mapped = _norm_path(as_str(row.get_field("MappedPath", "Path", "Name")))

        extra = dll_index.get((pid, base), {})
        emitted_bases.add((pid, base))

        present = [flag for flag in (in_load, in_init, in_mem) if flag is not None]
        fields: dict[str, Any] = {
            "scope": "user",
            "pid": pid,
            "process": as_str(row.get_field("Process", "ImageFileName"))
            or extra.get("process"),
            "base": as_hex(base),
            "size": extra.get("size"),
            "name": extra.get("name"),
            "mapped_path": mapped,
            "path": extra.get("path") or mapped,
            "load_time_utc": extra.get("load_time_utc"),
            "peb_lists": {"in_load": in_load, "in_init": in_init, "in_mem": in_mem},
            "peb_lists_complete": bool(present) and all(present),
            "peb_lists_read": len(present),
            "peb_list_exemptions": list(PEB_LIST_EXEMPTIONS),
            "sources": sorted(
                {LDRMODULES} | ({DLLLIST} if (pid, base) in dll_index else set())
            ),
        }

        observations.append(
            context.observation(
                "module", plugin=LDRMODULES, row_index=i, offset=as_hex(base),
                fields=fields,
                corroborating=fields["sources"],
                notes=[extra.get("note")] if extra.get("note") else [],
            )
        )

    collect_unmapped(context, DLLLIST, dll_rows)
    collect_unmapped(context, LDRMODULES, ldr_rows)

    # dlllist entries with no ldrmodules counterpart. Only meaningful to
    # emit when ldrmodules did not run -- otherwise the PEB view is the
    # richer record and this would duplicate it.
    if ldr_available is None and dll_available:
        for (pid, base), extra in sorted(
            dll_index.items(),
            key=lambda kv: (kv[0][0] if kv[0][0] is not None else -1,
                            kv[0][1] if kv[0][1] is not None else -1),
        ):
            observations.append(
                context.observation(
                    "module", plugin=DLLLIST, row_index=extra["row_index"],
                    offset=as_hex(base),
                    fields={
                        "scope": "user",
                        "pid": pid,
                        "process": extra.get("process"),
                        "base": as_hex(base),
                        "size": extra.get("size"),
                        "name": extra.get("name"),
                        "path": extra.get("path"),
                        "mapped_path": None,
                        "load_time_utc": extra.get("load_time_utc"),
                        "peb_lists": {"in_load": None, "in_init": None,
                                      "in_mem": None},
                        "peb_lists_complete": None,
                        "peb_lists_read": 0,
                        "sources": [DLLLIST],
                    },
                    notes=[
                        "ldrmodules did not run, so PEB list membership is not "
                        "established for this module"
                    ],
                )
            )

    # ── kernel modules ───────────────────────────────────────────────
    modules_available = context.availability(MODULES)
    modscan_available = context.availability(MODSCAN)

    if modules_available is None or modscan_available is None:
        context.note_absent(
            MODULES if modules_available is None else MODSCAN,
            "the kernel module cross-view is incomplete, so MEM-M-001 (hidden "
            "kernel module) could not be soundly evaluated",
        )

    kernel: dict[str, dict[str, Any]] = {}
    order: list[str] = []

    for plugin in (MODULES, MODSCAN):
        rows = indexed(context.rows(plugin))
        for i, row in enumerate(rows):
            name = as_str(row.get_field("Name", "ModuleName", "Driver Name"))
            base = as_int(row.get_field("Base", "Offset", "Offset(V)"))
            key = (name or "").lower() or f"@{base}"
            entry = kernel.get(key)
            if entry is None:
                entry = {
                    "name": name,
                    "base": base,
                    "size": as_int(row.get_field("Size")),
                    "path": _norm_path(as_str(row.get_field("Path", "File"))),
                    "seen_in": set(),
                    "source_rows": {},
                }
                kernel[key] = entry
                order.append(key)
            entry["seen_in"].add(plugin)
            entry["source_rows"].setdefault(plugin, i)
            if entry["base"] is None and base is not None:
                entry["base"] = base
        collect_unmapped(context, plugin, rows)

    for key in sorted(order):
        entry = kernel[key]
        seen = entry["seen_in"]
        cross_view = {
            "modules": None if modules_available is None else (MODULES in seen),
            "modscan": None if modscan_available is None else (MODSCAN in seen),
        }
        primary = MODULES if MODULES in seen else MODSCAN
        observations.append(
            context.observation(
                "module", plugin=primary,
                row_index=entry["source_rows"].get(primary, -1),
                offset=as_hex(entry["base"]),
                fields={
                    "scope": "kernel",
                    "pid": None,
                    "name": entry["name"],
                    "base": as_hex(entry["base"]),
                    "size": entry["size"],
                    "path": entry["path"],
                    "cross_view": cross_view,
                    "cross_view_note": (
                        "true = the source listed this module; false = the "
                        "source ran and did not; null = the source did not run"
                    ),
                    "sources": sorted(seen),
                    "source_rows": dict(sorted(entry["source_rows"].items())),
                },
                corroborating=sorted(seen),
            )
        )

    # ── driver objects ───────────────────────────────────────────────
    rows = indexed(context.rows(DRIVERSCAN))
    for i, row in enumerate(rows):
        observations.append(
            context.observation(
                "module", plugin=DRIVERSCAN, row_index=i,
                offset=as_hex(row.get_field("Offset", "Offset(V)")),
                fields={
                    "scope": "driver",
                    "pid": None,
                    "name": as_str(row.get_field("Driver Name", "Name")),
                    "service_key": as_str(row.get_field("Service Key",
                                                        "ServiceKey")),
                    "base": as_hex(row.get_field("Start", "Base")),
                    "size": as_int(row.get_field("Size")),
                    "path": None,
                    "sources": [DRIVERSCAN],
                },
            )
        )
    collect_unmapped(context, DRIVERSCAN, rows)

    return observations
