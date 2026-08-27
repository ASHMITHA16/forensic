"""
memory_agent.extractors.processes
─────────────────────────────────────────────────────────────────────
Normalise the four process enumeration sources into one observation per
process, carrying which sources saw it.

Why this is the fiddliest extractor in the package
──────────────────────────────────────────────────
The whole point of running ``pslist``, ``psscan``, ``pstree`` and
``psxview`` is that they disagree. A process visible to a pool scan but
absent from the active-process links is the classic DKOM rootkit
indicator. Merging their output therefore has to be exactly right in one
specific way: **a process must not be merged with a different process,
and must not be split from itself.**

A false merge hides a hidden process. A false split invents one.

PID is not an identity. Windows reuses PIDs freely, and ``psscan`` carves
terminated processes out of unallocated pool memory, so the same PID
routinely appears twice in one image with different creation times --
once for the live process and once for a predecessor that exited hours
earlier. Merging on PID alone would fuse them into a single record whose
``exit_time`` belongs to one process and whose sockets belong to another.

So identity here is ``(pid, name, create_time)``. Sources that omit the
creation time (``psxview`` gives only name and PID) are attached in a
second pass, and **only when exactly one candidate matches**. An
ambiguous attachment is left unattached and recorded as a note, because
guessing here would corrupt precisely the cross-view signal the merge
exists to preserve.
"""

from __future__ import annotations

from typing import Any, Iterable

from ..core.rows import IndexedRow, as_hex, as_int, as_str, parse_timestamp
from ..core.schema import Observation
from .base import ExtractionContext, collect_unmapped, indexed, process_key

PSLIST = "windows.pslist"
PSSCAN = "windows.psscan"
PSTREE = "windows.pstree"
PSXVIEW = "windows.psxview"
DLLLIST = "windows.dlllist"

#: Columns psxview may present, depending on version. Read whatever is
#: there rather than insisting on a fixed set.
_PSXVIEW_COLUMNS = (
    "pslist", "psscan", "thrdscan", "thrdproc", "csrss", "session",
    "deskthrd", "exit_time",
)


def _parse_common(row: IndexedRow) -> dict[str, Any]:
    """Fields shared by pslist, psscan and pstree rows."""
    create_time, create_note = parse_timestamp(
        row.get_field("CreateTime", "Create Time", "Created")
    )
    exit_time, exit_note = parse_timestamp(
        row.get_field("ExitTime", "Exit Time", "Exited")
    )

    return {
        "pid": as_int(row.get_field("PID", "Pid", "ProcessID")),
        "ppid": as_int(row.get_field("PPID", "Ppid", "ParentPID", "ParentProcessID")),
        "name": as_str(row.get_field("ImageFileName", "Process", "Name", "Comm")),
        "create_time_utc": create_time,
        "exit_time_utc": exit_time,
        "threads": as_int(row.get_field("Threads", "ThreadCount")),
        "handles": as_int(row.get_field("Handles", "HandleCount")),
        "session_id": as_int(row.get_field("SessionId", "Session")),
        "wow64": row.get_field("Wow64"),
        "offset": as_hex(
            row.get_field("Offset(V)", "Offset (V)", "Offset(P)", "Offset (P)",
                          "Offset")
        ),
        "_notes": [n for n in (create_note, exit_note) if n],
    }


def _image_paths(context: ExtractionContext) -> dict[int, dict[str, Any]]:
    """
    Best-effort full image path per PID, taken from ``dlllist``.

    ``pslist`` reports only ``ImageFileName``, a 15-character truncated
    field with no path. MEM-P-004 ("system binary running from the wrong
    directory") cannot be evaluated without a path, so one is recovered
    here: within each process, the loaded module whose file name matches
    the process name is, in the ordinary case, the executable itself.

    "In the ordinary case" is doing real work in that sentence, which is
    why the derivation is recorded on the observation as
    ``image_path_basis``. A hollowed process is exactly the situation
    where the mapped image and the EPROCESS name disagree -- so a rule
    reading this field must treat it as evidence about the *mapping*,
    not as the authoritative process path.
    """
    paths: dict[int, dict[str, Any]] = {}
    rows = context.rows(DLLLIST)
    if not rows:
        return paths

    for i, raw in enumerate(rows):
        row = IndexedRow(raw)
        pid = as_int(row.get_field("PID", "Pid"))
        name = as_str(row.get_field("Name", "Module", "BaseDllName"))
        path = as_str(row.get_field("Path", "FullDllName", "MappedPath"))
        if pid is None or not path or not name:
            continue
        if pid in paths:
            continue
        process_name = as_str(row.get_field("Process", "ImageFileName")) or ""
        # The executable is the module whose name matches the process.
        if name.lower() != process_name.lower():
            continue
        paths[pid] = {
            "path": path,
            "plugin": DLLLIST,
            "row_index": i,
            "basis": (
                "recovered from windows.dlllist: the loaded module whose file "
                "name matches the process name. This is the mapped image, which "
                "in a hollowed process differs from the EPROCESS image path."
            ),
        }
    return paths


def _psxview_flags(row: IndexedRow) -> dict[str, Any]:
    flags: dict[str, Any] = {}
    for column in _PSXVIEW_COLUMNS:
        value = row.get_field(column)
        if value is None:
            continue
        if isinstance(value, bool):
            flags[column] = value
        else:
            text = str(value).strip().lower()
            if text in {"true", "yes", "1"}:
                flags[column] = True
            elif text in {"false", "no", "0"}:
                flags[column] = False
            else:
                flags[column] = str(value)
    return flags


def extract_processes(context: ExtractionContext) -> Iterable[Observation]:
    """Merge the process sources into one observation per process."""
    availability = {
        plugin: context.availability(plugin)
        for plugin in (PSLIST, PSSCAN, PSTREE, PSXVIEW)
    }

    if availability[PSLIST] is None and availability[PSSCAN] is None:
        context.note_absent(
            PSLIST,
            "neither the active process list nor the pool scan produced rows, "
            "so no process observations could be built at all",
        )
        return []

    for plugin, state in availability.items():
        if state is None and plugin in (PSLIST, PSSCAN, PSXVIEW):
            context.note_absent(
                plugin,
                "cross-view comparison against this source was not possible, so "
                "a process absent from it is recorded as 'not established' "
                "rather than as absent. MEM-P-001 is correspondingly weakened.",
            )

    merged: dict[tuple, dict[str, Any]] = {}
    order: list[tuple] = []
    all_rows: list[IndexedRow] = []

    # ── pass 1: sources that carry a creation time ───────────────────
    for plugin in (PSLIST, PSSCAN, PSTREE):
        raw_rows = context.rows(plugin)
        rows = indexed(raw_rows)
        all_rows.extend(rows)
        for i, row in enumerate(rows):
            parsed = _parse_common(row)
            if parsed["pid"] is None:
                continue

            key = process_key(parsed["pid"], parsed["name"],
                              parsed["create_time_utc"])
            entry = merged.get(key)
            if entry is None:
                entry = {
                    "pid": parsed["pid"],
                    "name": parsed["name"],
                    "ppid": parsed["ppid"],
                    "create_time_utc": parsed["create_time_utc"],
                    "exit_time_utc": parsed["exit_time_utc"],
                    "threads": parsed["threads"],
                    "handles": parsed["handles"],
                    "session_id": parsed["session_id"],
                    "wow64": parsed["wow64"],
                    "offsets": {},
                    "seen_in": set(),
                    "source_rows": {},
                    "notes": [],
                    "tree_depth": None,
                    "psxview": {},
                }
                merged[key] = entry
                order.append(key)

            entry["seen_in"].add(plugin)
            entry["source_rows"].setdefault(plugin, i)
            if parsed["offset"]:
                entry["offsets"].setdefault(plugin, parsed["offset"])
            entry["notes"].extend(parsed["_notes"])

            # Fill gaps without overwriting. The first source to supply a
            # value wins, and a later source disagreeing is recorded as a
            # discrepancy rather than silently resolved -- disagreement
            # between enumeration sources is itself evidence.
            for field_name in ("ppid", "exit_time_utc", "threads", "handles",
                               "session_id", "wow64"):
                current = entry.get(field_name)
                incoming = parsed.get(field_name)
                if current is None and incoming is not None:
                    entry[field_name] = incoming
                elif (
                    current is not None
                    and incoming is not None
                    and current != incoming
                ):
                    entry["notes"].append(
                        f"{plugin} reports {field_name}={incoming!r} where an "
                        f"earlier source reported {current!r}"
                    )

            if plugin == PSTREE:
                depth = raw_rows[i].get("__depth")
                if isinstance(depth, int):
                    entry["tree_depth"] = depth

    # ── pass 2: psxview, which has no creation time ──────────────────
    psxview_rows = indexed(context.rows(PSXVIEW))
    all_rows.extend(psxview_rows)
    for i, row in enumerate(psxview_rows):
        pid = as_int(row.get_field("PID", "Pid"))
        name = (as_str(row.get_field("Name", "ImageFileName", "Process")) or "").lower()
        if pid is None:
            continue

        candidates = [
            k for k in order
            if k[0] == pid and (not name or k[1] == name or not k[1])
        ]
        flags = _psxview_flags(row)

        if len(candidates) == 1:
            entry = merged[candidates[0]]
            entry["psxview"] = flags
            entry["seen_in"].add(PSXVIEW)
            entry["source_rows"].setdefault(PSXVIEW, i)
        elif len(candidates) > 1:
            # Ambiguous: several processes share this PID and name. Attach
            # to none of them. Guessing would put one process's cross-view
            # flags on another and manufacture or mask a hidden process.
            for key in candidates:
                merged[key]["notes"].append(
                    f"psxview row {i} matched {len(candidates)} processes with "
                    f"PID {pid}; its flags were not attached to any of them "
                    f"because the match is ambiguous"
                )
        else:
            # In psxview but in no other source: a process only the
            # cross-view plugin saw. That is a real record, not a stray.
            key = process_key(pid, name, None)
            if key not in merged:
                merged[key] = {
                    "pid": pid,
                    "name": as_str(row.get_field("Name", "ImageFileName",
                                                 "Process")),
                    "ppid": None, "create_time_utc": None, "exit_time_utc": None,
                    "threads": None, "handles": None, "session_id": None,
                    "wow64": None, "offsets": {}, "seen_in": {PSXVIEW},
                    "source_rows": {PSXVIEW: i}, "tree_depth": None,
                    "psxview": flags,
                    "notes": [
                        "this process was reported only by psxview; no other "
                        "enumeration source returned a matching row"
                    ],
                }
                order.append(key)

    collect_unmapped(context, "process sources", all_rows)
    paths = _image_paths(context)

    # ── emit ─────────────────────────────────────────────────────────
    # Sorted so that identifiers are assigned deterministically: two runs
    # over identical input must produce identical obs_ids or the
    # envelopes cannot be diffed.
    observations: list[Observation] = []
    for key in sorted(order, key=lambda k: (k[0] if k[0] is not None else -1,
                                            k[1], k[2])):
        entry = merged[key]
        seen = entry["seen_in"]

        cross_view = {}
        for plugin in (PSLIST, PSSCAN, PSTREE, PSXVIEW):
            state = availability[plugin]
            short = plugin.split(".", 1)[1]
            if state is None:
                cross_view[short] = None  # not established -- never False
            else:
                cross_view[short] = plugin in seen

        primary = next(
            (p for p in (PSLIST, PSSCAN, PSTREE, PSXVIEW) if p in seen), PSLIST
        )
        path_info = paths.get(entry["pid"]) if entry["pid"] is not None else None

        fields: dict[str, Any] = {
            "pid": entry["pid"],
            "ppid": entry["ppid"],
            "name": entry["name"],
            "path": path_info["path"] if path_info else None,
            "image_path_basis": path_info["basis"] if path_info else None,
            "create_time_utc": entry["create_time_utc"],
            "exit_time_utc": entry["exit_time_utc"],
            "threads": entry["threads"],
            "handles": entry["handles"],
            "session_id": entry["session_id"],
            "wow64": entry["wow64"],
            "offsets": dict(sorted(entry["offsets"].items())),
            "tree_depth": entry["tree_depth"],
            "cross_view": cross_view,
            "cross_view_note": (
                "true = the source returned this process; false = the source ran "
                "and did not; null = the source did not run, so nothing is "
                "established either way"
            ),
            "psxview_flags": entry["psxview"] or None,
            "source_rows": dict(sorted(entry["source_rows"].items())),
        }

        observations.append(
            context.observation(
                "process",
                plugin=primary,
                row_index=entry["source_rows"].get(primary, -1),
                offset=entry["offsets"].get(primary)
                or next(iter(entry["offsets"].values()), None),
                fields=fields,
                corroborating=sorted(seen),
                notes=_dedupe(entry["notes"]),
            )
        )

    return observations


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out
