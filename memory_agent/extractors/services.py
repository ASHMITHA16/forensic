"""
memory_agent.extractors.services
─────────────────────────────────────────────────────────────────────
Registered services and the binaries behind them.

Services are the most durable persistence mechanism on Windows: they
survive reboot, run before the user logs in, and frequently run as
SYSTEM. ``svcscan`` recovers the service records resident in memory,
including the binary path each one launches.

Two normalisations happen here and neither is a judgement:

* The binary path is split into a command and its arguments, because a
  service binary is often ``svchost.exe -k netsvcs`` and the interesting
  part is the ``-k`` group, not the host process.
* ``%SystemRoot%``-style variables are recorded as-is *and* expanded to
  a canonical form for comparison. The unexpanded original is kept
  because it is what was actually in memory; the expansion exists so
  that a rule comparing directories is not defeated by a variable.

Where a service's binary sits is a fact. That ``\\Users\\Public`` is an
unusual place for one is MEM-S-001's opinion.
"""

from __future__ import annotations

import re
from typing import Any, Iterable

from ..core.rows import IndexedRow, as_hex, as_int, as_str
from ..core.schema import Observation
from .base import ExtractionContext, collect_unmapped, indexed
from .commands import basename, split_command

SVCSCAN = "windows.svcscan"

#: Environment variables Windows expands in service binary paths. Values
#: are the conventional defaults; the observation records that these are
#: assumed, since the image's actual values were not read.
_ENV_DEFAULTS = {
    "%systemroot%": "c:\\windows",
    "%windir%": "c:\\windows",
    "%systemdrive%": "c:",
    "%programfiles%": "c:\\program files",
    "%programfiles(x86)%": "c:\\program files (x86)",
    "%programdata%": "c:\\programdata",
}

_ENV_RE = re.compile(r"%[A-Za-z0-9_()]+%")


def expand_path(path: str | None) -> tuple[str | None, list[str]]:
    """
    Canonical lower-case path with known variables expanded.

    Returns ``(expanded, unresolved_variables)``. An unresolved variable
    is reported rather than left in place silently, because a rule that
    compares directory prefixes would otherwise return a confident "not
    in System32" for a path that expands to exactly System32.
    """
    if not path:
        return None, []

    text = path.strip().strip('"').replace("/", "\\")
    lowered = text.lower()

    # \??\C:\... and \SystemRoot\... prefixes appear in kernel-sourced paths.
    lowered = re.sub(r"^\\\?\?\\", "", lowered)
    lowered = re.sub(r"^\\systemroot\\", "c:\\\\windows\\\\", lowered)

    unresolved: list[str] = []
    for match in _ENV_RE.findall(lowered):
        replacement = _ENV_DEFAULTS.get(match.lower())
        if replacement:
            lowered = lowered.replace(match, replacement)
        elif match not in unresolved:
            unresolved.append(match)

    return re.sub(r"\\{2,}", "\\\\", lowered), unresolved


def extract_services(context: ExtractionContext) -> Iterable[Observation]:
    if context.availability(SVCSCAN) is None:
        context.note_absent(
            SVCSCAN,
            "registered services were not enumerated, so MEM-S-001 (service "
            "binary in an unusual directory) could not be evaluated",
        )
        return []

    rows = indexed(context.rows(SVCSCAN))

    observations: list[Observation] = []
    for i, row in enumerate(rows):
        binary_raw = as_str(row.get_field("Binary", "BinaryPath", "Binary Path"))
        registry_binary = as_str(
            row.get_field("Binary (Registry)", "BinaryRegistry", "ImagePath")
        )
        chosen = binary_raw or registry_binary
        executable, arguments = split_command(chosen or "")
        expanded, unresolved = expand_path(executable)

        notes: list[str] = []
        if unresolved:
            notes.append(
                f"environment variables {', '.join(unresolved)} in the service "
                f"binary path could not be expanded; directory comparisons "
                f"against this path are unreliable"
            )
        if binary_raw and registry_binary and binary_raw != registry_binary:
            notes.append(
                f"the in-memory service record and the registry ImagePath "
                f"disagree ({binary_raw!r} vs {registry_binary!r})"
            )

        fields: dict[str, Any] = {
            "name": as_str(row.get_field("Name", "Service Name", "ServiceName")),
            "display_name": as_str(row.get_field("Display", "DisplayName",
                                                 "Display Name")),
            "pid": as_int(row.get_field("PID", "Pid", "Process ID")),
            "state": as_str(row.get_field("State")),
            "start_type": as_str(row.get_field("Start", "StartType",
                                               "Start Type")),
            "service_type": as_str(row.get_field("Type", "ServiceType")),
            "order": as_int(row.get_field("Order")),
            "binary_raw": chosen,
            "binary_registry": registry_binary,
            "executable": executable,
            "executable_name": basename(executable),
            "executable_path_normalised": expanded,
            "path_variables_unresolved": unresolved,
            "arguments": arguments,
            "sources": [SVCSCAN],
        }

        observations.append(
            context.observation(
                "service", plugin=SVCSCAN, row_index=i,
                offset=as_hex(row.get_field("Offset", "Offset(V)")),
                fields=fields, notes=notes,
            )
        )
    collect_unmapped(context, SVCSCAN, rows)

    return observations
