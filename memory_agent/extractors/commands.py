"""
memory_agent.extractors.commands
─────────────────────────────────────────────────────────────────────
Command lines, console scrollback and typed history.

Three sources, three different evidentiary weights, and the difference
matters enough to be carried on every observation:

* ``cmdline`` reads the PEB's ``ProcessParameters``. It is the command
  line the process was *launched* with -- strong evidence, and the PEB is
  writable by the process itself, which is a known evasion.
* ``consoles`` recovers the console screen buffer: what was displayed,
  including output. Rich, and includes text the user never typed.
* ``cmdscan`` carves ``COMMAND_HISTORY`` structures. It recovers commands
  that were typed, including ones whose process has since exited -- and
  including entries from unallocated memory that may predate the session.

None of these is "the command that ran" in the same sense. So each
observation records its ``source_kind`` (``launch_parameters`` /
``console_buffer`` / ``typed_history``) and rules cite it. A detection
that fires on typed history is making a weaker claim than one firing on
launch parameters, and the finding needs to say so.

This extractor does not decide whether a command line is malicious. It
normalises whitespace, records the executable and the argument tail, and
stops. ``-enc`` means nothing here; it means something in MEM-C-001.
"""

from __future__ import annotations

import re
from typing import Any, Iterable

from ..core.rows import IndexedRow, as_int, as_str
from ..core.schema import Observation
from .base import ExtractionContext, clip, collect_unmapped, indexed

CMDLINE = "windows.cmdline"
CONSOLES = "windows.consoles"
CMDSCAN = "windows.cmdscan"

_WS_RE = re.compile(r"\s+")

#: Splitting a Windows command line properly requires CommandLineToArgvW
#: semantics. This is a deliberate approximation used only to recover the
#: executable token, and the observation says so.
_QUOTED_HEAD_RE = re.compile(r'^\s*"([^"]+)"')

#: Volatility renders a failure to read a process's parameters *into the
#: Args column itself*, as prose. Left alone, "Required memory at 0x0 is
#: not valid (process exited?)" becomes a command observation whose
#: executable is the word "Required" -- a fabricated artifact that a rule
#: could then match on. These are the renderings Vol3 has shipped.
_UNREADABLE_RE = re.compile(
    r"^\s*(?:"
    r"required memory at 0x[0-9a-f]+ is not valid"
    r"|unable to (?:read|access|parse)"
    r"|error(?:\s*:|\s+reading|\s+while)"
    r"|swapped\s*out"
    r"|not\s+(?:available|readable|valid)"
    r"|<?unreadable>?"
    r"|n/?a"
    r")",
    re.IGNORECASE,
)


def split_command(text: str) -> tuple[str | None, str | None]:
    """
    Split into (executable token, argument tail).

    Approximate by design: a quoted path is honoured, otherwise the first
    whitespace-delimited token is taken. An unquoted path containing
    spaces will therefore split wrongly -- which is itself a documented
    Windows ambiguity, and the reason the full string is always retained
    alongside the split.
    """
    if not text:
        return None, None

    match = _QUOTED_HEAD_RE.match(text)
    if match:
        head = match.group(1)
        tail = text[match.end():].strip()
        return head, tail or None

    parts = text.strip().split(None, 1)
    if not parts:
        return None, None
    return parts[0], (parts[1].strip() if len(parts) > 1 else None)


def basename(path: str | None) -> str | None:
    if not path:
        return None
    return re.split(r"[\\/]", path.strip().strip('"'))[-1] or None


def _emit(
    context: ExtractionContext,
    plugin: str,
    row_index: int,
    source_kind: str,
    pid: int | None,
    process: str | None,
    text: str | None,
    extra: dict[str, Any] | None = None,
    notes: list[str] | None = None,
) -> Observation | None:
    if not text or not text.strip():
        return None

    normalised = _WS_RE.sub(" ", text.strip())
    clipped, truncated = clip(normalised)
    executable, arguments = split_command(clipped or "")

    fields: dict[str, Any] = {
        "pid": pid,
        "process": process,
        "source_kind": source_kind,
        "command_line": clipped,
        "command_line_truncated": truncated,
        "executable": executable,
        "executable_name": basename(executable),
        "arguments": arguments,
        "length_chars": len(normalised),
    }
    if extra:
        fields.update(extra)

    all_notes = list(notes or [])
    if truncated:
        all_notes.append(
            "command text was truncated for the envelope; the complete string "
            "is in the raw plugin output in the case workspace"
        )
    return context.observation(
        "command", plugin=plugin, row_index=row_index,
        fields=fields, notes=all_notes,
    )


def extract_commands(context: ExtractionContext) -> Iterable[Observation]:
    observations: list[Observation] = []
    availability = {p: context.availability(p)
                    for p in (CMDLINE, CONSOLES, CMDSCAN)}

    if all(state is None for state in availability.values()):
        context.note_absent(
            CMDLINE,
            "no command observations could be produced; MEM-C-001 through "
            "MEM-C-003 could not be evaluated",
        )
        return []

    # ── cmdline ──────────────────────────────────────────────────────
    rows = indexed(context.rows(CMDLINE))
    for i, row in enumerate(rows):
        args = as_str(row.get_field("Args", "CommandLine", "Cmd", "Command"))
        # Vol3 renders unreadable parameters as an error string in the
        # Args column. That is a fact about the acquisition, not a command.
        note = None
        if args and _UNREADABLE_RE.match(args):
            note = (
                f"windows.cmdline could not read PID "
                f"{as_int(row.get_field('PID', 'Pid'))}'s parameters and "
                f"rendered {args!r} in their place; the page is most likely "
                f"swapped out, unmapped, or the process had exited. No command "
                f"observation was created for it."
            )
            args = None

        obs = _emit(
            context, CMDLINE, i, "launch_parameters",
            pid=as_int(row.get_field("PID", "Pid")),
            process=as_str(row.get_field("Process", "ImageFileName", "Name")),
            text=args,
            notes=[
                "read from the PEB ProcessParameters block, which is writable "
                "by the process itself and can therefore be overwritten after "
                "launch"
            ],
        )
        if obs:
            observations.append(obs)
        elif note:
            context.limit(note)
    collect_unmapped(context, CMDLINE, rows)

    # ── consoles ─────────────────────────────────────────────────────
    rows = indexed(context.rows(CONSOLES))
    for i, row in enumerate(rows):
        pid = as_int(row.get_field("PID", "Pid"))
        process = as_str(row.get_field("Process", "ImageFileName", "Name"))
        text = as_str(
            row.get_field("Cmd", "Command", "CommandHistory", "Screen",
                          "ScreenBuffer", "Dump", "Output")
        )
        obs = _emit(
            context, CONSOLES, i, "console_buffer",
            pid=pid, process=process, text=text,
            extra={
                "console_title": as_str(row.get_field("Title", "ConsoleTitle")),
                "attached_process": as_str(
                    row.get_field("AttachedProcess", "ConsoleProcess")
                ),
            },
            notes=[
                "recovered from the console screen buffer, which contains "
                "displayed output as well as typed input; a line here was not "
                "necessarily entered by the operator"
            ],
        )
        if obs:
            observations.append(obs)
    collect_unmapped(context, CONSOLES, rows)

    # ── cmdscan ──────────────────────────────────────────────────────
    rows = indexed(context.rows(CMDSCAN))
    for i, row in enumerate(rows):
        text = as_str(row.get_field("Cmd", "Command", "CommandHistory", "Value"))
        obs = _emit(
            context, CMDSCAN, i, "typed_history",
            pid=as_int(row.get_field("PID", "Pid")),
            process=as_str(row.get_field("Process", "ImageFileName", "Name")),
            text=text,
            extra={
                "history_offset": as_str(
                    row.get_field("CommandHistoryOffset", "Offset")
                ),
                "last_added": as_int(row.get_field("LastAdded")),
            },
            notes=[
                "carved from a COMMAND_HISTORY structure. Entries can survive "
                "the process that typed them and can originate in unallocated "
                "memory from an earlier session, so the owning PID is an "
                "attribution hint rather than an established link"
            ],
        )
        if obs:
            observations.append(obs)
    collect_unmapped(context, CMDSCAN, rows)

    return observations
