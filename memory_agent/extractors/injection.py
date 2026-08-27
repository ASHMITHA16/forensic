"""
memory_agent.extractors.injection
─────────────────────────────────────────────────────────────────────
Memory regions that hold code they should not.

``malfind`` reports private, committed, executable regions and dumps the
first bytes of each. Three facts are extracted per region and each is
recorded separately, because the rule downstream weighs them separately:

* the protection constant (is it writable *and* executable?)
* whether the region is private (unshared, not backed by a mapped file)
* whether the first bytes are ``4D 5A`` -- a DOS ``MZ`` header

The last one is the interesting case for honesty. ``MZ`` at offset zero
of an anonymous executable region is the signature of a reflectively
loaded PE. It is also two ASCII characters that occur in ordinary data
with modest probability, and JIT compilers (.NET, V8, the JVM) allocate
exactly this kind of region as a matter of routine operation.

So this extractor records ``starts_with_mz: true`` and the leading bytes
as hex, and does not use the word "injection" anywhere in the record.
MEM-I-001 makes that claim, at a confidence that reflects the JIT
possibility, with the JIT possibility written into the finding's
``alternative_explanations``.

``vadinfo`` and ``hollowprocesses`` add the mapped-file backing for each
region, which is what lets MEM-I-003 compare a process's image path
against what is actually mapped at its base address.
"""

from __future__ import annotations

import re
from typing import Any, Iterable

from ..core.rows import IndexedRow, as_hex, as_int, as_str
from ..core.schema import Observation
from .base import ExtractionContext, clip, collect_unmapped, indexed

MALFIND = "windows.malfind"
VADINFO = "windows.vadinfo"
HOLLOW = "windows.hollowprocesses"

#: Protection constants that permit both writing and execution. A page
#: that is writable and executable at the same time is unusual outside
#: of a JIT: ordinary code is mapped read-execute from a file on disk.
WX_PROTECTIONS = frozenset({
    "PAGE_EXECUTE_READWRITE",
    "PAGE_EXECUTE_WRITECOPY",
})

EXECUTABLE_PROTECTIONS = frozenset({
    "PAGE_EXECUTE",
    "PAGE_EXECUTE_READ",
    "PAGE_EXECUTE_READWRITE",
    "PAGE_EXECUTE_WRITECOPY",
})

_HEX_PAIR_RE = re.compile(r"\b([0-9a-fA-F]{2})\b")


def leading_bytes(hexdump: str | None, count: int = 16) -> str | None:
    """
    Recover the first bytes from a Volatility hexdump block.

    The hexdump is a rendered table -- offset column, hex columns, ASCII
    column -- and the ASCII column contains characters that look like hex
    pairs. Taking every two-character token would therefore mix ASCII
    into the byte stream. Parsing is restricted to the hex columns of the
    first lines, and returns None rather than a guess when the layout is
    not recognised.
    """
    if not hexdump:
        return None

    collected: list[str] = []
    for line in str(hexdump).splitlines():
        # Canonical form: "0x1234  4d 5a 90 00 ...  MZ......"
        body = line.split("\t")[0]
        parts = body.split()
        if not parts:
            continue
        # Drop a leading offset token, then take only tokens that are
        # exactly two hex digits, stopping at the first that is not.
        start = 1 if parts[0].lower().startswith("0x") or len(parts[0]) > 2 else 0
        for token in parts[start:]:
            if _HEX_PAIR_RE.fullmatch(token):
                collected.append(token.lower())
            else:
                break
        if len(collected) >= count:
            break

    if not collected:
        return None
    return " ".join(collected[:count])


def starts_with_mz(hex_bytes: str | None) -> bool | None:
    """True/False when the leading bytes are known, None when they are not."""
    if not hex_bytes:
        return None
    tokens = hex_bytes.split()
    if len(tokens) < 2:
        return None
    return tokens[0] == "4d" and tokens[1] == "5a"


def _protection(value: Any) -> str | None:
    text = as_str(value)
    if not text:
        return None
    return text.strip().upper().replace(" ", "_")


def extract_injections(context: ExtractionContext) -> Iterable[Observation]:
    observations: list[Observation] = []

    if context.availability(MALFIND) is None:
        context.note_absent(
            MALFIND,
            "private executable memory regions were not enumerated, so "
            "MEM-I-001 (code in private RWX memory) could not be evaluated",
        )

    # ── vadinfo: backing file per region, keyed by (pid, start) ──────
    vad_index: dict[tuple[int | None, int | None], dict[str, Any]] = {}
    vad_rows = indexed(context.rows(VADINFO))
    for i, row in enumerate(vad_rows):
        pid = as_int(row.get_field("PID", "Pid"))
        start = as_int(row.get_field("Start VPN", "StartVPN", "Start", "Offset"))
        vad_index[(pid, start)] = {
            "row_index": i,
            "file": as_str(row.get_field("File", "FileName", "MappedPath",
                                         "Filename")),
            "protection": _protection(row.get_field("Protection")),
            "tag": as_str(row.get_field("Tag")),
            "private": row.get_field("PrivateMemory", "Private Memory", "Private"),
            "commit": as_int(row.get_field("CommitCharge", "Commit Charge")),
        }

    # ── malfind ──────────────────────────────────────────────────────
    rows = indexed(context.rows(MALFIND))
    for i, row in enumerate(rows):
        pid = as_int(row.get_field("PID", "Pid"))
        start = as_int(row.get_field("Start VPN", "StartVPN", "Start"))
        end = as_int(row.get_field("End VPN", "EndVPN", "End"))
        protection = _protection(row.get_field("Protection"))
        private_raw = row.get_field("PrivateMemory", "Private Memory", "Private")
        private = (
            bool(private_raw) if isinstance(private_raw, bool)
            else (as_int(private_raw) == 1 if private_raw is not None else None)
        )

        hexdump = row.get_field("Hexdump", "Hex Dump", "Data")
        head = leading_bytes(hexdump)
        mz = starts_with_mz(head)

        disasm, disasm_truncated = clip(as_str(row.get_field("Disasm",
                                                             "Disassembly")), 2000)
        vad = vad_index.get((pid, start), {})

        notes: list[str] = []
        if head is None:
            notes.append(
                "the leading bytes of this region could not be parsed from the "
                "plugin's hexdump, so no PE-header check was possible"
            )

        size = None
        if start is not None and end is not None and end >= start:
            size = end - start

        fields: dict[str, Any] = {
            "pid": pid,
            "process": as_str(row.get_field("Process", "ImageFileName", "Name")),
            "region_start": as_hex(start),
            "region_end": as_hex(end),
            "region_size_bytes": size,
            "protection": protection,
            "writable_and_executable": (
                protection in WX_PROTECTIONS if protection else None
            ),
            "executable": (
                protection in EXECUTABLE_PROTECTIONS if protection else None
            ),
            "private_memory": private,
            "vad_tag": as_str(row.get_field("Tag")) or vad.get("tag"),
            "commit_charge": as_int(row.get_field("CommitCharge",
                                                  "Commit Charge"))
            or vad.get("commit"),
            "backing_file": vad.get("file"),
            "leading_bytes_hex": head,
            "starts_with_mz": mz,
            "disassembly_excerpt": disasm,
            "disassembly_truncated": disasm_truncated,
            "plugin_notes": as_str(row.get_field("Notes")),
            "sources": sorted({MALFIND} | ({VADINFO} if vad else set())),
        }

        observations.append(
            context.observation(
                "injection", plugin=MALFIND, row_index=i, offset=as_hex(start),
                fields=fields, corroborating=fields["sources"], notes=notes,
            )
        )

    collect_unmapped(context, VADINFO, vad_rows)
    collect_unmapped(context, MALFIND, rows)

    # ── hollowprocesses ──────────────────────────────────────────────
    rows = indexed(context.rows(HOLLOW))
    for i, row in enumerate(rows):
        eprocess_path = as_str(row.get_field("Process Path", "ProcessPath",
                                             "Image Path", "Path"))
        vad_path = as_str(row.get_field("VAD Path", "VadPath", "Mapped Path",
                                        "File"))
        observations.append(
            context.observation(
                "injection", plugin=HOLLOW, row_index=i,
                offset=as_hex(row.get_field("Base", "Offset")),
                fields={
                    "pid": as_int(row.get_field("PID", "Pid")),
                    "process": as_str(row.get_field("Process", "ImageFileName",
                                                    "Name")),
                    "kind": "image_path_discrepancy",
                    "eprocess_image_path": eprocess_path,
                    "vad_backing_path": vad_path,
                    "paths_agree": (
                        None if not (eprocess_path and vad_path)
                        else eprocess_path.strip().lower().replace("/", "\\")
                        == vad_path.strip().lower().replace("/", "\\")
                    ),
                    "plugin_notes": as_str(row.get_field("Notes", "Note",
                                                         "Reason")),
                    "sources": [HOLLOW],
                },
            )
        )
    collect_unmapped(context, HOLLOW, rows)

    return observations
