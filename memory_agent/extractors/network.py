"""
memory_agent.extractors.network
─────────────────────────────────────────────────────────────────────
Sockets and connections from ``netscan`` and ``netstat``.

The two sources are not interchangeable and the difference is
evidentially significant. ``netstat`` walks the live network structures
and reports what the system currently believes is open. ``netscan``
carves connection objects out of pool memory, so it also returns
connections that were *closed before capture* -- their structures are
freed but not yet overwritten.

A closed connection recovered by netscan is often the most valuable
artifact in the image: the exfiltration finished, the socket closed, the
process exited, and the pool memory is the only remaining record. So
netscan-only rows are kept, and flagged as netscan-only rather than
being quietly presented as live connections. ``state`` is reported
exactly as the plugin gave it; this tier does not decide what
"ESTABLISHED" implies about a socket that no longer exists.

Addresses are classified here (loopback / private / multicast / public)
because that is a fact about the address, computable from the address
alone. Whether a public address is *suspicious* is MEM-N-001's call.
"""

from __future__ import annotations

import ipaddress
from typing import Any, Iterable

from ..core.rows import IndexedRow, as_hex, as_int, as_str, parse_timestamp
from ..core.schema import Observation
from .base import ExtractionContext, collect_unmapped, indexed

NETSCAN = "windows.netscan"
NETSTAT = "windows.netstat"


def classify_address(value: str | None) -> dict[str, Any]:
    """
    Structural facts about an address. No judgement.

    ``scope`` is one of unspecified / loopback / private / link_local /
    multicast / reserved / public, or ``unparseable`` when the value is
    not an IP at all (netscan renders ``*`` for a wildcard bind).
    """
    text = (value or "").strip()
    if not text or text in {"*", "::", "0.0.0.0"}:
        return {"scope": "unspecified", "version": None, "routable": False}

    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return {"scope": "unparseable", "version": None, "routable": None}

    if addr.is_loopback:
        scope = "loopback"
    elif addr.is_link_local:
        scope = "link_local"
    elif addr.is_multicast:
        scope = "multicast"
    elif addr.is_private:
        scope = "private"
    elif addr.is_reserved or addr.is_unspecified:
        scope = "reserved"
    else:
        scope = "public"

    return {
        "scope": scope,
        "version": addr.version,
        "routable": scope == "public",
    }


def _parse_row(row: IndexedRow) -> dict[str, Any]:
    created, created_note = parse_timestamp(
        row.get_field("Created", "CreateTime", "Create Time")
    )
    local_addr = as_str(row.get_field("LocalAddr", "Local Address", "LocalIP"))
    foreign_addr = as_str(row.get_field("ForeignAddr", "Foreign Address",
                                        "ForeignIP", "RemoteAddr"))
    return {
        "protocol": as_str(row.get_field("Proto", "Protocol")),
        "local_address": local_addr,
        "local_port": as_int(row.get_field("LocalPort", "Local Port")),
        "foreign_address": foreign_addr,
        "foreign_port": as_int(row.get_field("ForeignPort", "Foreign Port",
                                             "RemotePort")),
        "state": as_str(row.get_field("State")),
        "pid": as_int(row.get_field("PID", "Pid", "Owner PID")),
        "owner": as_str(row.get_field("Owner", "Process", "Owner Process")),
        "created_utc": created,
        "offset": as_hex(row.get_field("Offset", "Offset(V)", "Offset (V)")),
        "_notes": [created_note] if created_note else [],
    }


def _identity(parsed: dict[str, Any]) -> tuple:
    return (
        (parsed["protocol"] or "").lower(),
        parsed["local_address"] or "",
        parsed["local_port"],
        parsed["foreign_address"] or "",
        parsed["foreign_port"],
        (parsed["state"] or "").upper(),
        parsed["pid"],
    )


def extract_network(context: ExtractionContext) -> Iterable[Observation]:
    availability = {p: context.availability(p) for p in (NETSCAN, NETSTAT)}

    if all(state is None for state in availability.values()):
        context.note_absent(
            NETSCAN,
            "no network observations could be produced; MEM-N-001 through "
            "MEM-N-003 and MEM-P-002 could not be evaluated",
        )
        return []

    if availability[NETSCAN] is None:
        context.note_absent(
            NETSCAN,
            "connections that closed before capture cannot be recovered from "
            "netstat alone, so pre-capture network activity may be missing "
            "entirely from this analysis",
        )

    merged: dict[tuple, dict[str, Any]] = {}
    order: list[tuple] = []
    all_rows: list[IndexedRow] = []

    for plugin in (NETSCAN, NETSTAT):
        rows = indexed(context.rows(plugin))
        all_rows.extend(rows)
        for i, row in enumerate(rows):
            parsed = _parse_row(row)
            if not parsed["local_address"] and not parsed["foreign_address"]:
                continue

            key = _identity(parsed)
            entry = merged.get(key)
            if entry is None:
                entry = dict(parsed)
                entry["seen_in"] = set()
                entry["source_rows"] = {}
                entry["notes"] = list(parsed["_notes"])
                merged[key] = entry
                order.append(key)

            entry["seen_in"].add(plugin)
            entry["source_rows"].setdefault(plugin, i)
            for field_name in ("owner", "created_utc", "offset"):
                if entry.get(field_name) is None and parsed.get(field_name):
                    entry[field_name] = parsed[field_name]

    collect_unmapped(context, "network sources", all_rows)

    observations: list[Observation] = []
    for key in sorted(order, key=lambda k: tuple(
        "" if part is None else str(part) for part in k
    )):
        entry = merged[key]
        seen = entry["seen_in"]
        primary = NETSCAN if NETSCAN in seen else NETSTAT

        local = classify_address(entry["local_address"])
        foreign = classify_address(entry["foreign_address"])

        notes = list(entry["notes"])
        if seen == {NETSCAN} and availability[NETSTAT] is not None:
            notes.append(
                "recovered by the pool scan only. netstat ran and did not report "
                "it, which is what a connection that closed before capture looks "
                "like -- the state field reflects the socket's last recorded "
                "state, not its state at the moment of acquisition"
            )

        fields: dict[str, Any] = {
            "protocol": entry["protocol"],
            "local_address": entry["local_address"],
            "local_port": entry["local_port"],
            "local_scope": local["scope"],
            "foreign_address": entry["foreign_address"],
            "foreign_port": entry["foreign_port"],
            "foreign_scope": foreign["scope"],
            "foreign_routable": foreign["routable"],
            "ip_version": foreign["version"] or local["version"],
            "state": entry["state"],
            "pid": entry["pid"],
            "owner": entry["owner"],
            "created_utc": entry["created_utc"],
            "sources": sorted(seen),
            "netscan_only": seen == {NETSCAN},
            "source_rows": dict(sorted(entry["source_rows"].items())),
        }

        observations.append(
            context.observation(
                "network",
                plugin=primary,
                row_index=entry["source_rows"].get(primary, -1),
                offset=entry["offset"],
                fields=fields,
                corroborating=sorted(seen),
                notes=notes,
            )
        )

    return observations
