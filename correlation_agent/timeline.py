"""
correlation_agent.timeline  (stage C4)
─────────────────────────────────────────────────────────────────────
One cross-domain timeline, built from real timestamps only.

The memory agent's design is explicit that only ``precision: exact``
(and bounded ``approximate``) events may be placed on a cross-domain
timeline. Findings without a timestamp are *counted* per domain in
``untimed_findings`` and never given a synthetic time: an invented
ordering is how a correlation agent reports a sequence of events that
never happened.

A known memory clock skew is subtracted so memory times line up with
the other sources; the adjustment is recorded on each event.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Mapping

from .core.constants import DOMAINS
from .core.entities import parse_iso, to_iso


def _shift(iso: str, seconds: float) -> str:
    return to_iso(datetime.fromtimestamp(parse_iso(iso) - seconds, tz=timezone.utc).isoformat()) or iso


def build_timeline(items: list[dict[str, Any]], correlations: list[dict[str, Any]],
                   memory: Mapping[str, Any] | None) -> tuple[list[dict[str, Any]], dict[str, int]]:
    corr_by_ref: dict[str, list[str]] = {}
    for c in correlations:
        for r in c["evidence_refs"]:
            corr_by_ref.setdefault(r, []).append(c["correlation_id"])

    skew = (memory or {}).get("clock_skew_seconds")
    skew = skew if isinstance(skew, (int, float)) and not isinstance(skew, bool) and skew else None

    def adjust(domain: str, iso: str) -> tuple[str, float | None]:
        if domain != "memory" or skew is None:
            return iso, None
        return _shift(iso, skew), -skew

    events: list[dict[str, Any]] = []
    for item in items:
        if not item["timestamp_utc"]:
            continue
        ts, adjusted = adjust(item["domain"], item["timestamp_utc"])
        events.append({
            "timestamp_utc": ts, "precision": "exact", "source_domain": item["domain"], "kind": "finding",
            "type": item["type"], "severity": item["severity"], "description": item["observation"],
            "evidence_ref": item["ref"], "correlation_refs": corr_by_ref.get(item["ref"], []),
            "clock_adjustment_s": adjusted,
        })

    # The memory agent's own timeline (process creates, socket opens) gives
    # context around the findings. Only exact / approximate events carry a time.
    for t in (memory or {}).get("timeline") or []:
        precision = t.get("precision") or "exact"
        iso = to_iso(t.get("timestamp"))
        if not iso or precision not in ("exact", "approximate"):
            continue
        ts, adjusted = adjust("memory", iso)
        events.append({
            "timestamp_utc": ts, "precision": precision, "source_domain": "memory", "kind": "context",
            "type": t.get("type") or "memory event", "severity": "info", "description": t.get("detail") or "",
            "evidence_ref": None, "correlation_refs": [], "clock_adjustment_s": adjusted,
        })

    events.sort(key=lambda e: (e["timestamp_utc"], e["source_domain"], str(e["evidence_ref"]), e["description"]))
    for n, e in enumerate(events, 1):
        e["event_id"] = f"CTL-{n:04d}"

    untimed = {d: sum(1 for i in items if i["domain"] == d and not i["timestamp_utc"]) for d in DOMAINS}
    return events, untimed
