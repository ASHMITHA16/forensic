"""
memory_agent.core.rows
─────────────────────────────────────────────────────────────────────
Tolerant readers for Volatility 3 row dictionaries.

Volatility's JSON renderer uses the *display* column names as keys, and
those names are not a stable API. Across versions and plugins the same
value appears as ``PID`` / ``Pid`` / ``pid``, ``ImageFileName`` /
``Process`` / ``Name``, ``Offset(V)`` / ``Offset (V)`` / ``Offset``.
Hard-coding one spelling means a working extractor silently produces
empty observations after a routine ``pip install -U volatility3`` --
and empty observations mean absent findings, which look exactly like a
clean machine.

So every field is read through :func:`pick`, which matches on a
normalised key and takes the first name that is present. Anything an
extractor did not consume is reported as ``unmapped``, which is how a
column that got renamed shows up as a visible gap rather than as
silence.

Timestamps get the same treatment. Vol3 has emitted at least four
formats for the same field, and one of them is timezone-naive. A naive
timestamp is *not* assumed to be UTC here: it is recorded with a note
saying the zone was absent, because quietly labelling a local time as
UTC is how a timeline ends up confidently wrong by hours.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Mapping

#: Keys the renderer adds that are structural, not data.
STRUCTURAL_KEYS = frozenset({"__depth", "__parent_index", "__children"})

#: Values Volatility uses to mean "absent".
_NULLISH = frozenset({"", "-", "n/a", "na", "none", "null", "disabled", "unknown"})

_NORMALISE_RE = re.compile(r"[^a-z0-9]+")


def normalise_key(key: str) -> str:
    """``"Offset (V)"`` and ``"Offset(V)"`` and ``"offset_v"`` all agree."""
    return _NORMALISE_RE.sub("", str(key).lower())


def index_row(row: Mapping[str, Any]) -> dict[str, Any]:
    """
    Build a normalised-key view of a row.

    Later duplicates do not overwrite earlier ones: if a row genuinely
    has both ``Offset(V)`` and ``Offset (V)``, the first wins and the
    collision is not silently resolved in favour of whichever happened to
    be last in dict order.
    """
    indexed: dict[str, Any] = {}
    for key, value in row.items():
        if key in STRUCTURAL_KEYS:
            continue
        nk = normalise_key(key)
        if nk not in indexed:
            indexed[nk] = value
    return indexed


def pick(row: Mapping[str, Any], *names: str, default: Any = None) -> Any:
    """
    First present, non-null value among ``names``.

    Matching is on the normalised key, so callers list the spellings they
    know about and do not have to care about punctuation or case.
    """
    indexed = row if _looks_indexed(row) else index_row(row)
    for name in names:
        nk = normalise_key(name)
        if nk in indexed:
            value = indexed[nk]
            if value is not None:
                return value
    return default


def _looks_indexed(row: Mapping[str, Any]) -> bool:
    """Cheap check for an already-normalised mapping, to avoid re-indexing."""
    return isinstance(row, dict) and getattr(row, "_ma_indexed", False) is True


class IndexedRow(dict):
    """A row pre-normalised once, for extractors that read many fields."""

    _ma_indexed = True

    def __init__(self, row: Mapping[str, Any]) -> None:
        super().__init__(index_row(row))
        self.original: Mapping[str, Any] = row
        self.consumed: set[str] = set()

    def get_field(self, *names: str, default: Any = None) -> Any:
        # Every candidate name is marked consumed, not only the one that
        # matched. The point of `unmapped()` is to surface column names
        # this build has never heard of -- a rename after a Volatility
        # upgrade. A column the extractor asked for by name is known to
        # it whether or not that particular spelling was the one present.
        result = default
        found = False
        for name in names:
            nk = normalise_key(name)
            self.consumed.add(nk)
            if not found and nk in self and self[nk] is not None:
                result = self[nk]
                found = True
        return result

    def unmapped(self) -> list[str]:
        """
        Original column names this extractor never read.

        Surfaced in ``limitations`` so a renamed column is visible instead
        of producing a quietly empty field.
        """
        out = []
        for key in self.original:
            if key in STRUCTURAL_KEYS:
                continue
            if normalise_key(key) not in self.consumed:
                out.append(str(key))
        return sorted(out)


# ── scalar coercion ───────────────────────────────────────────────────


def is_nullish(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, str) and value.strip().lower() in _NULLISH:
        return True
    return False


def as_str(value: Any, default: str | None = None) -> str | None:
    if is_nullish(value):
        return default
    return str(value).strip()


def as_int(value: Any, default: int | None = None) -> int | None:
    """
    Integer, accepting the hex strings Volatility renders offsets as.

    ``bool`` is rejected explicitly: it is a subclass of ``int`` in
    Python, and letting ``True`` become ``1`` would turn a flag column
    into a plausible-looking PID.
    """
    if is_nullish(value) or isinstance(value, bool):
        return default
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value) if value.is_integer() else default
    text = str(value).strip().replace(",", "")
    try:
        if text.lower().startswith(("0x", "-0x")):
            return int(text, 16)
        return int(text, 10)
    except ValueError:
        try:
            return int(text, 16)
        except ValueError:
            return default


def as_bool(value: Any, default: bool | None = None) -> bool | None:
    if isinstance(value, bool):
        return value
    if is_nullish(value):
        return default
    text = str(value).strip().lower()
    if text in {"true", "yes", "y", "1", "enabled"}:
        return True
    if text in {"false", "no", "n", "0"}:
        return False
    return default


def as_hex(value: Any) -> str | None:
    """Render an offset canonically, so the same address is one string."""
    n = as_int(value)
    if n is None:
        return None
    return f"0x{n:x}" if n >= 0 else f"-0x{-n:x}"


# ── timestamps ────────────────────────────────────────────────────────

_TS_PATTERNS = (
    "%Y-%m-%d %H:%M:%S.%f%z",
    "%Y-%m-%d %H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S",
)

#: Below this, an "epoch" is far more likely to be a counter than a date.
_MIN_PLAUSIBLE_EPOCH = 946_684_800  # 2000-01-01T00:00:00Z
_MAX_PLAUSIBLE_EPOCH = 4_102_444_800  # 2100-01-01T00:00:00Z


def parse_timestamp(value: Any) -> tuple[str | None, str | None]:
    """
    Parse a Volatility timestamp into ``(iso_utc, note)``.

    ``note`` is non-None whenever something about the value had to be
    interpreted. The caller is expected to carry it into the observation:
    a timestamp whose timezone had to be assumed is a materially weaker
    fact than one that carried its own offset, and the timeline's
    ``precision`` field depends on knowing which it was.
    """
    if is_nullish(value):
        return None, None

    if isinstance(value, datetime):
        return _to_utc_iso(value), (
            None if value.tzinfo else "timestamp had no timezone; assumed UTC"
        )

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if _MIN_PLAUSIBLE_EPOCH <= float(value) <= _MAX_PLAUSIBLE_EPOCH:
            dt = datetime.fromtimestamp(float(value), tz=timezone.utc)
            return _to_utc_iso(dt), "parsed from a Unix epoch value"
        return None, f"numeric timestamp {value!r} is not a plausible date"

    text = str(value).strip()
    if not text or text.lower() in _NULLISH:
        return None, None

    # "+0000 UTC" and trailing zone names defeat %z.
    cleaned = re.sub(r"\s+(UTC|GMT|Z)$", "", text, flags=re.IGNORECASE).strip()
    cleaned = re.sub(r"(?<=[+-]\d{2}):(?=\d{2}$)", "", cleaned)

    for pattern in _TS_PATTERNS:
        try:
            dt = datetime.strptime(cleaned, pattern)
        except ValueError:
            continue
        if dt.tzinfo is None:
            # Deliberately not silently localised. Vol3 renders kernel
            # timestamps that are already UTC, but it has also rendered
            # naive local times; saying which assumption was made is the
            # difference between a defensible timeline and a guess.
            return _to_utc_iso(dt.replace(tzinfo=timezone.utc)), (
                "timestamp carried no timezone; recorded as UTC on the "
                "assumption that Volatility rendered a kernel UTC value"
            )
        return _to_utc_iso(dt), None

    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None, f"unrecognised timestamp format: {text!r}"
    if dt.tzinfo is None:
        return _to_utc_iso(dt.replace(tzinfo=timezone.utc)), (
            "timestamp carried no timezone; recorded as UTC"
        )
    return _to_utc_iso(dt), None


def _to_utc_iso(dt: datetime) -> str:
    return (
        dt.astimezone(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def iso_to_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def seconds_between(a: str | None, b: str | None) -> float | None:
    """``a - b`` in seconds, or None if either is unparseable."""
    da, db = iso_to_datetime(a), iso_to_datetime(b)
    if da is None or db is None:
        return None
    return (da - db).total_seconds()


def shift_iso(value: str, delta_s: float) -> str:
    dt = iso_to_datetime(value)
    if dt is None:
        return value
    return _to_utc_iso(dt + timedelta(seconds=delta_s))


def rows_of(results: Mapping[str, Any], plugin: str) -> list[dict[str, Any]]:
    """
    Rows for ``plugin``, or an empty list when it did not run.

    Extractors call this rather than indexing, so a missing or failed
    plugin degrades that extractor's coverage instead of raising.
    """
    result = results.get(plugin)
    if result is None:
        return []
    rows = getattr(result, "rows", None)
    if rows is None and isinstance(result, Mapping):
        rows = result.get("rows")
    if not isinstance(rows, list):
        return []
    return [r for r in rows if isinstance(r, dict)]


def dedupe_preserving_order(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for v in values:
        if v not in seen:
            seen.add(v)
            out.append(v)
    return out
