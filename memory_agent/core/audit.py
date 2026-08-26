"""
memory_agent.core.audit
─────────────────────────────────────────────────────────────────────
Append-only, hash-chained audit trail.

Every action the agent takes is written as one JSON object per line to
``audit.jsonl``. Each entry embeds the SHA-256 of the *previous* entry:

    entry[0].prev_hash = "000...0"            (genesis)
    entry[n].prev_hash = sha256(line[n-1])

What the chain does and does not prove
──────────────────────────────────────
A hash chain with no key and no external anchor detects *casual* tampering
-- an entry edited, deleted, inserted or reordered in place. It does **not**
resist an attacker who can rewrite the whole file, because they can simply
renumber every entry and recompute every link. Nothing inside the file can
prevent that; the chain has no secret.

What defeats a full rewrite is an anchor held *outside* the trail. This
module produces one at ``seal()`` time -- ``final_chain_hash`` and
``log_sha256`` -- which the caller embeds in ``custody.json`` and, in a real
deployment, would also record somewhere the analysis host cannot reach.
``verify_chain()`` accepts those values and reports **two distinct
verdicts**:

  * ``valid``           -- the chain is internally consistent
  * ``anchor_verified`` -- it also matches a known-good external anchor

Only the second is proof against a determined attacker, and the CLI is
required to say which one it got. Reporting "INTACT" for the first alone
would be exactly the kind of overclaim this agent is built to avoid.

The chain's real value is *localisation*: verification reports the exact
sequence number at which the record diverges, so entries before it stay
provably intact while everything after is provably suspect.

Completeness is checked separately from validity. A trail must begin with
``audit.open`` and end with ``audit.close``, and the count recorded in the
closing entry must match what was actually read -- which is what catches
truncation and post-close appending, neither of which breaks the links.

Design constraints honoured here:
  * append-only -- entries are never rewritten or deleted
  * flushed and fsynced per entry, so a crash preserves the trail
  * deterministic serialisation (sorted keys, no whitespace) so the same
    logical entry always produces the same hash
  * stdlib only -- no third-party dependencies
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from .errors import AuditError

GENESIS_HASH = "0" * 64

OPEN_EVENT = "audit.open"
CLOSE_EVENT = "audit.close"

#: Serialisation used for hashing. Must stay byte-stable forever --
#: changing it would invalidate every previously written audit trail.
#: Note the absence of ``default``: nothing is silently coerced. Values
#: that JSON cannot represent are converted by ``_sanitize`` first, which
#: marks the coercion in the record instead of hiding it.
_JSON_ARGS: dict[str, Any] = {
    "sort_keys": True,
    "separators": (",", ":"),
    "ensure_ascii": True,
}

#: Cap on a single coerced value's textual form, so one pathological
#: object cannot bloat the trail.
_MAX_COERCED_REPR = 512


def utc_now_iso() -> str:
    """Current UTC time as an RFC-3339 string with millisecond precision."""
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


def _hash_line(line: str) -> str:
    return hashlib.sha256(line.encode("utf-8")).hexdigest()


def _sanitize(value: Any, _depth: int = 0) -> Any:
    """
    Make ``value`` JSON-serialisable, marking anything that had to be
    converted.

    An append-only forensic record must never quietly change the data it
    was handed. Where a lossless representation exists (bytes -> hex,
    set -> sorted list) it is used; anything else is wrapped in an
    explicit marker so a reader can see that coercion happened and what
    the original type was.

    Dict keys are coerced to strings because ``sort_keys=True`` cannot
    order mixed-type keys -- a PID-keyed dict from a Volatility plugin
    would otherwise raise ``TypeError`` from inside the writer.
    """
    if _depth > 32:
        return {"__coerced__": "max-depth", "__type__": type(value).__name__}

    if value is None or isinstance(value, (bool, int, float, str)):
        # Reject non-finite floats: JSON has no representation for them
        # and json.dumps would emit invalid `NaN` / `Infinity` literals.
        if isinstance(value, float) and value != value:
            return {"__coerced__": "NaN", "__type__": "float"}
        if isinstance(value, float) and value in (float("inf"), float("-inf")):
            return {"__coerced__": str(value), "__type__": "float"}
        return value

    if isinstance(value, (bytes, bytearray, memoryview)):
        raw = bytes(value)
        return {
            "__bytes_hex__": raw[:_MAX_COERCED_REPR].hex(),
            "__len__": len(raw),
            "__truncated__": len(raw) > _MAX_COERCED_REPR,
        }

    if isinstance(value, dict):
        return {str(k): _sanitize(v, _depth + 1) for k, v in value.items()}

    if isinstance(value, (list, tuple)):
        return [_sanitize(v, _depth + 1) for v in value]

    if isinstance(value, (set, frozenset)):
        return sorted(_sanitize(v, _depth + 1) for v in value)

    if isinstance(value, (datetime,)):
        return value.isoformat()

    if isinstance(value, Path):
        return str(value)

    text = repr(value)
    return {
        "__coerced__": text[:_MAX_COERCED_REPR],
        "__type__": type(value).__name__,
        "__truncated__": len(text) > _MAX_COERCED_REPR,
    }


class AuditLog:
    """
    An append-only hash-chained JSONL audit trail.

    Usage::

        with AuditLog(workspace.audit_path, run_id, case_id) as audit:
            audit.record("evidence.seal.begin", path=str(p))
            ...
        seal = audit.seal_info    # available after close
    """

    def __init__(self, path: str | os.PathLike[str], run_id: str, case_id: str) -> None:
        self.path = Path(path)
        self.run_id = run_id
        self.case_id = case_id
        self._seq = 0
        self._prev_hash = GENESIS_HASH
        self._fh = None
        self._closed = False
        self.seal_info: dict[str, Any] | None = None

        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            # "x" -- refuse to append to an existing trail. A run always
            # gets a fresh log; silently continuing someone else's chain
            # would make the sequence numbers meaningless.
            self._fh = self.path.open("x", encoding="utf-8", newline="\n")
        except FileExistsError as exc:
            raise AuditError(
                "Audit trail already exists; refusing to append to a foreign chain",
                path=str(self.path),
            ) from exc
        except OSError as exc:
            raise AuditError(
                f"Could not open audit trail for writing: {exc}",
                path=str(self.path),
            ) from exc

        try:
            self.record(
                OPEN_EVENT,
                run_id=run_id,
                case_id=case_id,
                agent="memory_analysis_agent",
            )
        except BaseException:
            # Leaving a zero-byte audit.jsonl behind would poison the
            # workspace: "x" mode makes every retry fail with "already
            # exists". Clean up so the run can be re-attempted.
            try:
                if self._fh is not None:
                    self._fh.close()
            finally:
                self._fh = None
                try:
                    self.path.unlink()
                except OSError:
                    pass
            raise

    # ── writing ───────────────────────────────────────────────────────

    def record(self, event: str, **data: Any) -> str:
        """
        Append one entry to the trail and return that entry's hash.

        ``event`` is a dotted identifier (``evidence.seal.complete``).
        ``data`` is arbitrary context; values JSON cannot represent are
        converted by ``_sanitize`` with an explicit marker.
        """
        if self._closed or self._fh is None:
            raise AuditError("Cannot record to a sealed audit trail", event=event)

        entry = {
            "seq": self._seq,
            "ts_utc": utc_now_iso(),
            "event": str(event),
            "data": _sanitize(data),
            "prev_hash": self._prev_hash,
        }

        try:
            line = json.dumps(entry, **_JSON_ARGS)
        except (TypeError, ValueError) as exc:
            # Must not escape the MemoryAgentError hierarchy -- the CLI
            # would surface a raw traceback instead of a structured error.
            raise AuditError(
                f"Audit entry could not be serialised: {exc}", event=event
            ) from exc

        try:
            self._fh.write(line + "\n")
            self._fh.flush()
        except OSError as exc:
            raise AuditError(
                f"Could not write to audit trail: {exc}", event=event
            ) from exc

        try:
            os.fsync(self._fh.fileno())
        except OSError:
            # fsync is unavailable on some filesystems; the flush above
            # still gets the bytes out of the process buffer.
            pass

        self._prev_hash = _hash_line(line)
        self._seq += 1
        return self._prev_hash

    # ── sealing ───────────────────────────────────────────────────────

    def seal(self) -> dict[str, Any]:
        """
        Close the trail and compute its overall digest.

        The seal record is deliberately *not* written into the log --
        doing so would change the very digest it reports. It is returned
        for embedding in ``custody.json``, where it becomes the external
        anchor that makes a full rewrite of the trail detectable.
        """
        if self._closed:
            if self.seal_info is None:
                raise AuditError(
                    "Audit trail is closed but was never sealed", path=str(self.path)
                )
            return self.seal_info

        # ``entries_written`` counts this closing entry too, so a verifier
        # can cross-check it against the number of lines actually present
        # and detect truncation or post-close appending.
        self.record(CLOSE_EVENT, entries_written=self._seq + 1)

        if self._fh is None:
            raise AuditError("Audit trail handle vanished before sealing")
        self._fh.close()
        self._fh = None
        self._closed = True

        digest = hashlib.sha256()
        try:
            with self.path.open("rb") as fh:
                for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                    digest.update(chunk)
        except OSError as exc:
            raise AuditError(
                f"Could not read audit trail to seal it: {exc}", path=str(self.path)
            ) from exc

        self.seal_info = {
            "log_path": str(self.path),
            "log_sha256": digest.hexdigest(),
            "entries": self._seq,
            "final_chain_hash": self._prev_hash,
            "sealed_utc": utc_now_iso(),
            "anchor_note": (
                "final_chain_hash and log_sha256 are the external anchors for "
                "this trail. Verification without them proves only internal "
                "consistency, not that the trail was never rewritten."
            ),
        }
        return self.seal_info

    # ── context manager ───────────────────────────────────────────────

    def __enter__(self) -> "AuditLog":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        try:
            if exc is not None and not self._closed:
                # Record the failure before sealing so the trail explains
                # why the run ended. Catch everything: losing the original
                # exception to a secondary failure in the logger would hide
                # the actual cause of the run failing.
                try:
                    self.record(
                        "audit.abort",
                        error_type=exc_type.__name__ if exc_type else "Unknown",
                        message=repr(exc),
                    )
                except Exception:  # noqa: BLE001 - deliberate
                    pass
        finally:
            if not self._closed:
                try:
                    self.seal()
                except Exception:  # noqa: BLE001 - never mask the real error
                    if self._fh is not None:
                        try:
                            self._fh.close()
                        except OSError:
                            pass
                        self._fh = None
                    self._closed = True

    # ── verification ──────────────────────────────────────────────────

    @staticmethod
    def read(path: str | os.PathLike[str]) -> Iterator[dict[str, Any]]:
        """Yield each entry of a trail in order."""
        with Path(path).open("r", encoding="utf-8") as fh:
            for raw in fh:
                raw = raw.rstrip("\n")
                if raw:
                    yield json.loads(raw)

    @staticmethod
    def verify_chain(
        path: str | os.PathLike[str],
        expected_final_hash: str | None = None,
        expected_log_sha256: str | None = None,
    ) -> dict[str, Any]:
        """
        Re-walk the hash chain of an existing trail.

        ``expected_final_hash`` and ``expected_log_sha256`` are the anchors
        produced by :meth:`seal` and stored in ``custody.json``. Supplying
        them is what turns internal consistency into actual proof.

        Returns::

            {"valid": bool,             # links and sequence are consistent
             "complete": bool,          # opens with audit.open, closes with
                                        # audit.close, count matches
             "anchor_verified": bool | None,   # None = no anchor supplied
             "entries": int,
             "broken_at_seq": int | None,
             "reason": str | None,
             "final_chain_hash": str | None,
             "log_sha256": str | None}
        """
        p = Path(path)
        if not p.is_file():
            raise AuditError("Audit trail not found", path=str(p))

        def failure(seq: int | None, count: int, reason: str) -> dict[str, Any]:
            return {
                "valid": False,
                "complete": False,
                "anchor_verified": False if expected_final_hash else None,
                "entries": count,
                "broken_at_seq": seq,
                "reason": reason,
                "final_chain_hash": None,
                "log_sha256": None,
            }

        prev = GENESIS_HASH
        count = 0
        first_event: str | None = None
        last_entry: dict[str, Any] | None = None

        with p.open("r", encoding="utf-8") as fh:
            for lineno, raw in enumerate(fh, 1):
                raw = raw.rstrip("\n")

                if not raw:
                    # Not skipped. A blank line means the bytes on disk
                    # differ from the certified content, and silently
                    # ignoring it would let an attacker pad the file.
                    return failure(
                        count, count, f"line {lineno} is blank (trail was edited)"
                    )

                try:
                    entry = json.loads(raw)
                except json.JSONDecodeError as exc:
                    return failure(
                        count, count, f"line {lineno} is not valid JSON: {exc.msg}"
                    )

                if not isinstance(entry, dict):
                    return failure(
                        count, count, f"line {lineno} is not a JSON object"
                    )

                if entry.get("seq") != count:
                    return failure(
                        count,
                        count,
                        f"sequence gap at line {lineno}: expected seq={count}, "
                        f"found seq={entry.get('seq')} (entry inserted or removed)",
                    )

                if entry.get("prev_hash") != prev:
                    return failure(
                        count,
                        count,
                        "hash chain broken: entry does not link to its "
                        "predecessor (content modified at or before this entry)",
                    )

                # Re-serialise deterministically rather than hashing the raw
                # line, so cosmetic reformatting is distinguished from a
                # change to the logical content.
                try:
                    canonical = json.dumps(entry, **_JSON_ARGS)
                except (TypeError, ValueError) as exc:
                    return failure(
                        count, count, f"line {lineno} cannot be re-serialised: {exc}"
                    )

                if canonical != raw:
                    return failure(
                        count,
                        count,
                        f"line {lineno} is not in canonical serialised form",
                    )

                if count == 0:
                    first_event = entry.get("event")
                last_entry = entry
                prev = _hash_line(canonical)
                count += 1

        # ── completeness ─────────────────────────────────────────────
        # The links alone cannot catch truncation (the surviving prefix is
        # a perfectly valid chain) or an append made after sealing (the
        # attacker just continues the chain). The bookend events and the
        # count recorded in the closing entry are what catch both.
        complete = True
        reason: str | None = None

        if count == 0:
            complete, reason = False, "trail is empty"
        elif first_event != OPEN_EVENT:
            complete, reason = False, f"trail does not begin with {OPEN_EVENT}"
        elif last_entry is not None and last_entry.get("event") != CLOSE_EVENT:
            complete, reason = (
                False,
                f"trail does not end with {CLOSE_EVENT}: it was truncated, or the "
                f"run terminated without sealing",
            )
        elif last_entry is not None:
            declared = last_entry.get("data", {}).get("entries_written")
            if declared != count:
                complete, reason = (
                    False,
                    f"entry count mismatch: closing record declares "
                    f"{declared} entries, {count} found (entries appended after "
                    f"sealing, or removed before it)",
                )

        # ── external anchor ──────────────────────────────────────────
        log_digest = hashlib.sha256()
        with p.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                log_digest.update(chunk)
        log_sha256 = log_digest.hexdigest()

        anchor_verified: bool | None = None
        if expected_final_hash is not None or expected_log_sha256 is not None:
            anchor_verified = True
            if expected_final_hash is not None and expected_final_hash != prev:
                anchor_verified = False
                reason = (
                    "final chain hash does not match the recorded anchor: the "
                    "trail was rewritten in full"
                )
            if expected_log_sha256 is not None and expected_log_sha256 != log_sha256:
                anchor_verified = False
                reason = reason or (
                    "audit log digest does not match the recorded anchor: the "
                    "file was modified after sealing"
                )

        return {
            "valid": True,
            "complete": complete,
            "anchor_verified": anchor_verified,
            "entries": count,
            "broken_at_seq": None,
            "reason": reason,
            "final_chain_hash": prev,
            "log_sha256": log_sha256,
        }
