"""
memory_agent.core.evidence
─────────────────────────────────────────────────────────────────────
Evidence integrity: hashing, read-only handling, and chain of custody.

This module is the foundation the rest of the agent stands on. Every
finding the agent eventually emits is only as defensible as the proof
that the bytes it was derived from never changed while the agent held
them.

The protocol implemented here:

  1. PRE-ANALYSIS SEAL   -- stream the dump once, computing SHA-256 and
                            MD5 together; capture size, inode, device
                            and timestamps *both before and after* the
                            pass, so a file that changed underneath us
                            cannot produce a seal nobody can reproduce.
  2. READ-ONLY ACCESS    -- every open of the evidence goes through
                            ``open_readonly``, which uses ``os.O_RDONLY``
                            and never a write mode.
  3. POST-ANALYSIS VERIFY -- recompute and re-stat; compare against the
                            seal. Content drift invalidates the run;
                            metadata drift is reported separately.

A deliberate note on what this does *not* claim
───────────────────────────────────────────────
Software cannot make a file physically immutable. What this module
guarantees is narrower and honest: the agent itself never opens the
evidence for writing, and any modification by *anything* -- the agent, a
Volatility plugin, another process, the operating system -- is detected
and reported. Genuine write-protection is a job for a hardware write
blocker or a read-only mount, and the report should say so. Overclaiming
here would be the kind of error that gets findings excluded.

Reading a file updates its access time on a default-mounted volume, so
the agent does touch evidence *metadata* even though it never touches
the bytes. ``O_NOATIME`` is requested where the platform supports it and
the caller owns the file; where it is unavailable, ``st_atime_ns`` is
recorded in the seal so the change is at least on the record rather than
silently denied.

Standard practice is to work from a forensic copy and leave the original
untouched; this module verifies whichever file it is pointed at.
"""

from __future__ import annotations

import hashlib
import os
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from .audit import utc_now_iso
from .errors import (
    EvidenceEmpty,
    EvidenceNotAFile,
    EvidenceNotFound,
    EvidenceTampered,
    EvidenceUnreadable,
)

#: Read size for streaming hashes. 8 MiB balances syscall overhead
#: against memory footprint and is comfortable for multi-gigabyte dumps.
CHUNK_SIZE = 8 * 1024 * 1024

#: Below this size a "memory dump" is almost certainly the wrong file
#: (a text file, a truncated transfer). Warned about, never fatal --
#: the investigator decides what is evidence, not the tool.
IMPLAUSIBLE_DUMP_BYTES = 1 * 1024 * 1024

#: On Windows a file must be opened in binary mode explicitly or the
#: runtime performs newline translation and corrupts the byte stream.
_O_BINARY = getattr(os, "O_BINARY", 0)

#: Linux-only, best-effort: suppresses the access-time update on read.
#: Requires file ownership; EPERM is expected and handled by retrying
#: without it.
_O_NOATIME = getattr(os, "O_NOATIME", 0)

ProgressCallback = Callable[[int, int], None]


# ── Data records ──────────────────────────────────────────────────────


@dataclass(frozen=True)
class EvidenceSeal:
    """
    An immutable snapshot of the evidence taken before analysis begins.

    ``sha256`` is the primary integrity anchor. ``md5`` is recorded only
    so that results can be cross-checked against legacy tools that still
    report MD5; it is never relied on alone, MD5 being collision-broken.

    ``stable_during_hash`` records whether size and mtime were identical
    before and after the hashing pass. A ``False`` here means the file
    was being written while it was read, and the ``(size_bytes, sha256)``
    pair describes an indeterminate range of bytes that nobody -- not
    even this tool -- can reproduce.
    """

    evidence_id: str
    file_name: str
    absolute_path: str
    size_bytes: int
    sha256: str
    md5: str
    computed_utc: str
    st_mtime_ns: int
    st_atime_ns: int
    st_ino: int
    st_dev: int
    hash_duration_s: float
    stable_during_hash: bool = True
    inode_available: bool = True
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class IntegrityReport:
    """
    The result of comparing a post-analysis state against a seal.

    ``discrepancies`` holds only findings that **invalidate** the run:
    the content changed, or the path now refers to a different file.
    ``metadata_notes`` holds informational drift that does not invalidate
    anything -- an mtime touch with an identical digest, for instance.

    Keeping them apart matters because a caller checking
    ``len(discrepancies) > 0`` is making the obvious reading of the field
    name, and that reading must not raise a false tamper alarm.
    """

    integrity_verified: bool
    sha256_before: str
    sha256_after: str
    size_before: int
    size_after: int
    metadata_stable: bool
    checked_utc: str
    verification_method: str = "reread"
    inode_check: str = "performed"
    discrepancies: list[str] = field(default_factory=list)
    metadata_notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ChainOfCustody:
    """
    The custody record for one analysis run.

    Custody events are appended as the run progresses; the completed
    record is embedded in the output envelope and written to disk
    alongside the audit trail.
    """

    case_id: str
    evidence_id: str
    run_id: str
    investigator: str | None = None
    acquisition: dict[str, Any] = field(default_factory=dict)
    events: list[dict[str, Any]] = field(default_factory=list)

    def add_event(self, action: str, actor: str = "memory_analysis_agent", **detail: Any) -> None:
        self.events.append(
            {
                "seq": len(self.events),
                "ts_utc": utc_now_iso(),
                "actor": actor,
                "action": action,
                "detail": detail,
            }
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ── Preconditions ─────────────────────────────────────────────────────


def validate_evidence_path(path: str | os.PathLike[str]) -> Path:
    """
    Check that ``path`` is something the agent can analyse.

    Raises the specific ``EvidenceError`` subclass describing the
    failure, so the caller can serialise a precise reason rather than a
    generic "file problem".
    """
    p = Path(path).expanduser()

    try:
        p = p.resolve(strict=True)
    except FileNotFoundError as exc:
        raise EvidenceNotFound("Evidence file does not exist", path=str(path)) from exc
    except OSError as exc:
        raise EvidenceUnreadable(
            f"Evidence path could not be resolved: {exc}", path=str(path)
        ) from exc

    if not p.is_file():
        kind = "directory" if p.is_dir() else "special file (device, socket or FIFO)"
        raise EvidenceNotAFile(
            f"Evidence path is a {kind}, not a regular file. This build analyses "
            f"memory dump files only; live devices and raw volumes are out of scope.",
            path=str(p),
        )

    if not os.access(p, os.R_OK):
        raise EvidenceUnreadable(
            "Evidence file exists but is not readable by this process", path=str(p)
        )

    if p.stat().st_size == 0:
        raise EvidenceEmpty("Evidence file is zero bytes", path=str(p))

    return p


# ── Read-only access ──────────────────────────────────────────────────


class open_readonly:
    """
    Context manager yielding a read-only binary handle on the evidence.

    Opened via ``os.open`` with ``O_RDONLY`` explicitly, rather than
    ``Path.open("rb")``, so that the read-only intent is expressed at the
    syscall boundary and is visible to anyone auditing this code. This is
    the *only* sanctioned way for the agent to touch evidence bytes.

    ``O_NOATIME`` is added where available so that reading the evidence
    does not update its access time. It requires ownership of the file,
    so ``EPERM`` is expected and falls back to a plain read-only open.
    """

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = Path(path)
        self.noatime_applied = False
        self._fd: int | None = None
        self._fh = None

    def _open_fd(self) -> int:
        base_flags = os.O_RDONLY | _O_BINARY
        if _O_NOATIME:
            try:
                fd = os.open(self.path, base_flags | _O_NOATIME)
                self.noatime_applied = True
                return fd
            except PermissionError:
                pass  # not the owner; fall through
            except OSError:
                pass  # filesystem does not support it
        return os.open(self.path, base_flags)

    def __enter__(self):
        try:
            self._fd = self._open_fd()
            self._fh = os.fdopen(self._fd, "rb", closefd=True)
        except OSError as exc:
            if self._fd is not None:
                try:
                    os.close(self._fd)
                except OSError:
                    pass
                self._fd = None
            raise EvidenceUnreadable(
                f"Could not open evidence read-only: {exc}", path=str(self.path)
            ) from exc
        return self._fh

    def __exit__(self, exc_type, exc, tb) -> None:
        if self._fh is not None:
            self._fh.close()
            self._fh = None
            self._fd = None


# ── Hashing ───────────────────────────────────────────────────────────


def compute_hashes(
    path: str | os.PathLike[str],
    chunk_size: int = CHUNK_SIZE,
    progress: ProgressCallback | None = None,
) -> tuple[str, str, float]:
    """
    Stream the file once, returning ``(sha256_hex, md5_hex, seconds)``.

    Both digests are computed in a single pass -- a multi-gigabyte dump
    should be read from disk once, not twice.

    ``progress`` is called as ``progress(bytes_done, bytes_total)``.
    """
    p = Path(path)
    total = p.stat().st_size

    sha = hashlib.sha256()
    # usedforsecurity=False keeps MD5 available on FIPS-restricted hosts,
    # where the default constructor raises. It is a cross-check value
    # only and carries no security weight here.
    try:
        md5 = hashlib.md5(usedforsecurity=False)  # type: ignore[call-arg]
    except TypeError:  # pragma: no cover - Python < 3.9
        md5 = hashlib.md5()

    done = 0
    started = datetime.now(timezone.utc)

    with open_readonly(p) as fh:
        while True:
            block = fh.read(chunk_size)
            if not block:
                break
            sha.update(block)
            md5.update(block)
            done += len(block)
            if progress is not None:
                progress(done, total)

    elapsed = (datetime.now(timezone.utc) - started).total_seconds()
    return sha.hexdigest(), md5.hexdigest(), elapsed


# ── Sealing and verification ──────────────────────────────────────────


def seal_evidence(
    path: str | os.PathLike[str],
    evidence_id: str | None = None,
    progress: ProgressCallback | None = None,
) -> EvidenceSeal:
    """
    Take the pre-analysis seal of the evidence file.

    This must be called before any analysis touches the dump.

    The file is stat'ed both before and after the hashing pass. If it
    changed in between -- an acquisition tool still writing, a mounted
    share being updated -- the resulting ``(size, digest)`` pair would
    describe an indeterminate byte range that nobody could reproduce.
    That is recorded as ``stable_during_hash=False`` with a prominent
    warning rather than being emitted as though it were authoritative.
    """
    p = validate_evidence_path(path)
    st_before = p.stat()

    warnings: list[str] = []
    if st_before.st_size < IMPLAUSIBLE_DUMP_BYTES:
        warnings.append(
            f"File is only {st_before.st_size} bytes, which is implausibly small "
            f"for a memory dump. Verify this is the intended evidence."
        )

    sha256, md5, elapsed = compute_hashes(p, progress=progress)

    st_after = p.stat()
    stable = (
        st_after.st_size == st_before.st_size
        and st_after.st_mtime_ns == st_before.st_mtime_ns
    )
    if not stable:
        warnings.append(
            f"THE FILE CHANGED WHILE IT WAS BEING HASHED "
            f"(size {st_before.st_size} -> {st_after.st_size}, "
            f"mtime {st_before.st_mtime_ns} -> {st_after.st_mtime_ns}). "
            f"The recorded digest covers an indeterminate range of bytes and "
            f"CANNOT BE REPRODUCED. Do not treat this seal as authoritative. "
            f"Ensure acquisition has finished, then re-seal."
        )

    # st_ino is 0 on filesystems that cannot supply one -- FAT/exFAT
    # removable media, some network shares, and Windows when the file
    # cannot be opened to query its NTFS index. A zero is "unknown", not
    # an identity, and must never be compared as though it were.
    inode_available = bool(st_after.st_ino) and bool(st_after.st_dev)
    if not inode_available:
        warnings.append(
            "This filesystem does not report a usable inode/device identity, so "
            "file-substitution detection is unavailable. Integrity still rests "
            "on the SHA-256 digest."
        )

    return EvidenceSeal(
        evidence_id=evidence_id or f"EV-MEM-{uuid.uuid4().hex[:8].upper()}",
        file_name=p.name,
        absolute_path=str(p),
        size_bytes=st_after.st_size if stable else st_before.st_size,
        sha256=sha256,
        md5=md5,
        computed_utc=utc_now_iso(),
        st_mtime_ns=st_after.st_mtime_ns,
        st_atime_ns=st_after.st_atime_ns,
        st_ino=st_after.st_ino,
        st_dev=st_after.st_dev,
        hash_duration_s=round(elapsed, 3),
        stable_during_hash=stable,
        inode_available=inode_available,
        warnings=warnings,
    )


def verify_from_seal(seal: EvidenceSeal) -> IntegrityReport:
    """
    Produce an integrity report from the seal alone, without re-reading.

    Used when the caller has done nothing since sealing that could have
    changed the evidence. Re-hashing a 32 GB dump to prove that the two
    seconds since the last pass left it untouched costs another full read
    for no evidentiary gain, so the report is marked
    ``verification_method="seal_only"`` and says exactly what it checked.
    """
    return IntegrityReport(
        integrity_verified=seal.stable_during_hash,
        sha256_before=seal.sha256,
        sha256_after=seal.sha256,
        size_before=seal.size_bytes,
        size_after=seal.size_bytes,
        metadata_stable=True,
        checked_utc=utc_now_iso(),
        verification_method="seal_only",
        inode_check="not applicable",
        discrepancies=(
            []
            if seal.stable_during_hash
            else ["Evidence changed during the hashing pass; the seal is not reproducible"]
        ),
        metadata_notes=[],
    )


def verify_seal(
    seal: EvidenceSeal,
    path: str | os.PathLike[str] | None = None,
    progress: ProgressCallback | None = None,
    raise_on_failure: bool = False,
) -> IntegrityReport:
    """
    Recompute the evidence state and compare it against ``seal``.

    Called after analysis completes. A mismatch means findings derived
    from this run are not defensible and the run must be marked INVALID.

    Content drift (digest, size) and identity drift (inode, device) go
    into ``discrepancies`` and invalidate the run. Timestamp drift with
    an intact digest goes into ``metadata_notes`` and does not.
    """
    p = Path(path) if path is not None else Path(seal.absolute_path)
    discrepancies: list[str] = []
    metadata_notes: list[str] = []

    if not p.is_file():
        report = IntegrityReport(
            integrity_verified=False,
            sha256_before=seal.sha256,
            sha256_after="",
            size_before=seal.size_bytes,
            size_after=-1,
            metadata_stable=False,
            checked_utc=utc_now_iso(),
            inode_check="not performed",
            discrepancies=["Evidence file is no longer present at the sealed path"],
        )
        if raise_on_failure:
            raise EvidenceTampered("Evidence disappeared during analysis", path=str(p))
        return report

    sha256, _md5, _elapsed = compute_hashes(p, progress=progress)
    st = p.stat()

    if sha256 != seal.sha256:
        discrepancies.append(f"SHA-256 mismatch: sealed {seal.sha256}, now {sha256}")
    if st.st_size != seal.size_bytes:
        discrepancies.append(
            f"Size changed: sealed {seal.size_bytes} bytes, now {st.st_size} bytes"
        )

    # Identity check -- only meaningful when both sides reported a real
    # inode. Comparing zeroes would "pass" vacuously; comparing a zero
    # against a real value would invalidate an intact dump.
    if not seal.inode_available or not st.st_ino or not st.st_dev:
        inode_check = "unavailable on this filesystem"
        metadata_notes.append(
            "File identity (inode/device) could not be compared on this "
            "filesystem; substitution detection rests on the digest alone."
        )
    else:
        inode_check = "performed"
        if st.st_ino != seal.st_ino:
            discrepancies.append(
                f"Inode changed ({seal.st_ino} -> {st.st_ino}): the path now "
                f"refers to a different file object"
            )
        if st.st_dev != seal.st_dev:
            discrepancies.append(
                f"Device changed ({seal.st_dev} -> {st.st_dev})"
            )

    if st.st_mtime_ns != seal.st_mtime_ns:
        metadata_notes.append(
            f"Modification time changed ({seal.st_mtime_ns} -> {st.st_mtime_ns})"
        )

    verified = not discrepancies

    report = IntegrityReport(
        integrity_verified=verified,
        sha256_before=seal.sha256,
        sha256_after=sha256,
        size_before=seal.size_bytes,
        size_after=st.st_size,
        metadata_stable=not metadata_notes,
        checked_utc=utc_now_iso(),
        verification_method="reread",
        inode_check=inode_check,
        discrepancies=discrepancies,
        metadata_notes=metadata_notes,
    )

    if raise_on_failure and not verified:
        raise EvidenceTampered(
            "Evidence integrity verification failed",
            path=str(p),
            discrepancies=report.discrepancies,
        )

    return report
