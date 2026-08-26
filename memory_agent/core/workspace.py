"""
memory_agent.core.workspace
─────────────────────────────────────────────────────────────────────
Isolated per-run case workspace.

Every byte the agent writes -- audit trail, raw plugin output, symbol
cache, the final envelope -- lands inside a single directory tree keyed
by case and run:

    <output_dir>/<case_id>/<run_id>/
        audit.jsonl        tamper-evident action log
        custody.json       chain-of-custody record
        raw/               verbatim Volatility plugin output (Phase 2+)
        cache/             Volatility scan cache (Phase 2+)
        artifacts/         dumped regions, extracted files (Phase 4+)
        memory_agent_output.json   the final envelope (Phase 5+)

The agent must never write into the directory holding the evidence. A
tool that scatters cache files beside the evidence changes the directory
an investigator may later need to present as untouched.

Enforcing that correctly is fiddlier than it looks. Comparing resolved
path *strings* is not sufficient:

  * on case-insensitive filesystems (NTFS, APFS) ``/Evidence`` and
    ``/EVIDENCE`` are the same directory but different strings;
  * ``Path.resolve()`` in non-strict mode gives up canonicalising when it
    hits an access error and splices the as-typed tail back on, so the
    two sides of the comparison are not produced the same way;
  * symlinks and junctions can alias one directory under many names.

So the check is done on filesystem *identity* -- ``(st_dev, st_ino)`` of
the nearest existing ancestor -- which is immune to all three. Where the
platform cannot supply an inode, it falls back to a normalised-case path
comparison and records that the weaker check was used.
"""

from __future__ import annotations

import os
import re
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from .errors import UnsafeWorkspace, WorkspaceError

#: Case identifiers become directory names, so they are constrained to
#: characters that are safe on Windows, macOS and Linux alike.
_SAFE_SEGMENT = re.compile(r"[^A-Za-z0-9._-]+")

DEFAULT_OUTPUT_DIR = "memory_agent_cases"


def sanitize_segment(value: str, fallback: str = "unnamed") -> str:
    """Reduce an arbitrary string to a safe single path segment."""
    cleaned = _SAFE_SEGMENT.sub("_", value.strip()).strip("._-")
    return cleaned[:64] or fallback


def new_run_id() -> str:
    """A fresh UUID4 identifying one execution of the agent."""
    return str(uuid.uuid4())


def _nearest_existing(p: Path) -> Path:
    """The closest ancestor of ``p`` (including ``p``) that exists."""
    cur = p
    while not cur.exists():
        parent = cur.parent
        if parent == cur:
            return cur
        cur = parent
    return cur


def _identity(p: Path) -> tuple[int, int] | None:
    """``(st_dev, st_ino)`` for ``p``, or None where unavailable."""
    try:
        st = p.stat()
    except OSError:
        return None
    if not st.st_ino or not st.st_dev:
        return None  # FAT/exFAT, some network shares, restricted Windows
    return (st.st_dev, st.st_ino)


def _is_within(candidate: Path, ancestor: Path) -> bool:
    """
    True when ``candidate`` is ``ancestor`` or lies inside its subtree.

    Walks the real directory chain by identity, so symlinks, junctions
    and case-folding aliases cannot slip past.
    """
    ancestor_id = _identity(ancestor)
    start = _nearest_existing(candidate)

    if ancestor_id is not None:
        cur = start
        while True:
            if _identity(cur) == ancestor_id:
                return True
            parent = cur.parent
            if parent == cur:
                break
            cur = parent
        return False

    # Fallback: no usable inode. Compare normalised-case paths, which at
    # least catches the case-insensitive-filesystem alias.
    a = os.path.normcase(os.path.normpath(str(ancestor)))
    c = os.path.normcase(os.path.normpath(str(start)))
    return c == a or c.startswith(a + os.sep)


def _same_volume(a: Path, b: Path) -> bool:
    try:
        return _nearest_existing(a).stat().st_dev == b.stat().st_dev
    except OSError:
        return False


@dataclass(frozen=True)
class Workspace:
    """Resolved paths for one analysis run."""

    root: Path
    case_id: str
    run_id: str
    warnings: list[str] = field(default_factory=list)

    @property
    def audit_path(self) -> Path:
        return self.root / "audit.jsonl"

    @property
    def custody_path(self) -> Path:
        return self.root / "custody.json"

    @property
    def raw_dir(self) -> Path:
        return self.root / "raw"

    @property
    def cache_dir(self) -> Path:
        return self.root / "cache"

    @property
    def artifacts_dir(self) -> Path:
        return self.root / "artifacts"

    @property
    def envelope_path(self) -> Path:
        return self.root / "memory_agent_output.json"


def create_workspace(
    case_id: str,
    run_id: str | None = None,
    output_dir: str | os.PathLike[str] | None = None,
    evidence_path: str | os.PathLike[str] | None = None,
) -> Workspace:
    """
    Create and return the workspace for a run.

    ``evidence_path``, when supplied, is used to refuse a workspace inside
    the evidence's directory and to warn when the workspace shares a
    volume with the evidence.
    """
    run_id = run_id or new_run_id()
    base = Path(output_dir or DEFAULT_OUTPUT_DIR).expanduser().resolve()
    root = base / sanitize_segment(case_id, "case") / sanitize_segment(run_id, "run")

    warnings: list[str] = []

    if evidence_path is not None:
        evidence_dir = Path(evidence_path).expanduser().resolve().parent

        if _is_within(base, evidence_dir):
            raise UnsafeWorkspace(
                "Refusing to create the case workspace inside the evidence "
                "directory. Agent output must not land beside the evidence. "
                "Choose an output directory outside it with -o.",
                evidence_dir=str(evidence_dir),
                requested_output_dir=str(base),
            )

        if _same_volume(base, evidence_dir):
            warnings.append(
                f"The case workspace ({base}) is on the same volume as the "
                f"evidence ({evidence_dir}). This is acceptable on a single-disk "
                f"machine, but when the evidence sits on dedicated media you "
                f"should write output elsewhere so that volume stays untouched."
            )

    try:
        for d in (root, root / "raw", root / "cache", root / "artifacts"):
            d.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise WorkspaceError(
            f"Could not create case workspace: {exc}", path=str(root)
        ) from exc

    return Workspace(root=root, case_id=case_id, run_id=run_id, warnings=warnings)
