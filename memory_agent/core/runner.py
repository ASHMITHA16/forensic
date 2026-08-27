"""
memory_agent.core.runner
─────────────────────────────────────────────────────────────────────
Volatility 3 execution, as a subprocess.

Why a subprocess and not the Python API
────────────────────────────────────────
Three reasons, all of which are about what happens when things go wrong:

* **Crash isolation.** Vol3 plugins raise on truncated, hibernation-
  compressed and partially-overwritten images with real frequency. A
  process boundary contains that; an in-process ``SymbolError`` would
  take the agent down mid-run and cost every result already gathered.
* **Enforceable timeouts.** ``windows.filescan`` and ``windows.handles``
  can run for many minutes on a large image. A subprocess can be killed
  at a wall-clock budget. A Python call into a C-bound scan loop cannot
  be safely interrupted from another thread.
* **Auditability.** The exact ``argv`` is a first-class artifact. "This
  finding came from *this literal command*" is a statement a reviewer can
  re-run by hand. "We called this internal API with these keyword
  arguments" is not.

What this module guarantees
───────────────────────────
* The dump path is only ever passed as an input argument. Every path
  Volatility might write to -- cache, symbols, temp -- is redirected into
  the case workspace, so nothing lands beside the evidence.
* stdout is streamed straight to a file in ``raw/``. The verbatim bytes
  Volatility produced are the record; what this module parses out of them
  is a convenience. If parsing later proves wrong, the raw output is
  still there to re-derive from.
* A plugin never raises into the caller. Failure, timeout and
  unavailability are *statuses*, recorded per plugin and reflected in
  coverage. Partial results are always emitted.

Determinism note: ``duration_s`` is wall-clock and therefore varies
between runs. It is deliberately excluded from the deterministic core
(see ``report.deterministic_core``) so that reproducibility can be
asserted over the analysis rather than over the machine's mood.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Sequence

from .errors import PluginExecutionError, VolatilityNotFound, VolatilityUnusable

#: Statuses a plugin execution can end in. ``skipped`` means the planner
#: chose not to run it (behind ``--deep``, or its precondition failed);
#: ``unavailable`` means this Volatility build does not ship it.
STATUS_OK = "ok"
STATUS_FAILED = "failed"
STATUS_TIMEOUT = "timeout"
STATUS_UNAVAILABLE = "unavailable"
STATUS_SKIPPED = "skipped"

#: Executable names to try, in order, when no path is configured.
_CANDIDATES = ("vol", "vol.py", "volatility3", "vol3")

#: Volatility prints this in its help banner. Also our version source.
_VERSION_RE = re.compile(r"Volatility\s+3\s+Framework\s+([0-9][0-9A-Za-z._-]*)")

#: Plugin names as they appear in ``vol -h``.
_PLUGIN_RE = re.compile(r"^\s{2,}(?P<name>[a-z][a-z0-9_]*(?:\.[a-z0-9_]+)+)\b")

#: Beyond this, raw stdout is kept on disk but not parsed into memory.
#: ``windows.filescan`` on a large image can emit hundreds of megabytes
#: of JSON; loading that eagerly would put the agent at risk of being
#: OOM-killed, which loses every result gathered so far. The file is
#: still written, still hashed, and still available to a human.
DEFAULT_MAX_PARSE_BYTES = 512 * 1024 * 1024

#: Cap on captured stderr per plugin, so a plugin stuck in a warning loop
#: cannot fill the workspace.
_MAX_STDERR_BYTES = 256 * 1024

_STDERR_EXCERPT_CHARS = 2000


def _excerpt(text: str, limit: int = _STDERR_EXCERPT_CHARS) -> str:
    text = (text or "").strip()
    if len(text) <= limit:
        return text
    half = limit // 2
    return f"{text[:half]}\n...[{len(text) - limit} chars omitted]...\n{text[-half:]}"


@dataclass(frozen=True)
class ToolchainInfo:
    """What was found when the toolchain was probed."""

    executable: str
    argv_prefix: tuple[str, ...]
    volatility_version: str
    python_version: str
    available_plugins: tuple[str, ...]
    plugin_list_source: str
    probe_duration_s: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "volatility": self.volatility_version,
            "volatility_executable": self.executable,
            "python": self.python_version,
            "plugins_available": len(self.available_plugins),
            "plugin_list_source": self.plugin_list_source,
        }


@dataclass
class PluginResult:
    """
    The outcome of one plugin invocation.

    ``rows`` is the parsed convenience view. ``raw_path`` is the record.
    """

    plugin: str
    argv: list[str]
    status: str
    exit_code: int | None = None
    duration_s: float = 0.0
    row_count: int = 0
    raw_path: str | None = None
    raw_bytes: int = 0
    rows: list[dict[str, Any]] = field(default_factory=list)
    parsed: bool = False
    stderr_excerpt: str = ""
    error: str | None = None
    notes: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.status == STATUS_OK

    def to_execution_record(self) -> dict[str, Any]:
        """
        The per-plugin entry for the envelope's ``execution[]``.

        Deliberately excludes ``rows``: the envelope carries normalised
        observations, not a second copy of every raw row.
        """
        return {
            "plugin": self.plugin,
            "argv": list(self.argv),
            "exit_code": self.exit_code,
            "duration_s": round(self.duration_s, 3),
            "row_count": self.row_count,
            "status": self.status,
            "raw_output": self.raw_path,
            "raw_bytes": self.raw_bytes,
            "parsed": self.parsed,
            "stderr_excerpt": self.stderr_excerpt,
            "error": self.error,
            "notes": list(self.notes),
        }


#: Depth beyond which a rendered hierarchy is treated as malformed. Real
#: process trees are a few dozen levels at worst; anything deeper means
#: corrupted or adversarial output, and following it would be a way to
#: crash the agent from inside the evidence.
MAX_TREE_DEPTH = 256


def flatten_treegrid(rows: Iterable[Any]) -> list[dict[str, Any]]:
    """
    Flatten Volatility's nested JSON renderer output.

    ``windows.pstree`` (and anything else that renders a hierarchy) emits
    children under a ``__children`` key rather than as sibling rows. A
    naive ``json.loads`` therefore sees only the roots -- which for
    pstree means only the processes with no resident parent, i.e. almost
    none of them.

    The nesting is the whole point of pstree, so it is preserved as
    ``__depth`` and ``__parent_index`` rather than discarded.

    Walked with an explicit stack rather than recursion. A recursive walk
    over a deeply nested document raises ``RecursionError``, which is not
    an exception the callers are structured to contain -- and the input
    here is derived from the evidence, so its shape is not under the
    agent's control.
    """
    out: list[dict[str, Any]] = []
    if not isinstance(rows, (list, tuple)):
        rows = list(rows)

    # (item, depth, parent_index), processed depth-first so that the flat
    # order matches the order the tree renders in.
    stack: list[tuple[Any, int, int | None]] = [
        (item, 0, None) for item in reversed(list(rows))
    ]

    while stack:
        item, depth, parent = stack.pop()
        if not isinstance(item, dict):
            continue

        children = item.get("__children") or []
        row = {k: v for k, v in item.items() if k != "__children"}
        row["__depth"] = depth
        row["__parent_index"] = parent
        index = len(out)
        out.append(row)

        if isinstance(children, list) and children and depth < MAX_TREE_DEPTH:
            stack.extend(
                (child, depth + 1, index) for child in reversed(children)
            )

    return out


class VolatilityRunner:
    """
    Locates Volatility 3 and runs plugins against one memory image.

    The runner is deliberately dumb about *which* plugins to run -- that
    is the planner's job. It knows how to run one safely, time it out,
    capture it, and describe what happened.
    """

    def __init__(
        self,
        evidence_path: str | os.PathLike[str],
        raw_dir: str | os.PathLike[str],
        cache_dir: str | os.PathLike[str] | None = None,
        vol_command: str | Sequence[str] | None = None,
        default_timeout_s: int = 300,
        audit: Any = None,
        max_parse_bytes: int = DEFAULT_MAX_PARSE_BYTES,
    ) -> None:
        self.evidence_path = Path(evidence_path).expanduser().resolve()
        self.raw_dir = Path(raw_dir)
        self.cache_dir = Path(cache_dir) if cache_dir else None
        self.default_timeout_s = int(default_timeout_s)
        self.audit = audit
        self.max_parse_bytes = int(max_parse_bytes)
        self._configured = vol_command
        self._info: ToolchainInfo | None = None

        self.raw_dir.mkdir(parents=True, exist_ok=True)
        if self.cache_dir:
            self.cache_dir.mkdir(parents=True, exist_ok=True)

    # ── toolchain discovery ───────────────────────────────────────────

    @staticmethod
    def _candidate_argvs(configured: str | Sequence[str] | None) -> list[list[str]]:
        """Every way we know of to invoke Volatility 3, in priority order."""
        if configured:
            if isinstance(configured, str):
                return [[configured]]
            return [list(configured)]

        env = os.environ.get("VOLATILITY_BIN") or os.environ.get("VOL_BIN")
        candidates: list[list[str]] = []
        if env:
            candidates.append([env])

        for name in _CANDIDATES:
            found = shutil.which(name)
            if found:
                candidates.append([found])

        # A source checkout with no console script installed. Last resort
        # because it depends on the *current* interpreter having vol3
        # importable, which is a different toolchain than a system `vol`.
        candidates.append([sys.executable, "-m", "volatility3.cli"])
        return candidates

    def probe(self, timeout_s: int = 120) -> ToolchainInfo:
        """
        Find a usable Volatility 3 and record its version and plugin list.

        The plugin list matters: ``windows.hollowprocesses`` exists only
        in newer builds, and the planner needs to degrade gracefully
        rather than record a spurious failure for a plugin that was never
        going to be there.
        """
        if self._info is not None:
            return self._info

        started = time.monotonic()
        attempts: list[str] = []

        for argv in self._candidate_argvs(self._configured):
            try:
                proc = subprocess.run(
                    [*argv, "-h"],
                    capture_output=True,
                    text=True,
                    errors="replace",
                    timeout=timeout_s,
                    env=self._child_env(),
                )
            except FileNotFoundError:
                attempts.append(f"{argv[0]}: not found")
                continue
            except subprocess.TimeoutExpired:
                attempts.append(f"{' '.join(argv)}: version probe timed out")
                continue
            except OSError as exc:
                attempts.append(f"{' '.join(argv)}: {exc}")
                continue

            blob = f"{proc.stdout}\n{proc.stderr}"
            match = _VERSION_RE.search(blob)
            if not match:
                attempts.append(
                    f"{' '.join(argv)}: ran but did not identify as Volatility 3"
                )
                continue

            plugins = tuple(sorted(set(_PLUGIN_RE.findall(blob))))
            self._info = ToolchainInfo(
                executable=argv[0],
                argv_prefix=tuple(argv),
                volatility_version=match.group(1),
                python_version=".".join(str(v) for v in sys.version_info[:3]),
                available_plugins=plugins,
                plugin_list_source="vol -h" if plugins else "unavailable",
                probe_duration_s=round(time.monotonic() - started, 3),
            )
            self._record(
                "toolchain.probe",
                executable=argv[0],
                version=match.group(1),
                plugins_found=len(plugins),
            )
            return self._info

        self._record("toolchain.probe.failed", attempts=attempts)

        # Distinguish "nothing to run" from "found something that isn't
        # Volatility". They need different fixes from the operator.
        if any("did not identify" in a or "timed out" in a for a in attempts):
            raise VolatilityUnusable(
                "A candidate executable was found but could not be confirmed as "
                "Volatility 3. Point --vol at the correct executable.",
                attempts=attempts,
            )
        raise VolatilityNotFound(
            "Volatility 3 was not found. Install it (pip install volatility3), "
            "put `vol` on PATH, set VOLATILITY_BIN, or pass --vol <path>.",
            attempts=attempts,
        )

    @property
    def info(self) -> ToolchainInfo | None:
        return self._info

    def has_plugin(self, plugin: str) -> bool | None:
        """
        True/False if the plugin list is known, None if it is not.

        None is not False. If we could not enumerate plugins we must not
        claim a plugin is missing -- that would silently drop coverage and
        report it as a deliberate exclusion.
        """
        if self._info is None or not self._info.available_plugins:
            return None
        return plugin in self._info.available_plugins

    # ── execution ─────────────────────────────────────────────────────

    def _child_env(self) -> dict[str, str]:
        """
        Environment for the child, with every writable path redirected
        into the case workspace.

        Volatility caches symbol tables and JSON metadata under the user's
        home by default. That is fine for interactive use and wrong here:
        a forensic run should leave its intermediate state inside the case
        so it can be preserved, inspected, and thrown away as a unit.
        """
        env = dict(os.environ)
        if self.cache_dir:
            cache = str(self.cache_dir)
            env["VOLATILITY_CACHE_PATH"] = cache
            # Keep any tempfile the child makes inside the case too.
            env["TMPDIR"] = cache
            env["TEMP"] = cache
            env["TMP"] = cache
        return env

    def build_argv(self, plugin: str, plugin_args: Sequence[str] = ()) -> list[str]:
        """
        The literal command line for one plugin.

        Global options must precede the plugin name; anything after it is
        parsed as an argument *to* the plugin. Getting that order wrong is
        the single most common way to make Vol3 do something other than
        what the audit trail claims it did.
        """
        info = self.probe()
        argv = [*info.argv_prefix, "-q", "-r", "json"]
        if self.cache_dir:
            argv += ["--cache-path", str(self.cache_dir)]
        argv += ["-f", str(self.evidence_path), plugin, *plugin_args]
        return argv

    def run(
        self,
        plugin: str,
        plugin_args: Sequence[str] = (),
        timeout_s: int | None = None,
        raw_name: str | None = None,
    ) -> PluginResult:
        """
        Run one plugin. Never raises for a plugin-level problem.

        The only exceptions that escape are ``VolatilityNotFound`` /
        ``VolatilityUnusable`` from the probe (no plugin can run at all)
        and ``PluginExecutionError`` when the workspace itself broke.
        """
        available = self.has_plugin(plugin)
        if available is False:
            result = PluginResult(
                plugin=plugin,
                argv=[],
                status=STATUS_UNAVAILABLE,
                error=(
                    f"{plugin} is not provided by Volatility "
                    f"{self._info.volatility_version if self._info else '?'}"
                ),
            )
            self._record("plugin.unavailable", plugin=plugin)
            return result

        argv = self.build_argv(plugin, plugin_args)
        budget = int(timeout_s if timeout_s is not None else self.default_timeout_s)
        raw_path = self.raw_dir / f"{raw_name or plugin}.json"
        err_path = self.raw_dir / f"{raw_name or plugin}.stderr.txt"

        self._record(
            "plugin.begin", plugin=plugin, argv=argv, timeout_s=budget,
            raw_output=str(raw_path),
        )

        started = time.monotonic()
        stderr_text = ""
        exit_code: int | None = None
        status = STATUS_OK
        error: str | None = None
        notes: list[str] = []

        try:
            # stdout goes straight to disk. Buffering a multi-hundred-MB
            # plugin result through a pipe into a Python string is how a
            # long run dies with a MemoryError two hours in.
            with raw_path.open("wb") as out_fh:
                proc = subprocess.Popen(
                    argv,
                    stdout=out_fh,
                    stderr=subprocess.PIPE,
                    env=self._child_env(),
                    cwd=str(self.raw_dir),
                    **_process_group_kwargs(),
                )
                try:
                    _, err_bytes = proc.communicate(timeout=budget)
                    exit_code = proc.returncode
                except subprocess.TimeoutExpired:
                    status = STATUS_TIMEOUT
                    error = f"exceeded the {budget}s budget and was terminated"
                    err_bytes = _terminate(proc)
                    exit_code = proc.returncode
                    notes.append(
                        "Output captured before termination is retained and may "
                        "be partially valid, but is not parsed: a truncated JSON "
                        "document cannot be distinguished from a complete one "
                        "that happens to end early."
                    )
        except FileNotFoundError as exc:
            raise VolatilityNotFound(
                f"Volatility executable vanished between probe and run: {exc}",
                plugin=plugin,
            ) from exc
        except OSError as exc:
            raise PluginExecutionError(
                f"Could not run {plugin}: {exc}", plugin=plugin, argv=argv
            ) from exc

        duration = time.monotonic() - started

        if err_bytes:
            stderr_text = err_bytes[:_MAX_STDERR_BYTES].decode("utf-8", "replace")
            try:
                err_path.write_text(stderr_text, encoding="utf-8", newline="\n")
            except OSError:
                notes.append("stderr could not be written to the workspace")

        raw_bytes = raw_path.stat().st_size if raw_path.exists() else 0

        result = PluginResult(
            plugin=plugin,
            argv=argv,
            status=status,
            exit_code=exit_code,
            duration_s=duration,
            raw_path=str(raw_path),
            raw_bytes=raw_bytes,
            stderr_excerpt=_excerpt(stderr_text),
            error=error,
            notes=notes,
        )

        if status == STATUS_OK and exit_code != 0:
            result.status = STATUS_FAILED
            result.error = (
                f"exited with code {exit_code}"
                + (f": {_excerpt(stderr_text, 300)}" if stderr_text else "")
            )

        if result.status == STATUS_OK:
            self._parse_into(result, raw_path, raw_bytes)

        self._record(
            "plugin.end",
            plugin=plugin,
            status=result.status,
            exit_code=exit_code,
            duration_s=round(duration, 3),
            row_count=result.row_count,
            raw_bytes=raw_bytes,
            error=result.error,
        )
        return result

    def _parse_into(self, result: PluginResult, raw_path: Path, raw_bytes: int) -> None:
        """Parse captured stdout into rows, downgrading status on failure."""
        if raw_bytes == 0:
            # A clean exit with no output is a legitimate result: the
            # plugin ran and found nothing. Not a failure.
            result.parsed = True
            result.rows = []
            result.row_count = 0
            result.notes.append("plugin produced no output rows")
            return

        if raw_bytes > self.max_parse_bytes:
            result.parsed = False
            result.notes.append(
                f"raw output is {raw_bytes} bytes, above the "
                f"{self.max_parse_bytes}-byte parse limit; it is retained on disk "
                f"but no observations were derived from it"
            )
            return

        try:
            with raw_path.open("r", encoding="utf-8", errors="replace") as fh:
                data = json.load(fh)
        except json.JSONDecodeError as exc:
            result.status = STATUS_FAILED
            result.parsed = False
            result.error = (
                f"output is not valid JSON (line {exc.lineno}, col {exc.colno}): "
                f"{exc.msg}"
            )
            return
        except (OSError, RecursionError, MemoryError) as exc:
            result.status = STATUS_FAILED
            result.parsed = False
            result.error = f"output could not be read: {type(exc).__name__}: {exc}"
            return

        if isinstance(data, dict):
            # Some renderer versions wrap rows in an object.
            for key in ("rows", "data", "results"):
                if isinstance(data.get(key), list):
                    data = data[key]
                    result.notes.append(f"rows unwrapped from object key {key!r}")
                    break

        if not isinstance(data, list):
            result.status = STATUS_FAILED
            result.parsed = False
            result.error = (
                f"expected a JSON array of rows, got {type(data).__name__}"
            )
            return

        rows = flatten_treegrid(data)
        if len(rows) != len(data):
            result.notes.append(
                f"treegrid flattened: {len(data)} root rows expanded to {len(rows)}"
            )

        result.rows = rows
        result.row_count = len(rows)
        result.parsed = True

    # ── audit plumbing ────────────────────────────────────────────────

    def _record(self, event: str, **data: Any) -> None:
        if self.audit is not None:
            self.audit.record(event, **data)


def load_raw_results(raw_dir: str | os.PathLike[str]) -> dict[str, PluginResult]:
    """
    Reconstruct plugin results from previously captured raw JSON.

    Each ``<plugin>.json`` in the directory becomes a ``PluginResult``
    with status ``ok``. The argv is not recovered -- it lives in the
    original run's ``execution[]`` -- so replayed records carry an empty
    argv and the envelope's status makes clear this was not a live run.
    """
    directory = Path(raw_dir)
    results: dict[str, PluginResult] = {}

    for path in sorted(directory.glob("*.json")):
        plugin = path.stem
        try:
            with path.open("r", encoding="utf-8", errors="replace") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            results[plugin] = PluginResult(
                plugin=plugin, argv=[], status="failed",
                error=f"replay could not read {path.name}: {exc}",
                raw_path=str(path),
            )
            continue

        if isinstance(data, dict):
            for key in ("rows", "data", "results"):
                if isinstance(data.get(key), list):
                    data = data[key]
                    break
        if not isinstance(data, list):
            results[plugin] = PluginResult(
                plugin=plugin, argv=[], status="failed",
                error=f"replay expected a JSON array in {path.name}",
                raw_path=str(path),
            )
            continue

        rows = flatten_treegrid(data)
        results[plugin] = PluginResult(
            plugin=plugin, argv=[], status=STATUS_OK, exit_code=0,
            row_count=len(rows), rows=rows, parsed=True,
            raw_path=str(path), raw_bytes=path.stat().st_size,
            notes=["reconstructed from captured raw output; not a live run"],
        )

    return results


def _process_group_kwargs() -> dict[str, Any]:
    """
    Put the child in its own process group so a timeout kills the whole
    tree, not just the parent.

    Vol3 can spawn helpers (symbol downloads, decompressors). Killing
    only the direct child leaves those running against the evidence file
    after the agent believes the plugin is dead -- the agent would then
    re-hash the dump while something is still reading it, and report a
    timing anomaly it caused itself.
    """
    if os.name == "nt":
        return {"creationflags": getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)}
    return {"start_new_session": True}


def _terminate(proc: subprocess.Popen, grace_s: float = 5.0) -> bytes:
    """Terminate, then kill, returning whatever stderr was captured."""
    err = b""
    try:
        if os.name != "nt":
            try:
                os.killpg(os.getpgid(proc.pid), 15)  # SIGTERM to the group
            except (ProcessLookupError, PermissionError, OSError):
                proc.terminate()
        else:
            proc.terminate()
    except OSError:
        pass

    try:
        _, err = proc.communicate(timeout=grace_s)
    except subprocess.TimeoutExpired:
        try:
            if os.name != "nt":
                try:
                    os.killpg(os.getpgid(proc.pid), 9)  # SIGKILL to the group
                except (ProcessLookupError, PermissionError, OSError):
                    proc.kill()
            else:
                proc.kill()
        except OSError:
            pass
        try:
            _, err = proc.communicate(timeout=grace_s)
        except (subprocess.TimeoutExpired, OSError):
            err = b""
    except OSError:
        err = b""
    return err or b""
