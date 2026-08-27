"""
memory_agent.core.profile
─────────────────────────────────────────────────────────────────────
Identify the operating system captured in the image, and anchor its clock.

The identification cascade
──────────────────────────
1. ``windows.info`` -- authoritative when it succeeds, and it also yields
   the image's own system time.
2. ``banners.Banners`` -- the Linux/macOS kernel banner string, which
   names the exact kernel build an ISF symbol table must match.
3. A bounded raw signature scan -- last resort, reads the head of the
   image looking for kernel version strings.
4. Failure. The run aborts.

Step 4 is a deliberate choice. The tempting alternative -- default to
Windows and run the Windows plugin set -- is worse than useless on an
unidentified image: pool scanners such as ``psscan`` carve structures out
of byte patterns, and against the wrong OS they will still return rows.
Those rows would enter the pipeline as observations and could reach a
report as findings. An honest abort is the only defensible behaviour.

Clock anchoring
───────────────
Every memory timestamp in the output is expressed in UTC relative to the
image's own ``SystemTime``, not the analysis host's clock. Without this,
a memory timeline silently drifts against disk MFT and network PCAP
timelines, and the correlation agent produces a confidently wrong
sequence of events.

Two honesty constraints are enforced here:

* ``SystemTime`` from ``windows.info`` is the last clock value written to
  the KUSER_SHARED_DATA page, not the instant of acquisition. It is
  recorded as an anchor with that caveat attached, never as the exact
  acquisition time.
* ``clock_skew_seconds`` is only computed when the investigator supplied
  a real acquisition time. It is a measured difference between two stated
  facts, never an inference. Where no acquisition time was supplied the
  field stays ``null`` -- an unknown skew is reported as unknown.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from .errors import OSIdentificationFailed
from .rows import as_bool, as_int, as_str, parse_timestamp, seconds_between

WINDOWS = "windows"
LINUX = "linux"
MAC = "mac"
UNKNOWN = "unknown"

#: How much of the image the raw fallback scan will read. A signature
#: scan over 64 GB would take longer than the analysis it is meant to
#: enable, and kernel banners live low in physical memory in practice.
RAW_SCAN_BYTES = 512 * 1024 * 1024
_RAW_CHUNK = 8 * 1024 * 1024
#: Overlap between chunks so a signature straddling a boundary is not lost.
_RAW_OVERLAP = 4096

_LINUX_BANNER_RE = re.compile(rb"Linux version [0-9][^\x00\n]{0,255}")
_MAC_BANNER_RE = re.compile(rb"Darwin Kernel Version [0-9][^\x00\n]{0,255}")
_WINDOWS_MARKER_RE = re.compile(rb"Windows (?:NT|Server|10|11)[^\x00\n]{0,64}")

_LINUX_VERSION_RE = re.compile(r"Linux version ([0-9][0-9A-Za-z._+-]*)")
_MAC_VERSION_RE = re.compile(r"Darwin Kernel Version ([0-9][0-9A-Za-z._ :]*)")

_ARCH_HINTS = (
    ("x86_64", "x64"),
    ("amd64", "x64"),
    ("aarch64", "arm64"),
    ("arm64", "arm64"),
    ("i386", "x86"),
    ("i686", "x86"),
)


@dataclass(frozen=True)
class OSProfile:
    """What we determined about the captured system, and how sure we are."""

    family: str
    version: str | None = None
    arch: str | None = None
    build: str | None = None
    confidence: float = 0.0
    determined_by: str = "none"
    banner: str | None = None
    dump_system_time_utc: str | None = None
    dump_system_time_basis: str | None = None
    clock_skew_seconds: float | None = None
    clock_skew_basis: str | None = None
    symbol_requirement: str | None = None
    notes: list[str] = field(default_factory=list)
    raw_info: dict[str, Any] = field(default_factory=dict)

    @property
    def identified(self) -> bool:
        return self.family != UNKNOWN

    def to_dict(self) -> dict[str, Any]:
        return {
            "os": {
                "family": self.family,
                "version": self.version,
                "arch": self.arch,
                "build": self.build,
                "confidence": self.confidence,
                "determined_by": self.determined_by,
                "banner": self.banner,
                "symbol_requirement": self.symbol_requirement,
            },
            "dump_system_time_utc": self.dump_system_time_utc,
            "dump_system_time_basis": self.dump_system_time_basis,
            "clock_skew_seconds": self.clock_skew_seconds,
            "clock_skew_basis": self.clock_skew_basis,
            "notes": list(self.notes),
        }


# ── windows.info ──────────────────────────────────────────────────────


class _InfoMap(dict):
    """
    The ``windows.info`` variable table, looked up case-insensitively.

    Volatility spells these variable names inconsistently across versions
    -- ``NTBuildLab`` and ``NtBuildLab`` have both shipped, as have
    ``Is64Bit`` and ``Is64bit``. An exact-case lookup silently returns
    None for the wrong spelling, and a None build number turns into a
    version string that quietly omits the build. Matching on a folded key
    removes the whole class of failure.
    """

    def __init__(self, pairs: dict[str, Any]) -> None:
        super().__init__(pairs)
        self._folded = {k.replace(" ", "").lower(): k for k in pairs}

    def get(self, key: str, default: Any = None) -> Any:  # type: ignore[override]
        actual = self._folded.get(str(key).replace(" ", "").lower())
        return super().get(actual, default) if actual is not None else default

    def __contains__(self, key: object) -> bool:  # type: ignore[override]
        return str(key).replace(" ", "").lower() in self._folded


def _variable_value_map(rows: list[dict[str, Any]]) -> _InfoMap:
    """
    ``windows.info`` renders as (Variable, Value) pairs, not columns.

    Duplicate variables are kept as the first occurrence; Vol3 emits some
    keys more than once across layers and the first is the primary one.
    """
    out: dict[str, Any] = {}
    for row in rows:
        name = None
        value = None
        for key, val in row.items():
            nk = str(key).strip().lower()
            if nk in {"variable", "name", "key"}:
                name = as_str(val)
            elif nk == "value":
                value = val
        if name and name not in out:
            out[name] = value
    return _InfoMap(out)


def profile_from_windows_info(
    rows: list[dict[str, Any]],
    acquisition_utc: str | None = None,
) -> OSProfile | None:
    """Build a profile from ``windows.info`` rows, or None if unusable."""
    info = _variable_value_map(rows)
    if not info:
        return None

    # Require a Windows-specific key. An empty or foreign table must not
    # be dressed up as a low-confidence Windows identification.
    if not any(k in info for k in ("NtMajorVersion", "NtBuildLab", "KdVersionBlock",
                                   "Kernel Base", "NtProductType")):
        return None

    notes: list[str] = []

    major = as_int(info.get("NtMajorVersion"))
    minor = as_int(info.get("NtMinorVersion"))
    build_lab = as_str(info.get("NtBuildLab")) or ""
    build = build_lab.split(".")[0] if build_lab and build_lab[0].isdigit() else None
    if build is None:
        build = as_str(info.get("NtBuildNumber")) or as_str(info.get("Build"))

    version = None
    if major is not None and minor is not None:
        version = f"{major}.{minor}" + (f".{build}" if build else "")
    elif build:
        version = build

    is_64 = as_bool(info.get("Is64Bit"))
    machine = as_str(info.get("MachineType")) or ""
    arch = None
    if is_64 is True:
        arch = "x64"
    elif is_64 is False:
        arch = "x86"
    if arch is None:
        for needle, value in _ARCH_HINTS:
            if needle in machine.lower():
                arch = value
                break

    system_time_raw = info.get("SystemTime")
    system_time, ts_note = parse_timestamp(system_time_raw)
    if ts_note:
        notes.append(f"SystemTime: {ts_note}")

    basis = None
    if system_time:
        basis = (
            "windows.info SystemTime -- the last clock value written to "
            "KUSER_SHARED_DATA before capture. It approximates, but does not "
            "equal, the instant of acquisition."
        )
    else:
        notes.append(
            "windows.info did not yield a usable SystemTime; memory timestamps "
            "cannot be anchored to the image's own clock and are reported as "
            "rendered by Volatility"
        )

    skew, skew_basis = _skew(system_time, acquisition_utc)

    # Confidence: windows.info succeeding is strong evidence, but the
    # completeness of the table varies. Missing version detail lowers it
    # rather than being papered over.
    confidence = 0.99
    if version is None:
        confidence = 0.90
        notes.append("windows.info returned no version fields")
    if arch is None:
        confidence = min(confidence, 0.92)
        notes.append("architecture could not be determined from windows.info")

    return OSProfile(
        family=WINDOWS,
        version=version,
        arch=arch,
        build=build,
        confidence=confidence,
        determined_by="windows.info",
        dump_system_time_utc=system_time,
        dump_system_time_basis=basis,
        clock_skew_seconds=skew,
        clock_skew_basis=skew_basis,
        notes=notes,
        raw_info={k: str(v) for k, v in info.items()},
    )


# ── banners ───────────────────────────────────────────────────────────


def profile_from_banners(
    rows: list[dict[str, Any]],
    acquisition_utc: str | None = None,
) -> OSProfile | None:
    """Build a profile from ``banners.Banners`` rows, or None."""
    banners: list[str] = []
    for row in rows:
        for key, val in row.items():
            if str(key).strip().lower() in {"banner", "banners", "value"}:
                text = as_str(val)
                if text:
                    banners.append(text)

    if not banners:
        return None

    # Most frequent banner wins; a scan can turn up stale banners from
    # earlier boots or from container images resident in page cache.
    counts: dict[str, int] = {}
    for b in banners:
        counts[b] = counts.get(b, 0) + 1
    banner = max(sorted(counts), key=lambda b: (counts[b], len(b)))

    notes: list[str] = []
    distinct = len(counts)
    if distinct > 1:
        notes.append(
            f"{distinct} distinct kernel banners were present; the most frequent "
            f"was used. Multiple banners can mean container images or a prior "
            f"kernel still resident in memory -- confirm before relying on the "
            f"symbol table this implies."
        )

    family = UNKNOWN
    version = None
    if "Linux version" in banner:
        family = LINUX
        m = _LINUX_VERSION_RE.search(banner)
        version = m.group(1) if m else None
    elif "Darwin Kernel Version" in banner:
        family = MAC
        m = _MAC_VERSION_RE.search(banner)
        version = m.group(1).strip() if m else None

    if family == UNKNOWN:
        return None

    arch = None
    low = banner.lower()
    for needle, value in _ARCH_HINTS:
        if needle in low:
            arch = value
            break

    notes.append(
        "No system time is recoverable from a kernel banner. Linux and macOS "
        "timestamps are anchored per-artifact where the artifact carries one; "
        "there is no image-wide clock anchor for this profile."
    )

    skew, skew_basis = _skew(None, acquisition_utc)

    return OSProfile(
        family=family,
        version=version,
        arch=arch,
        build=version,
        confidence=0.85 if distinct == 1 else 0.70,
        determined_by="banners.Banners",
        banner=banner,
        symbol_requirement=(
            f"An ISF symbol table matching this exact kernel build is required "
            f"before any {family} plugin can run: {banner}"
        ),
        clock_skew_seconds=skew,
        clock_skew_basis=skew_basis,
        notes=notes,
    )


# ── raw signature scan ────────────────────────────────────────────────


def scan_raw_signatures(
    evidence_path: str,
    limit_bytes: int = RAW_SCAN_BYTES,
) -> dict[str, Any]:
    """
    Read the head of the image looking for kernel signatures.

    Opened read-only and never memory-mapped for write. Returns what was
    found and how much was searched, because "found nothing in the first
    512 MB" and "found nothing anywhere" are different statements and the
    caller must not conflate them.
    """
    found_linux: list[str] = []
    found_mac: list[str] = []
    windows_hits = 0
    read = 0
    truncated = False

    try:
        with open(evidence_path, "rb") as fh:
            tail = b""
            while read < limit_bytes:
                chunk = fh.read(min(_RAW_CHUNK, limit_bytes - read))
                if not chunk:
                    break
                read += len(chunk)
                window = tail + chunk
                for m in _LINUX_BANNER_RE.finditer(window):
                    found_linux.append(m.group(0).decode("ascii", "replace"))
                for m in _MAC_BANNER_RE.finditer(window):
                    found_mac.append(m.group(0).decode("ascii", "replace"))
                windows_hits += len(_WINDOWS_MARKER_RE.findall(window))
                # Carry the tail forward so a signature straddling a chunk
                # boundary is still matched. Overlap is counted once: the
                # window is (tail + chunk), and matches in the overlap
                # region are deduplicated by the set() below.
                tail = window[-_RAW_OVERLAP:]
            # "Did we stop because the file ended, or because we hit the
            # budget?" -- the two support different conclusions, so ask
            # rather than infer it from the loop's exit path.
            truncated = bool(fh.read(1))
    except OSError as exc:
        return {"error": str(exc), "bytes_scanned": read}

    return {
        "bytes_scanned": read,
        "scan_truncated": truncated,
        "linux_banners": sorted(set(found_linux))[:5],
        "mac_banners": sorted(set(found_mac))[:5],
        "windows_marker_hits": windows_hits,
    }


def profile_from_raw_scan(
    scan: dict[str, Any],
    acquisition_utc: str | None = None,
) -> OSProfile | None:
    """Interpret a raw signature scan, or None if it decided nothing."""
    if scan.get("error"):
        return None

    notes = [
        f"Identified by raw signature scan over the first "
        f"{scan.get('bytes_scanned', 0)} bytes"
        + (" (image is larger than the scanned region)"
           if scan.get("scan_truncated") else ""),
        "A signature scan proves a string is present in memory. It does not "
        "prove that string describes the running kernel -- a downloaded ISO, a "
        "log file or a container image in page cache produces the same hit. "
        "Confidence is capped accordingly.",
    ]
    skew, skew_basis = _skew(None, acquisition_utc)

    linux = scan.get("linux_banners") or []
    mac = scan.get("mac_banners") or []
    win_hits = int(scan.get("windows_marker_hits") or 0)

    if linux and not mac:
        banner = linux[0]
        m = _LINUX_VERSION_RE.search(banner)
        return OSProfile(
            family=LINUX, version=m.group(1) if m else None,
            confidence=0.55, determined_by="raw_signature_scan", banner=banner,
            symbol_requirement=f"ISF symbol table for: {banner}",
            clock_skew_seconds=skew, clock_skew_basis=skew_basis, notes=notes,
        )

    if mac and not linux:
        banner = mac[0]
        m = _MAC_VERSION_RE.search(banner)
        return OSProfile(
            family=MAC, version=m.group(1).strip() if m else None,
            confidence=0.55, determined_by="raw_signature_scan", banner=banner,
            symbol_requirement=f"ISF symbol table for: {banner}",
            clock_skew_seconds=skew, clock_skew_basis=skew_basis, notes=notes,
        )

    # A Windows marker count is the weakest signal of the three: the
    # string "Windows NT" appears in user-agent strings, in installers and
    # in documentation resident in memory on any OS. Require a lot of
    # them, and still cap confidence low.
    if win_hits >= 50 and not linux and not mac:
        notes.append(
            f"{win_hits} Windows marker strings were present, but no structured "
            f"Windows information could be read. Treat this identification as a "
            f"hint for choosing a symbol table, not as an established fact."
        )
        return OSProfile(
            family=WINDOWS, confidence=0.40, determined_by="raw_signature_scan",
            clock_skew_seconds=skew, clock_skew_basis=skew_basis, notes=notes,
        )

    return None


# ── cascade ───────────────────────────────────────────────────────────


def _skew(
    system_time_utc: str | None, acquisition_utc: str | None
) -> tuple[float | None, str | None]:
    """Measured skew, or None with a reason. Never an inference."""
    if not acquisition_utc:
        return None, (
            "No acquisition time was supplied, so skew between the captured "
            "system's clock and true UTC is unknown. Memory timestamps are "
            "reported as the captured system recorded them."
        )
    if not system_time_utc:
        return None, (
            "An acquisition time was supplied but the image yielded no system "
            "time, so no skew can be computed."
        )
    delta = seconds_between(system_time_utc, acquisition_utc)
    if delta is None:
        return None, f"Acquisition time {acquisition_utc!r} could not be parsed."
    return round(delta, 3), (
        "Difference between the image's own SystemTime and the acquisition time "
        "supplied by the investigator. Positive means the captured system's "
        "clock ran ahead of the acquisition record."
    )


def identify(
    runner: Any,
    evidence_path: str,
    acquisition_utc: str | None = None,
    audit: Any = None,
    allow_raw_scan: bool = True,
) -> tuple[OSProfile, list[Any]]:
    """
    Run the cascade. Returns ``(profile, plugin_results)``.

    Plugin results are returned so the caller can fold the identification
    attempts into ``execution[]`` -- an identification that took three
    tries is part of the record, not internal detail.
    """
    attempts: list[Any] = []

    def record(event: str, **data: Any) -> None:
        if audit is not None:
            audit.record(event, **data)

    record("profile.begin", methods=["windows.info", "banners.Banners", "raw_scan"])

    # 1 ── windows.info
    result = runner.run("windows.info", timeout_s=180)
    attempts.append(result)
    if result.ok and result.rows:
        profile = profile_from_windows_info(result.rows, acquisition_utc)
        if profile is not None:
            record(
                "profile.identified", family=profile.family,
                version=profile.version, determined_by=profile.determined_by,
                confidence=profile.confidence,
            )
            return profile, attempts
        record("profile.method.inconclusive", method="windows.info")
    else:
        record(
            "profile.method.failed", method="windows.info",
            status=result.status, error=result.error,
        )

    # 2 ── banners
    result = runner.run("banners.Banners", timeout_s=300)
    attempts.append(result)
    if result.ok and result.rows:
        profile = profile_from_banners(result.rows, acquisition_utc)
        if profile is not None:
            record(
                "profile.identified", family=profile.family,
                version=profile.version, determined_by=profile.determined_by,
                confidence=profile.confidence,
            )
            return profile, attempts
        record("profile.method.inconclusive", method="banners.Banners")
    else:
        record(
            "profile.method.failed", method="banners.Banners",
            status=result.status, error=result.error,
        )

    # 3 ── raw scan
    if allow_raw_scan:
        scan = scan_raw_signatures(evidence_path)
        record("profile.raw_scan", **{k: v for k, v in scan.items()
                                     if k != "linux_banners"})
        profile = profile_from_raw_scan(scan, acquisition_utc)
        if profile is not None:
            record(
                "profile.identified", family=profile.family,
                determined_by=profile.determined_by, confidence=profile.confidence,
            )
            return profile, attempts

    # 4 ── abort
    record("profile.failed")
    raise OSIdentificationFailed(
        "The operating system of this image could not be determined by "
        "windows.info, kernel banner, or raw signature scan. The run is "
        "aborted rather than continuing with a guessed plugin set: pool "
        "scanners return carved rows against the wrong OS, and those rows "
        "would enter the record as observations. Common causes are a "
        "hibernation or crash-dump file needing conversion, a truncated "
        "acquisition, an encrypted image, or a missing ISF symbol table.",
        evidence_path=str(evidence_path),
        attempts=[getattr(a, "plugin", "?") for a in attempts],
    )
