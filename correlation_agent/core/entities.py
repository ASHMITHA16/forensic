"""
correlation_agent.core.entities
─────────────────────────────────────────────────────────────────────
Pure helpers: severity and time normalisation, IP classification, path
canonicalisation, and entity extraction from free text.

Nothing here makes a judgement about any finding. It only puts values
from four different agents into one comparable form.
"""

from __future__ import annotations

import math
import re
from datetime import datetime, timezone
from typing import Any, Iterable
from urllib.parse import urlsplit

from .constants import SEVERITIES, SEVERITY_RANK, TECHNIQUE_TACTIC

EXECUTABLE_EXT = re.compile(r"\.(exe|dll|sys|scr|com|ps1|psm1|bat|cmd|vbs|vbe|js|jse|wsf|hta|msi|bin)$", re.I)
EXE_IN_TEXT = re.compile(r"[\w$.-]+\.(?:exe|dll|sys|scr|ps1|bat|cmd|vbs|hta|msi|bin)\b", re.I)
WIN_PATH_IN_TEXT = re.compile(r"\b[a-z]:\\[^\s\"'<>|,;]+", re.I)
URL_IN_TEXT = re.compile(r"\bhttps?://[^\s\"'<>]+", re.I)
IPV4_IN_TEXT = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


# ── numbers and lists ─────────────────────────────────────────────────


def round2(n: float) -> float:
    """Half-up to two places (Python's round() is half-to-even)."""
    return math.floor(n * 100 + 0.5) / 100


def clamp(n: float, lo: float, hi: float) -> float:
    return min(hi, max(lo, n))


def uniq(values: Iterable[Any]) -> list[Any]:
    """De-duplicate, keep first-seen order, drop None and empty strings."""
    seen: set[Any] = set()
    out: list[Any] = []
    for v in values:
        if v is None or v == "" or v in seen:
            continue
        seen.add(v)
        out.append(v)
    return out


def as_list(v: Any) -> list[Any]:
    if isinstance(v, list):
        return v
    if v is None or v == "":
        return []
    return [v]


# ── severity and time ─────────────────────────────────────────────────


def norm_severity(value: Any) -> str:
    s = str(value or "").lower()
    if s == "informational":
        return "info"
    return s if s in SEVERITIES else "info"


def max_severity(values: Iterable[str]) -> str:
    best = "info"
    for s in values:
        if SEVERITY_RANK[s] > SEVERITY_RANK[best]:
            best = s
    return best


def to_iso(value: Any) -> str | None:
    """
    Any timestamp an agent emits -> ``YYYY-MM-DDTHH:MM:SS[.mmm]Z`` or None.

    A value without a zone is read as UTC: every upstream agent already
    emits UTC, and guessing the analysis host's zone instead would shift
    one source against the others.
    """
    if value is None or value == "" or isinstance(value, bool):
        return None
    try:
        if isinstance(value, (int, float)):
            seconds = value / 1000 if value > 1e11 else value
            dt = datetime.fromtimestamp(seconds, tz=timezone.utc)
        else:
            text = str(value).strip()
            if text.endswith(("Z", "z")):
                text = text[:-1] + "+00:00"
            dt = datetime.fromisoformat(text)
    except (ValueError, OverflowError, OSError):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    dt = dt.astimezone(timezone.utc)
    base = dt.strftime("%Y-%m-%dT%H:%M:%S")
    ms = dt.microsecond // 1000
    return f"{base}.{ms:03d}Z" if ms else f"{base}Z"


def parse_iso(iso: str) -> float:
    """Seconds since the epoch for a value produced by ``to_iso``."""
    return datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp()


# ── addresses and paths ───────────────────────────────────────────────


def is_valid_ipv4(ip: Any) -> bool:
    parts = str(ip).split(".")
    return len(parts) == 4 and all(p.isdigit() and len(p) <= 3 and int(p) <= 255 for p in parts)


def ip_scope(ip: str) -> str:
    """public | private | loopback | link_local | multicast | broadcast | unspecified"""
    a, b = (int(x) for x in ip.split(".")[:2])
    if a == 0:
        return "unspecified"
    if a == 127:
        return "loopback"
    if a == 10 or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168):
        return "private"
    if a == 100 and 64 <= b <= 127:
        return "private"  # carrier-grade NAT
    if a == 169 and b == 254:
        return "link_local"
    if 224 <= a <= 239:
        return "multicast"
    if ip == "255.255.255.255":
        return "broadcast"
    return "public"


def norm_path(p: Any) -> str:
    """Lower-case, forward slashes, no drive letter or NT device prefix."""
    s = str(p or "").strip().replace("\\", "/").lower()
    s = re.sub(r"^/\?\?/", "", s)
    s = re.sub(r"^/device/harddiskvolume\d+/", "", s)
    s = re.sub(r"^/systemroot/", "windows/", s)
    s = re.sub(r"^[a-z]:", "", s)
    return s.lstrip("/")


def basename(p: Any) -> str:
    return norm_path(p).split("/")[-1]


def image_name(name: Any) -> str:
    return re.sub(r"\.exe$", "", basename(name), flags=re.I)


def host_from_url(url: str) -> str | None:
    try:
        host = urlsplit(url).hostname
    except ValueError:
        return None
    return host.lower() if host else None


def techniques_to_tactics(techniques: Iterable[str]) -> list[str]:
    return uniq(TECHNIQUE_TACTIC.get(str(t).split(".")[0]) for t in techniques)


# ── entity extraction ─────────────────────────────────────────────────


def empty_entities() -> dict[str, list[Any]]:
    return {k: [] for k in ("ips", "domains", "urls", "images", "files", "paths", "users", "hosts", "pids", "ports")}


def entities_from_text(text: Any, into: dict[str, list[Any]]) -> None:
    """Pull IPs, URLs, Windows paths and executable names out of free text."""
    s = str(text or "")
    into["ips"].extend(ip for ip in IPV4_IN_TEXT.findall(s) if is_valid_ipv4(ip))
    into["urls"].extend(URL_IN_TEXT.findall(s))
    into["paths"].extend(WIN_PATH_IN_TEXT.findall(s))
    into["files"].extend(EXE_IN_TEXT.findall(s))


def _numbers(values: Iterable[Any]) -> list[int]:
    out = []
    for v in values:
        try:
            out.append(int(v))
        except (TypeError, ValueError):
            continue
    return out


def finish_entities(e: dict[str, list[Any]]) -> dict[str, list[Any]]:
    """Shared final pass: derive hosts from URLs and names from paths, validate, de-duplicate."""
    for url in e["urls"]:
        host = host_from_url(url)
        if not host:
            continue
        (e["ips"] if is_valid_ipv4(host) else e["domains"]).append(host)
    for p in e["paths"]:
        e["files"].append(basename(p))

    files = uniq(basename(f) for f in e["files"])
    return {
        "ips": uniq(ip for ip in e["ips"] if is_valid_ipv4(ip)),
        "domains": uniq(str(d).lower() for d in e["domains"]),
        "urls": uniq(e["urls"]),
        "images": uniq([*(image_name(i) for i in e["images"]),
                        *(image_name(f) for f in files if EXECUTABLE_EXT.search(f))]),
        "files": files,
        # Only a path with a directory identifies a file better than its name
        "paths": uniq(p for p in (norm_path(x) for x in e["paths"]) if "/" in p),
        "users": uniq(str(u).lower() for u in e["users"]),
        "hosts": uniq(str(h).lower() for h in e["hosts"]),
        "pids": uniq(_numbers(e["pids"])),
        "ports": uniq(_numbers(e["ports"])),
    }
