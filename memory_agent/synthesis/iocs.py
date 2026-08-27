"""
memory_agent.synthesis.iocs
─────────────────────────────────────────────────────────────────────
Indicators, with the context that makes them usable.

An IOC list is the part of this output most likely to be pasted directly
into a blocklist, which makes hygiene here a safety property rather than
a nicety. Three rules:

**Allowlist aggressively.** RFC1918 addresses, loopback, link-local,
multicast and broadcast are removed unconditionally -- pushing
``192.168.1.1`` into a blocklist breaks the network it was meant to
protect. Microsoft and OS-vendor ranges are removed under a flag, off by
default, because they are also where a great deal of real C2 hides.

**Every indicator keeps its context and its false-positive risk.** A
bare list of addresses is unusable: the analyst cannot tell which one to
look at first, and cannot tell which are load-bearing. Each record says
where it came from, which finding it supports, and how likely it is to
be noise.

**Nothing is defanged by default.** ``hxxp://`` and ``1.2.3[.]4`` exist
to stop a human accidentally clicking a link in a report. They also
break every automated consumer, so defanging is a rendering option
applied on export, never to the stored value.

Indicators are drawn from findings first -- an address that supports a
finding is worth more than one merely present in memory -- and from
observations second, at lower confidence.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Iterable, Sequence

from ..core.schema import IOC, Finding, IdFactory, Observation, clamp_confidence

#: Networks never emitted as indicators. Blocking any of these does harm
#: and catches nothing.
_NEVER_EMIT = (
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("255.255.255.255/32"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("ff00::/8"),
)

#: Vendor ranges, excluded only when ``allowlist_vendor`` is set. Off by
#: default: telemetry endpoints and C2 share these networks.
_VENDOR_NETWORKS = (
    ipaddress.ip_network("13.64.0.0/11"),      # Azure
    ipaddress.ip_network("20.0.0.0/8"),        # Azure
    ipaddress.ip_network("40.64.0.0/10"),      # Azure
    ipaddress.ip_network("52.96.0.0/12"),      # Microsoft 365
    ipaddress.ip_network("104.40.0.0/13"),     # Azure
)

#: Process names too common to be useful as indicators on their own.
_UBIQUITOUS_PROCESSES = frozenset({
    "svchost.exe", "explorer.exe", "system", "smss.exe", "csrss.exe",
    "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe", "cmd.exe",
    "conhost.exe", "dllhost.exe", "taskhostw.exe", "runtimebroker.exe",
    "powershell.exe", "rundll32.exe", "msiexec.exe", "searchapp.exe",
})

_URL_RE = re.compile(r"https?://[^\s\"'<>)\]]+", re.IGNORECASE)
_DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"(?:com|net|org|io|ru|cn|info|biz|xyz|top|club|online|site|pw|cc|tk|su|"
    r"me|co|uk|de|fr|nl|br|in|jp|kr|ir)\b",
    re.IGNORECASE,
)
_SHA256_RE = re.compile(r"\b[a-f0-9]{64}\b", re.IGNORECASE)

#: Domains that appear in ordinary command lines and configuration.
_DOMAIN_ALLOWLIST = frozenset({
    "microsoft.com", "windows.com", "windowsupdate.com", "msftncsi.com",
    "msftconnecttest.com", "office.com", "office365.com", "live.com",
    "msn.com", "bing.com", "google.com", "gstatic.com", "mozilla.org",
    "digicert.com", "verisign.com", "symcb.com", "globalsign.com",
    "schemas.microsoft.com", "w3.org", "example.com", "localhost",
})


def is_emittable_ip(value: str, allowlist_vendor: bool = False) -> bool:
    try:
        addr = ipaddress.ip_address(value.strip())
    except ValueError:
        return False
    if any(addr in net for net in _NEVER_EMIT):
        return False
    if allowlist_vendor and any(addr in net for net in _VENDOR_NETWORKS):
        return False
    return True


def registrable_domain(value: str) -> str:
    parts = value.strip().lower().rstrip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else value.strip().lower()


def defang(value: str, ioc_type: str) -> str:
    """Render an indicator unclickable. Applied on export only."""
    if ioc_type in ("ipv4", "domain"):
        return value.replace(".", "[.]")
    if ioc_type == "ipv6":
        return value.replace(":", "[:]")
    if ioc_type == "url":
        out = re.sub(r"^http", "hxxp", value, flags=re.IGNORECASE)
        return out.replace("://", "[://]", 1)
    return value


class _Collector:
    """
    Accumulates indicators, keeping the strongest record for each value.

    Deduplication is case-insensitive on ``(type, value)``. When the same
    address arrives from a finding and again from a bare observation, the
    finding's record wins: it carries higher confidence and the context
    the analyst actually needs.
    """

    def __init__(self) -> None:
        self.items: dict[tuple[str, str], dict[str, Any]] = {}

    def add(
        self,
        ioc_type: str,
        value: Any,
        context: str,
        confidence: float,
        risk: str,
        observation_refs: Iterable[str] = (),
        finding_refs: Iterable[str] = (),
    ) -> None:
        if value is None:
            return
        text = str(value).strip()
        if not text:
            return

        key = (ioc_type, text.lower())
        existing = self.items.get(key)
        if existing is not None:
            existing["observation_refs"].update(observation_refs)
            existing["finding_refs"].update(finding_refs)
            if confidence > existing["confidence"]:
                existing.update({
                    "confidence": confidence,
                    "context": context,
                    "false_positive_risk": risk,
                })
            return

        self.items[key] = {
            "type": ioc_type,
            "value": text,
            "context": context,
            "confidence": confidence,
            "false_positive_risk": risk,
            "observation_refs": set(observation_refs),
            "finding_refs": set(finding_refs),
        }


def extract_iocs(
    observations: Sequence[Observation],
    findings: Sequence[Finding] = (),
    ids: IdFactory | None = None,
    allowlist_vendor: bool = False,
) -> tuple[list[IOC], list[str]]:
    """
    Build the IOC list. Returns ``(iocs, notes)``.

    ``notes`` records what was filtered out and why, so a reader can tell
    an empty IOC list produced by a clean image from one produced by an
    over-eager allowlist.
    """
    ids = ids or IdFactory()
    collector = _Collector()
    filtered = {"non_routable_ip": 0, "allowlisted_domain": 0,
                "ubiquitous_process": 0, "vendor_range": 0}

    obs_by_id = {o.obs_id: o for o in observations}

    # ── from findings (the high-value path) ──────────────────────────
    for finding in findings:
        entities = finding.entities or {}
        context_prefix = f"{finding.rule_id}: {finding.title}"
        risk = "low" if finding.confidence >= 0.7 else (
            "medium" if finding.confidence >= 0.5 else "high"
        )

        for ip in entities.get("ips", []):
            if not ip:
                continue
            if not is_emittable_ip(str(ip), allowlist_vendor):
                try:
                    addr = ipaddress.ip_address(str(ip).strip())
                    if allowlist_vendor and any(addr in n for n in _VENDOR_NETWORKS):
                        filtered["vendor_range"] += 1
                    else:
                        filtered["non_routable_ip"] += 1
                except ValueError:
                    filtered["non_routable_ip"] += 1
                continue
            version = ipaddress.ip_address(str(ip).strip()).version
            collector.add(
                "ipv6" if version == 6 else "ipv4", ip,
                f"{context_prefix}. {_ip_context(finding, obs_by_id, str(ip))}",
                clamp_confidence(finding.confidence), risk,
                finding.observation_refs, [finding.finding_id],
            )

        for url in entities.get("urls", []):
            if url:
                collector.add(
                    "url", url, f"{context_prefix}. Referenced in a command line.",
                    clamp_confidence(finding.confidence), risk,
                    finding.observation_refs, [finding.finding_id],
                )
                for domain in _DOMAIN_RE.findall(str(url)):
                    if registrable_domain(domain) not in _DOMAIN_ALLOWLIST:
                        collector.add(
                            "domain", domain,
                            f"{context_prefix}. Host of a URL in a command line.",
                            clamp_confidence(finding.confidence - 0.05), risk,
                            finding.observation_refs, [finding.finding_id],
                        )

        for path in entities.get("files", []):
            if path:
                collector.add(
                    "filepath", path, f"{context_prefix}.",
                    clamp_confidence(finding.confidence), risk,
                    finding.observation_refs, [finding.finding_id],
                )

        for name in entities.get("processes", []):
            if not name:
                continue
            if str(name).lower() in _UBIQUITOUS_PROCESSES:
                filtered["ubiquitous_process"] += 1
                continue
            collector.add(
                "process_name", name, f"{context_prefix}.",
                clamp_confidence(finding.confidence - 0.10), "medium",
                finding.observation_refs, [finding.finding_id],
            )

        for port in entities.get("ports", []):
            if isinstance(port, int):
                collector.add(
                    "port", str(port), f"{context_prefix}.",
                    clamp_confidence(finding.confidence - 0.20), "high",
                    finding.observation_refs, [finding.finding_id],
                )

        for service in entities.get("services", []):
            if service:
                collector.add(
                    "registry_key",
                    f"HKLM\\SYSTEM\\CurrentControlSet\\Services\\{service}",
                    f"{context_prefix}. Service registration implied by the "
                    f"in-memory service record.",
                    clamp_confidence(finding.confidence - 0.10), "medium",
                    finding.observation_refs, [finding.finding_id],
                )

    # ── from observations (lower value, still worth having) ──────────
    for obs in observations:
        if obs.type == "network":
            addr = obs.get("foreign_address")
            if not addr or obs.get("foreign_scope") != "public":
                # Count only things that are actually addresses. A
                # LISTENING socket renders its peer as "*", and counting
                # those would inflate the "excluded as non-routable"
                # figure in the notes into a number that misleads.
                if obs.get("foreign_scope") in ("private", "loopback",
                                                "link_local", "multicast",
                                                "reserved"):
                    filtered["non_routable_ip"] += 1
                continue
            if not is_emittable_ip(str(addr), allowlist_vendor):
                filtered["vendor_range" if allowlist_vendor
                         else "non_routable_ip"] += 1
                continue
            version = ipaddress.ip_address(str(addr).strip()).version
            collector.add(
                "ipv6" if version == 6 else "ipv4", addr,
                f"Foreign address of a {obs.get('protocol')} socket in state "
                f"{obs.get('state')} owned by PID {obs.get('pid')} "
                f"({obs.get('owner')}). No rule flagged this connection.",
                0.35, "high", [obs.obs_id], [],
            )

        elif obs.type == "command":
            text = str(obs.get("command_line") or "")
            for url in _URL_RE.findall(text):
                collector.add(
                    "url", url,
                    f"Present in a {obs.get('source_kind')} record for PID "
                    f"{obs.get('pid')}. No rule flagged this command.",
                    0.30, "high", [obs.obs_id], [],
                )
            for digest in _SHA256_RE.findall(text):
                collector.add(
                    "sha256", digest.lower(),
                    f"SHA-256-shaped token in a command line for PID "
                    f"{obs.get('pid')}.",
                    0.25, "high", [obs.obs_id], [],
                )

        elif obs.type == "service":
            binary = obs.get("executable")
            if binary and obs.get("executable_name") not in _UBIQUITOUS_PROCESSES:
                collector.add(
                    "filepath", binary,
                    f"Binary of service {obs.get('name')!r} "
                    f"({obs.get('start_type')}). No rule flagged this service.",
                    0.25, "high", [obs.obs_id], [],
                )

    # ── emit, sorted for determinism ─────────────────────────────────
    iocs: list[IOC] = []
    for key in sorted(collector.items):
        item = collector.items[key]
        iocs.append(IOC(
            ioc_id=ids.ioc(),
            type=item["type"],
            value=item["value"],
            context=item["context"],
            observation_refs=sorted(item["observation_refs"]),
            finding_refs=sorted(item["finding_refs"]),
            confidence=item["confidence"],
            false_positive_risk=item["false_positive_risk"],
        ))

    notes: list[str] = []
    if filtered["non_routable_ip"]:
        notes.append(
            f"{filtered['non_routable_ip']} address(es) were excluded as "
            f"non-routable (RFC1918, loopback, link-local, multicast or "
            f"reserved). Emitting them as indicators would cause harm and "
            f"catch nothing."
        )
    if filtered["vendor_range"]:
        notes.append(
            f"{filtered['vendor_range']} address(es) were excluded as vendor "
            f"infrastructure because --allowlist-vendor was set. Note that C2 "
            f"infrastructure is routinely hosted in these ranges."
        )
    if filtered["ubiquitous_process"]:
        notes.append(
            f"{filtered['ubiquitous_process']} process name(s) were excluded "
            f"as too common to function as indicators."
        )
    if not iocs:
        notes.append(
            "No indicators were extracted. This means no routable address, "
            "URL, or unusual binary path was recovered -- not that the image "
            "is clean."
        )

    return iocs, notes


def _ip_context(
    finding: Finding, obs_by_id: dict[str, Observation], ip: str
) -> str:
    """Locate the socket this address came from, for the context string."""
    for ref in finding.observation_refs:
        obs = obs_by_id.get(ref)
        if obs is None or obs.type != "network":
            continue
        if str(obs.get("foreign_address")) == ip:
            return (
                f"Foreign address of a {obs.get('protocol')} socket in state "
                f"{obs.get('state')} owned by PID {obs.get('pid')} "
                f"({obs.get('owner')})."
            )
    return "Address named by the finding above."


def render_defanged(iocs: Sequence[IOC]) -> list[dict[str, Any]]:
    """Export view with values defanged. The stored values are unchanged."""
    out = []
    for ioc in iocs:
        record = ioc.to_dict()
        record["value"] = defang(ioc.value, ioc.type)
        record["defanged"] = True
        out.append(record)
    return out
