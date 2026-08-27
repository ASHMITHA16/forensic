"""
Network rules -- MEM-N-001 through MEM-N-003.

A memory image gives you sockets without traffic. You can see that a
process held a connection to an address; you cannot see a single byte
that crossed it. Every rule here is therefore about *association*, and
the interpretations are written to stay inside what a socket structure
can actually support.

The port rule (MEM-N-003) is the weakest in the pack and is scored that
way. Port 4444 is Metasploit's default and also an ordinary ephemeral
port that any client can be assigned. 8080 is a penetration-testing
cliché and also the single most common alternate HTTP port in existence.
The rule earns its place by pairing the port with the owning process --
8080 owned by a browser is noise; 8080 owned by a binary in a temp
directory is worth an analyst's morning.
"""

from __future__ import annotations

from typing import Iterable

from ..engine import DetectionContext, Rule, RuleHit

#: Ports with a strong association with offensive tooling defaults.
#: Weight reflects how much of that association survives contact with a
#: real network, where these are also ordinary ports.
#:
#: 443 and 80 are deliberately absent. C2 hides in HTTPS precisely because
#: HTTPS is ubiquitous, so a rule keyed on 443 would emit one finding per
#: browser tab on a healthy machine. A rule that fires hundreds of times
#: on a clean image is not a weak rule, it is a broken one -- the analyst
#: learns to filter the rule out, and the one real hit goes with it.
SUSPICIOUS_PORTS: dict[int, tuple[str, float]] = {
    4444: ("Metasploit's default handler port", 0.15),
    4445: ("Metasploit handler range", 0.10),
    1337: ("conventional 'leet' port, common in commodity backdoors", 0.15),
    31337: ("Back Orifice default, still used by commodity tooling", 0.15),
    9001: ("Tor ORPort default, also common in Cobalt Strike profiles", 0.10),
    8080: ("common C2 and proxy port, though also the most common alternate "
           "HTTP port in ordinary use", 0.05),
    5555: ("Android Debug Bridge and several commodity RATs", 0.10),
}

#: Processes for which an outbound connection to the internet is their
#: entire job. Confidence is reduced explicitly and visibly.
EXPECTED_NETWORK_PROCESSES = frozenset({
    "chrome.exe", "msedge.exe", "firefox.exe", "opera.exe", "brave.exe",
    "iexplore.exe", "outlook.exe", "teams.exe", "slack.exe", "onedrive.exe",
    "svchost.exe", "searchapp.exe", "backgroundtaskhost.exe", "spotify.exe",
    "discord.exe", "zoom.exe", "dropbox.exe", "googledrivesync.exe",
    "msmpeng.exe", "updater.exe", "curl.exe",
})

#: Processes that normally listen on a socket. A listener owned by
#: something outside this set is the interesting case.
EXPECTED_LISTENERS = frozenset({
    "system", "svchost.exe", "services.exe", "lsass.exe", "spoolsv.exe",
    "wininit.exe", "sqlservr.exe", "w3wp.exe", "inetinfo.exe", "nginx.exe",
    "httpd.exe", "mysqld.exe", "postgres.exe", "dns.exe", "vmware-hostd.exe",
    "sshd.exe", "mongod.exe", "dockerd.exe",
})


def _owner(obs, context: DetectionContext) -> str:
    owner = obs.get("owner")
    if owner:
        return str(owner)
    return context.process_name(obs.get("pid")) or "unknown"


def _refs(obs, context: DetectionContext) -> list[str]:
    pid = obs.get("pid")
    refs = [obs.obs_id]
    if isinstance(pid, int):
        refs.extend(p.obs_id for p in context.process_by_pid.get(pid, []))
    return refs


# ── MEM-N-001 ─────────────────────────────────────────────────────────


def external_established_connection(
    context: DetectionContext,
) -> Iterable[RuleHit]:
    for obs in context.network:
        if obs.get("foreign_scope") != "public":
            continue
        if str(obs.get("state") or "").upper() != "ESTABLISHED":
            continue

        owner = _owner(obs, context)
        pid = obs.get("pid")

        adjustments = []
        if owner.lower() in EXPECTED_NETWORK_PROCESSES:
            adjustments.append((
                -0.30,
                f"-0.30 {owner} routinely maintains outbound internet "
                f"connections as part of normal operation",
            ))
        if obs.get("netscan_only"):
            adjustments.append((
                -0.05,
                "-0.05 the connection was recovered by pool scan only, so its "
                "recorded state may not describe the moment of acquisition",
            ))

        yield RuleHit(
            observation_refs=_refs(obs, context),
            entities={
                "pids": [pid] if isinstance(pid, int) else [],
                "processes": [owner] if owner != "unknown" else [],
                "ips": [obs.get("foreign_address")],
                "ports": [obs.get("foreign_port")]
                if obs.get("foreign_port") else [],
            },
            observation_statement=(
                f"A {obs.get('protocol')} socket owned by PID {pid} ({owner}) "
                f"records state ESTABLISHED to "
                f"{obs.get('foreign_address')}:{obs.get('foreign_port')}, which "
                f"is a publicly routable address."
                + (f" The socket was created at {obs.get('created_utc')}."
                   if obs.get("created_utc") else "")
            ),
            interpretation=(
                "The process held a connection to a host outside the local "
                "network. Whether that matters depends entirely on the process "
                "and the address; a memory image records the association and "
                "nothing about what crossed the connection."
            ),
            alternative_explanations=[
                "Ordinary application traffic -- updates, telemetry, cloud "
                "sync, or a user browsing.",
                "A stale socket structure recovered from freed pool memory "
                "whose state field no longer reflects reality.",
                "A legitimate remote administration or monitoring agent.",
            ],
            analyst_action=(
                "Resolve the address against threat intelligence and the "
                "organisation's own egress records, and correlate the socket "
                "creation time with the owning process's activity."
            ),
            confidence_adjustments=adjustments,
            first_seen_utc=obs.get("created_utc"),
        )


# ── MEM-N-002 ─────────────────────────────────────────────────────────


def unexpected_listener(context: DetectionContext) -> Iterable[RuleHit]:
    for obs in context.network:
        if str(obs.get("state") or "").upper() != "LISTENING":
            continue
        if obs.get("local_scope") == "loopback":
            # A loopback listener is not reachable from the network and is
            # how a great deal of ordinary local IPC is implemented.
            continue

        owner = _owner(obs, context)
        if owner.lower() in EXPECTED_LISTENERS:
            continue

        pid = obs.get("pid")
        port = obs.get("local_port")

        adjustments = []
        if isinstance(port, int) and port >= 49152:
            adjustments.append((
                -0.10,
                f"-0.10 port {port} is in the ephemeral range, where a "
                f"listening socket is more likely to be a transient client "
                f"artifact",
            ))

        yield RuleHit(
            observation_refs=_refs(obs, context),
            entities={
                "pids": [pid] if isinstance(pid, int) else [],
                "processes": [owner] if owner != "unknown" else [],
                "ports": [port] if port else [],
            },
            observation_statement=(
                f"A {obs.get('protocol')} socket owned by PID {pid} ({owner}) "
                f"is in state LISTENING on "
                f"{obs.get('local_address')}:{port}. The owning process is not "
                f"one of the Windows components that ordinarily accept "
                f"connections."
            ),
            interpretation=(
                "A non-service process is accepting inbound connections on a "
                "network-reachable address. That is the shape of a backdoor "
                "listener, and also the shape of any user application that "
                "opens a port."
            ),
            alternative_explanations=[
                "A legitimate application with a local server component -- "
                "development tools, media servers, game clients and "
                "collaboration software all do this.",
                "A peer-to-peer or file-sharing feature of an installed "
                "application.",
                "A stale socket structure recovered from freed memory.",
            ],
            analyst_action=(
                "Identify the listening binary and determine whether the port "
                "is documented for it. Check the firewall configuration for a "
                "matching allow rule, and when it exists, who created it."
            ),
            confidence_adjustments=adjustments,
            first_seen_utc=obs.get("created_utc"),
        )


# ── MEM-N-003 ─────────────────────────────────────────────────────────


def suspicious_port(context: DetectionContext) -> Iterable[RuleHit]:
    for obs in context.network:
        ports = [
            ("foreign", obs.get("foreign_port")),
            ("local", obs.get("local_port")),
        ]
        matches = [
            (side, port) for side, port in ports
            if isinstance(port, int) and port in SUSPICIOUS_PORTS
        ]
        if not matches:
            continue

        side, port = matches[0]
        reason, weight = SUSPICIOUS_PORTS[port]
        owner = _owner(obs, context)
        pid = obs.get("pid")

        adjustments = [(weight, f"{weight:+.2f} port {port}: {reason}")]
        if owner.lower() in EXPECTED_NETWORK_PROCESSES:
            adjustments.append((
                -0.25,
                f"-0.25 {owner} is an ordinary network client, for which any "
                f"port number is unremarkable",
            ))
        if obs.get("foreign_scope") == "public" and side == "foreign":
            adjustments.append((
                0.10,
                "+0.10 the port is on a publicly routable remote address",
            ))

        yield RuleHit(
            observation_refs=_refs(obs, context),
            entities={
                "pids": [pid] if isinstance(pid, int) else [],
                "processes": [owner] if owner != "unknown" else [],
                "ports": [port],
                "ips": [obs.get("foreign_address")]
                if obs.get("foreign_address") else [],
            },
            observation_statement=(
                f"A {obs.get('protocol')} socket owned by PID {pid} ({owner}) "
                f"uses {side} port {port} "
                f"({obs.get('local_address')}:{obs.get('local_port')} -> "
                f"{obs.get('foreign_address')}:{obs.get('foreign_port')}, state "
                f"{obs.get('state')})."
            ),
            interpretation=(
                f"Port {port} is {reason}. A port number is a weak indicator on "
                f"its own; it earns attention here because of which process "
                f"owns it, not because of the number."
            ),
            alternative_explanations=[
                "Coincidence. Ephemeral ports are assigned from a large range "
                "and any given value appears regularly on a busy system.",
                "A legitimate service or development tool configured to use "
                "this port.",
                "An internal scanning or monitoring tool operated by the "
                "organisation itself.",
            ],
            analyst_action=(
                "Judge the owning process first. Confirm against network flow "
                "records whether traffic actually crossed this socket -- a "
                "memory image cannot answer that."
            ),
            confidence_adjustments=adjustments,
            first_seen_utc=obs.get("created_utc"),
        )


RULES = (
    Rule(
        "MEM-N-001", "1.0", "Established connection to an external host",
        "network", "MEDIUM", 0.50, external_established_connection,
        ("T1071",),
        "ESTABLISHED socket to a publicly routable address.",
    ),
    Rule(
        "MEM-N-002", "1.0", "Listening socket owned by a non-service process",
        "network", "HIGH", 0.55, unexpected_listener,
        ("T1571", "T1205"),
        "LISTENING socket on a non-loopback address owned by a user process.",
    ),
    Rule(
        "MEM-N-003", "1.0", "Socket on a port associated with offensive tooling",
        "network", "LOW", 0.35, suspicious_port,
        ("T1571",),
        "Local or foreign port matches a known tooling default.",
    ),
)
