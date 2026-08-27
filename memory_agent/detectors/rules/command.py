"""
Command rules -- MEM-C-001 through MEM-C-003.

Command lines are the richest artifact a memory image gives up, and the
easiest to over-read. Three constraints shape these rules:

**Source strength varies.** A hit on ``cmdline`` describes how a process
was launched. A hit on ``cmdscan`` describes a string carved from a
history buffer that may predate the session and may belong to no
resident process at all. The same text supports a materially weaker
claim depending on which source it came from, so every rule reads
``source_kind`` and adjusts.

**Legitimate administration looks identical.** ``powershell -nop -w
hidden -enc <base64>`` is a textbook attack pattern and also exactly what
a great many software deployment tools emit. The rules fire, and say so
in the alternatives, rather than pretending the ambiguity is resolvable
from memory alone.

**Nothing is decoded.** MEM-C-001 records that a base64 payload is
present and how long it is. It does not decode it and report what it
found. Decoding is analysis of attacker-controlled content, it belongs
in a sandbox rather than in an extraction pipeline, and the analyst
action says so.
"""

from __future__ import annotations

import re
from typing import Iterable

from ..engine import DetectionContext, Rule, RuleHit

#: PowerShell flags whose combination is characteristic of scripted
#: execution designed not to be seen. Each carries its own weight.
POWERSHELL_FLAGS: tuple[tuple[str, str, float], ...] = (
    (r"(?:^|\s)[-/](?:e|en|enc|encod|encode|encoded|encodedcommand)\b",
     "-EncodedCommand: the script body is base64 rather than readable text",
     0.20),
    (r"(?:^|\s)[-/]w(?:in|indow|indowstyle)?\s+hidden\b",
     "-WindowStyle Hidden: no console window is displayed",
     0.10),
    (r"(?:^|\s)[-/]nop(?:rofile)?\b",
     "-NoProfile: the user's profile is bypassed",
     0.05),
    (r"(?:^|\s)[-/]ep?\s*(?:bypass|unrestricted)\b|executionpolicy\s+bypass",
     "ExecutionPolicy Bypass: script signing policy is disabled",
     0.10),
    (r"(?:^|\s)[-/]noni(?:nteractive)?\b",
     "-NonInteractive: no user prompt is possible",
     0.03),
    (r"downloadstring|downloadfile|invoke-expression|\biex\b|invoke-webrequest",
     "in-line download-and-execute construct",
     0.15),
    (r"frombase64string",
     "explicit base64 decoding inside the command",
     0.10),
)

POWERSHELL_NAMES = frozenset({"powershell.exe", "powershell_ise.exe", "pwsh.exe"})

#: Living-off-the-land patterns: signed Microsoft binaries invoked in a
#: way that turns them into downloaders or script hosts.
LOLBIN_PATTERNS: tuple[tuple[str, str, str, float], ...] = (
    ("certutil", r"-urlcache|-decode|-encode|\.exe\s+-f\s+http",
     "certutil used to fetch or decode a file rather than to manage "
     "certificates", 0.25),
    ("bitsadmin", r"/transfer|/create|/addfile",
     "bitsadmin used to transfer a file", 0.25),
    ("mshta", r"http|javascript:|vbscript:",
     "mshta executing remote or inline script", 0.30),
    ("regsvr32", r"/i:\s*http|scrobj\.dll",
     "regsvr32 loading a remote scriptlet (the 'Squiblydoo' pattern)", 0.30),
    ("rundll32", r"javascript:|url\.dll|shell32\.dll\s*,\s*shellexec",
     "rundll32 used as a script host", 0.25),
    ("msiexec", r"/i\s+http|/q\s+.*http",
     "msiexec installing a package from a remote URL", 0.20),
    ("wmic", r"process\s+call\s+create|/node:",
     "wmic used to create a process, possibly remotely", 0.20),
    ("curl", r"-o\s|\s--output\s", "curl writing a downloaded file to disk",
     0.10),
    ("esentutl", r"/y|/vss", "esentutl used to copy a locked file", 0.25),
)

#: Host discovery commands. Any one is unremarkable; a burst is not.
DISCOVERY_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"\bwhoami\b", "whoami"),
    (r"\bnet\s+user\b", "net user"),
    (r"\bnet\s+group\b", "net group"),
    (r"\bnet\s+localgroup\b", "net localgroup"),
    (r"\bnet\s+view\b", "net view"),
    (r"\bipconfig\b", "ipconfig"),
    (r"\bsysteminfo\b", "systeminfo"),
    (r"\bnltest\b", "nltest"),
    (r"\barp\s+-a\b", "arp -a"),
    (r"\bnetstat\b", "netstat"),
    (r"\btasklist\b", "tasklist"),
    (r"\bquser\b", "quser"),
    (r"\bwhoami\s+/(?:priv|groups|all)\b", "whoami /priv"),
)

#: Minimum distinct discovery commands before MEM-C-003 fires. Below
#: this, an administrator typing `ipconfig` would generate a finding.
DISCOVERY_THRESHOLD = 3

_BASE64_RE = re.compile(r"[A-Za-z0-9+/=]{40,}")

#: Weakening applied per source. A carved history entry is not a
#: statement about a process that ran.
SOURCE_ADJUSTMENT = {
    "launch_parameters": (0.0, None),
    "console_buffer": (
        -0.10,
        "-0.10 recovered from a console screen buffer, which contains "
        "displayed output as well as typed input",
    ),
    "typed_history": (
        -0.15,
        "-0.15 carved from a command history buffer, which can outlive its "
        "process and can originate in an earlier session",
    ),
}


def _source_adjustment(obs) -> list[tuple[float, str]]:
    weight, text = SOURCE_ADJUSTMENT.get(str(obs.get("source_kind")), (0.0, None))
    return [(weight, text)] if text else []


def _refs(obs, context: DetectionContext) -> list[str]:
    pid = obs.get("pid")
    refs = [obs.obs_id]
    if isinstance(pid, int):
        refs.extend(p.obs_id for p in context.process_by_pid.get(pid, []))
    return refs


# ── MEM-C-001 ─────────────────────────────────────────────────────────


def obfuscated_powershell(context: DetectionContext) -> Iterable[RuleHit]:
    for obs in context.commands:
        text = str(obs.get("command_line") or "")
        if not text:
            continue

        name = str(obs.get("executable_name") or "").lower()
        lowered = text.lower()
        if name not in POWERSHELL_NAMES and "powershell" not in lowered \
                and "pwsh" not in lowered:
            continue

        matched: list[tuple[str, float]] = []
        for pattern, description, weight in POWERSHELL_FLAGS:
            if re.search(pattern, lowered):
                matched.append((description, weight))

        if not matched:
            continue

        adjustments = [(w, f"+{w:.2f} {d}") for d, w in matched]
        adjustments.extend(_source_adjustment(obs))

        blob = _BASE64_RE.search(text)
        payload_note = ""
        if blob:
            payload_note = (
                f" A base64-like token of {len(blob.group(0))} characters is "
                f"present in the command."
            )

        pid = obs.get("pid")
        yield RuleHit(
            observation_refs=_refs(obs, context),
            entities={
                "pids": [pid] if isinstance(pid, int) else [],
                "processes": [obs.get("process")] if obs.get("process") else [],
            },
            observation_statement=(
                f"A {obs.get('source_kind')} record for PID {pid} "
                f"({obs.get('process')}) contains the command: {text[:600]!r}. "
                f"It matches {len(matched)} PowerShell concealment pattern(s): "
                f"{'; '.join(d for d, _ in matched)}.{payload_note}"
            ),
            interpretation=(
                "PowerShell invoked with flags that suppress the console, "
                "bypass execution policy, or carry the script body as encoded "
                "text. The combination is characteristic of scripted execution "
                "intended not to be observed."
            ),
            alternative_explanations=[
                "Legitimate software deployment. SCCM, Intune, Group Policy "
                "and most endpoint management suites launch PowerShell with "
                "exactly these flags as a matter of course.",
                "An administrator's own automation or scheduled task.",
                "A vendor installer that wraps its PowerShell steps to avoid "
                "flashing a console window at the user.",
            ],
            analyst_action=(
                "Decode the base64 payload in an isolated environment -- not on "
                "the analysis host -- and identify the parent process. A "
                "management agent as the parent is usually the end of it; a "
                "browser or Office process is not."
            ),
            confidence_adjustments=adjustments,
            severity_override="CRITICAL" if len(matched) >= 3 else None,
        )


# ── MEM-C-002 ─────────────────────────────────────────────────────────


def lolbin_abuse(context: DetectionContext) -> Iterable[RuleHit]:
    for obs in context.commands:
        text = str(obs.get("command_line") or "")
        if not text:
            continue
        lowered = text.lower()

        for binary, pattern, description, weight in LOLBIN_PATTERNS:
            if binary not in lowered:
                continue
            if not re.search(pattern, lowered):
                continue

            adjustments = [(weight, f"+{weight:.2f} {description}")]
            adjustments.extend(_source_adjustment(obs))
            if re.search(r"https?://", lowered):
                adjustments.append((
                    0.10, "+0.10 the command contains a URL"
                ))

            pid = obs.get("pid")
            urls = re.findall(r"https?://[^\s\"'>]+", text)

            yield RuleHit(
                observation_refs=_refs(obs, context),
                entities={
                    "pids": [pid] if isinstance(pid, int) else [],
                    "processes": [obs.get("process")]
                    if obs.get("process") else [],
                    "urls": urls,
                },
                observation_statement=(
                    f"A {obs.get('source_kind')} record for PID {pid} "
                    f"({obs.get('process')}) contains: {text[:600]!r}. The "
                    f"signed Microsoft binary {binary} is invoked with "
                    f"arguments matching: {description}."
                ),
                interpretation=(
                    f"{binary} is a signed Microsoft binary present on every "
                    f"Windows installation. Used this way it performs a file "
                    f"transfer or executes script content, which lets an "
                    f"operator avoid introducing their own executable."
                ),
                alternative_explanations=[
                    f"Legitimate administrative use -- {binary} exists because "
                    f"administrators need it, and these arguments are "
                    f"documented.",
                    "A software installer or updater using a built-in Windows "
                    "utility to fetch its own components.",
                    "A scripted build or deployment step in a development "
                    "environment.",
                ],
                analyst_action=(
                    "Retrieve the referenced URL or file path and determine "
                    "what was fetched. Check whether the destination file still "
                    "exists on disk and correlate its creation time against "
                    "this command."
                ),
                confidence_adjustments=adjustments,
            )
            break  # one finding per command, on the strongest match


# ── MEM-C-003 ─────────────────────────────────────────────────────────


def discovery_burst(context: DetectionContext) -> Iterable[RuleHit]:
    """
    Cluster discovery commands per process.

    Grouped by owning PID rather than by time. Command history entries
    frequently carry no timestamp at all, so a genuinely temporal
    clustering would silently drop most of the evidence -- and a rule
    that quietly ignores its input is worse than one that admits its
    ordering is weak.
    """
    by_pid: dict[int | None, list] = {}
    for obs in context.commands:
        if obs.get("command_line"):
            by_pid.setdefault(obs.get("pid"), []).append(obs)

    for pid in sorted(by_pid, key=lambda p: (p is None, p)):
        group = by_pid[pid]
        matched: dict[str, list] = {}

        for obs in group:
            lowered = str(obs.get("command_line") or "").lower()
            for pattern, label in DISCOVERY_PATTERNS:
                if re.search(pattern, lowered):
                    matched.setdefault(label, []).append(obs)

        if len(matched) < DISCOVERY_THRESHOLD:
            continue

        commands = sorted(matched)
        involved = sorted(
            {o.obs_id for group_obs in matched.values() for o in group_obs}
        )
        process = next(
            (str(o.get("process")) for o in group if o.get("process")), None
        )

        adjustments = [(
            min(0.15, 0.03 * (len(matched) - DISCOVERY_THRESHOLD)),
            f"+{min(0.15, 0.03 * (len(matched) - DISCOVERY_THRESHOLD)):.2f} "
            f"{len(matched)} distinct discovery commands, above the threshold "
            f"of {DISCOVERY_THRESHOLD}",
        )]
        kinds = {str(o.get("source_kind")) for group_obs in matched.values()
                 for o in group_obs}
        if kinds == {"typed_history"}:
            adjustments.append((
                -0.15,
                "-0.15 every command in the cluster comes from carved history "
                "rather than from a launched process",
            ))

        yield RuleHit(
            observation_refs=involved,
            entities={
                "pids": [pid] if isinstance(pid, int) else [],
                "processes": [process] if process else [],
            },
            observation_statement=(
                f"{len(matched)} distinct host-discovery commands are "
                f"associated with PID {pid} ({process}): "
                f"{', '.join(commands)}. Sources: {', '.join(sorted(kinds))}."
            ),
            interpretation=(
                "A cluster of enumeration commands in one process is the "
                "signature of situational-awareness activity -- an operator "
                "establishing where they have landed, what privileges they "
                "hold, and what else is reachable."
            ),
            alternative_explanations=[
                "An administrator or help-desk technician troubleshooting the "
                "machine, who runs exactly these commands for exactly these "
                "reasons.",
                "A logon script, inventory agent or monitoring tool collecting "
                "system information on a schedule.",
                "History entries carved from unallocated memory that were "
                "typed in an earlier, unrelated session.",
            ],
            analyst_action=(
                "Establish who was logged on and whether the account "
                "legitimately performs administration. Look for what followed "
                "the enumeration -- discovery on its own is not an intrusion."
            ),
            confidence_adjustments=adjustments,
        )


RULES = (
    Rule(
        "MEM-C-001", "1.0", "PowerShell invoked with concealment flags",
        "execution", "HIGH", 0.45, obfuscated_powershell,
        ("T1059.001", "T1027"),
        "Encoded, hidden-window, profile-bypassing or download-and-execute "
        "PowerShell.",
    ),
    Rule(
        "MEM-C-002", "1.0", "Signed Windows binary used as a downloader or "
                            "script host",
        "execution", "HIGH", 0.45, lolbin_abuse,
        ("T1218", "T1105"),
        "certutil, bitsadmin, mshta, regsvr32, rundll32 and similar invoked "
        "with transfer or script arguments.",
    ),
    Rule(
        "MEM-C-003", "1.0", "Cluster of host discovery commands",
        "discovery", "MEDIUM", 0.40, discovery_burst,
        ("T1082", "T1087", "T1016"),
        "Three or more distinct enumeration commands under one process.",
    ),
)
