"""
Process rules -- MEM-P-001 through MEM-P-006.

Every rule in this file has the same shape: read facts off process
observations, decide nothing that is not stated in the rule's own
threshold, and hand back a hit whose ``observation_statement`` a person
could verify against the raw plugin output in under a minute.

The recurring hazard in this family is the tri-state cross-view field.
``cross_view["pslist"]`` is ``False`` only when pslist *ran* and did not
return the process; it is ``None`` when pslist did not run. Treating
``None`` as ``False`` would report a hidden process on every image where
pslist timed out. Each rule below tests for ``is False`` explicitly, and
that is not stylistic.
"""

from __future__ import annotations

from typing import Iterable

from ..engine import DetectionContext, Rule, RuleHit

#: Parents a Windows system process is normally created by. Sourced from
#: documented Windows boot behaviour; deliberately conservative, since a
#: false "masquerade" on a core system process wastes an analyst's time
#: on the most heavily-audited processes on the machine.
CANONICAL_PARENTS: dict[str, tuple[str, ...]] = {
    "smss.exe": ("system",),
    "csrss.exe": ("smss.exe",),
    "wininit.exe": ("smss.exe",),
    "winlogon.exe": ("smss.exe",),
    "services.exe": ("wininit.exe",),
    "lsass.exe": ("wininit.exe",),
    "lsaiso.exe": ("wininit.exe",),
    "svchost.exe": ("services.exe",),
    "spoolsv.exe": ("services.exe",),
    "taskhostw.exe": ("svchost.exe",),
    "explorer.exe": ("userinit.exe", "winlogon.exe"),
}

#: Directory each system binary is expected to live in, lower-cased.
CANONICAL_DIRECTORIES: dict[str, tuple[str, ...]] = {
    "smss.exe": ("c:\\windows\\system32",),
    "csrss.exe": ("c:\\windows\\system32",),
    "wininit.exe": ("c:\\windows\\system32",),
    "winlogon.exe": ("c:\\windows\\system32",),
    "services.exe": ("c:\\windows\\system32",),
    "lsass.exe": ("c:\\windows\\system32",),
    "svchost.exe": ("c:\\windows\\system32",),
    "spoolsv.exe": ("c:\\windows\\system32",),
    "explorer.exe": ("c:\\windows",),
    "taskhostw.exe": ("c:\\windows\\system32",),
}

#: Processes of which exactly one should exist on a running system.
#: csrss.exe is deliberately absent: two instances is normal (one per
#: session), and including it would fire on every healthy image.
SINGLETON_PROCESSES = ("wininit.exe", "services.exe", "lsass.exe", "lsaiso.exe")


def _name(obs) -> str:
    return str(obs.get("name") or "").lower()


def _directory(path: str | None) -> str | None:
    if not path:
        return None
    normalised = path.strip().strip('"').replace("/", "\\").lower()
    if "\\" not in normalised:
        return None
    return normalised.rsplit("\\", 1)[0]


# ── MEM-P-001 ─────────────────────────────────────────────────────────


def hidden_process(context: DetectionContext) -> Iterable[RuleHit]:
    for obs in context.processes:
        cross = obs.get("cross_view") or {}
        in_pslist = cross.get("pslist")
        in_psscan = cross.get("psscan")
        psxview = obs.get("psxview_flags") or {}

        # The signal requires pslist to have actually run and not returned
        # it. `is False` is load-bearing: None means pslist did not run.
        if in_pslist is not False:
            continue
        if in_psscan is not True and psxview.get("psscan") is not True:
            continue

        sources_seeing_it = sorted(
            k for k, v in cross.items() if v is True
        ) or sorted(k for k, v in psxview.items() if v is True)

        pid = obs.get("pid")
        exited = obs.get("exit_time_utc")

        adjustments = []
        if exited:
            # A terminated process is absent from the active list for the
            # most ordinary reason there is. The rule still fires -- the
            # carved record is real -- but at much lower confidence.
            adjustments.append((
                -0.35,
                "-0.35 the process has a recorded exit time, so absence from "
                "the active process list is expected rather than anomalous",
            ))
        if psxview.get("thrdproc") is True or psxview.get("csrss") is True:
            adjustments.append((
                0.08,
                "+0.08 independently visible to a thread-based or CSRSS-based "
                "enumeration source",
            ))

        yield RuleHit(
            observation_refs=[obs.obs_id],
            entities={
                "pids": [pid] if isinstance(pid, int) else [],
                "processes": [obs.get("name")] if obs.get("name") else [],
            },
            observation_statement=(
                f"Process {obs.get('name')!r} (PID {pid}) was returned by "
                f"{', '.join(sources_seeing_it) or 'a pool scan'} but was not "
                f"returned by windows.pslist, which ran successfully."
                + (f" The process has a recorded exit time of {exited}."
                   if exited else " The process has no recorded exit time.")
            ),
            interpretation=(
                "Consistent with a process unlinked from the active process "
                "list -- the classic direct kernel object manipulation (DKOM) "
                "technique for hiding a running process from ordinary "
                "enumeration."
                if not exited else
                "Consistent with a process that terminated before capture and "
                "whose pool memory had not yet been reused. This is the "
                "ordinary explanation for the same evidence."
            ),
            alternative_explanations=[
                "The process exited before acquisition; its EPROCESS structure "
                "survives in unallocated pool memory until overwritten.",
                "A smeared or inconsistent acquisition: on a live system the "
                "process list can change while the image is being written, so "
                "the two enumerations describe different instants.",
                "A false positive from the pool scanner, which carves "
                "structures by tag signature and can match on stale or "
                "coincidental data.",
            ],
            analyst_action=(
                "Compare the PID against the thread and handle views, and dump "
                "the process image for static analysis. If the process is live "
                "and unlinked, treat the kernel as compromised and preserve the "
                "image before further interaction."
            ),
            confidence_adjustments=adjustments,
            first_seen_utc=obs.get("create_time_utc"),
            severity_override="MEDIUM" if exited else None,
        )


# ── MEM-P-002 ─────────────────────────────────────────────────────────


def exited_process_holding_sockets(context: DetectionContext) -> Iterable[RuleHit]:
    for obs in context.processes:
        exit_time = obs.get("exit_time_utc")
        pid = obs.get("pid")
        if not exit_time or not isinstance(pid, int):
            continue

        sockets = [
            n for n in context.network_by_pid.get(pid, [])
            if str(n.get("state") or "").upper() in {"ESTABLISHED", "LISTENING"}
        ]
        if not sockets:
            continue

        # PID reuse is the obvious confound and it is common on a
        # long-running system, so it is checked rather than assumed away.
        same_pid_live = [
            p for p in context.process_by_pid.get(pid, [])
            if not p.get("exit_time_utc")
        ]

        adjustments = []
        if same_pid_live:
            adjustments.append((
                -0.30,
                f"-0.30 a live process also holds PID {pid}, so the sockets may "
                f"belong to it rather than to the exited process",
            ))

        yield RuleHit(
            observation_refs=[obs.obs_id] + [s.obs_id for s in sockets],
            entities={
                "pids": [pid],
                "processes": [obs.get("name")] if obs.get("name") else [],
                "ips": [s.get("foreign_address") for s in sockets
                        if s.get("foreign_address")],
            },
            observation_statement=(
                f"Process {obs.get('name')!r} (PID {pid}) has an exit time of "
                f"{exit_time}, and {len(sockets)} socket object(s) attributed to "
                f"PID {pid} are in state "
                f"{', '.join(sorted({str(s.get('state')) for s in sockets}))}."
            ),
            interpretation=(
                "The network structures outlived the process that owned them. "
                "This is what a short-lived tool that connected out and then "
                "terminated leaves behind, and it is often the only surviving "
                "record of a completed transfer."
            ),
            alternative_explanations=[
                f"PID {pid} was reused by a later process, and the sockets "
                f"belong to that one instead.",
                "The socket structures are stale pool memory whose state field "
                "no longer reflects reality; a carved connection has no "
                "guarantee of currency.",
                "Normal teardown ordering during a smeared acquisition.",
            ],
            analyst_action=(
                "Compare the socket creation times against the process create "
                "and exit times. Where they fall inside the process's lifetime, "
                "treat the foreign addresses as attributable to it."
            ),
            confidence_adjustments=adjustments,
            first_seen_utc=obs.get("create_time_utc"),
        )


# ── MEM-P-003 ─────────────────────────────────────────────────────────


def masqueraded_system_process(context: DetectionContext) -> Iterable[RuleHit]:
    for obs in context.processes:
        name = _name(obs)
        expected = CANONICAL_PARENTS.get(name)
        ppid = obs.get("ppid")
        if not expected or not isinstance(ppid, int):
            continue

        parent_name = (context.process_name(ppid) or "").lower()
        if not parent_name:
            # The parent is not resident. That is MEM-P-005's territory,
            # not this rule's -- an unknown parent is not a wrong parent.
            continue
        if parent_name in expected:
            continue

        pid = obs.get("pid")
        yield RuleHit(
            observation_refs=[obs.obs_id] + [
                p.obs_id for p in context.process_by_pid.get(ppid, [])
            ],
            entities={
                "pids": [pid, ppid] if isinstance(pid, int) else [ppid],
                "processes": [obs.get("name"), context.process_name(ppid)],
            },
            observation_statement=(
                f"Process {obs.get('name')!r} (PID {pid}) has parent PID {ppid}, "
                f"which is {context.process_name(ppid)!r}. On Windows this "
                f"process is normally created by "
                f"{' or '.join(repr(e) for e in expected)}."
            ),
            interpretation=(
                "Consistent with a process named after a system binary but "
                "launched by something else -- a common masquerading technique, "
                "since analysts scanning a process list recognise the name and "
                "move on."
            ),
            alternative_explanations=[
                "The parent process exited and its PID was reused by an "
                "unrelated process, so the parent name shown is not the actual "
                "creator. Windows does not update PPID when a parent exits.",
                "A legitimate third-party tool, installer, or management agent "
                "that launches system binaries directly.",
                "A virtualised, containerised or terminal-services environment "
                "with a non-standard process hierarchy.",
            ],
            analyst_action=(
                "Check whether the parent's creation time precedes this "
                "process's creation time. If the parent was created afterwards, "
                "the PPID is stale and this finding should be discounted."
            ),
            first_seen_utc=obs.get("create_time_utc"),
        )


# ── MEM-P-004 ─────────────────────────────────────────────────────────


def system_binary_wrong_path(context: DetectionContext) -> Iterable[RuleHit]:
    for obs in context.processes:
        name = _name(obs)
        expected = CANONICAL_DIRECTORIES.get(name)
        path = obs.get("path")
        if not expected or not path:
            continue

        directory = _directory(str(path))
        if directory is None:
            continue
        if any(directory == e or directory.startswith(e + "\\") for e in expected):
            continue

        # SysWOW64 is the 32-bit system directory and is a legitimate home
        # for a system binary in a WOW64 process. Excluding it here rather
        # than in the alternatives list, because firing on it would be
        # simply wrong rather than merely arguable.
        if "syswow64" in directory and any("system32" in e for e in expected):
            continue

        pid = obs.get("pid")
        yield RuleHit(
            observation_refs=[obs.obs_id],
            entities={
                "pids": [pid] if isinstance(pid, int) else [],
                "processes": [obs.get("name")] if obs.get("name") else [],
                "files": [path],
            },
            observation_statement=(
                f"Process {obs.get('name')!r} (PID {pid}) maps an image at "
                f"{path!r}. The expected directory for this binary is "
                f"{' or '.join(expected)}. Path basis: "
                f"{obs.get('image_path_basis') or 'not recorded'}."
            ),
            interpretation=(
                "A binary carrying the name of a Windows system process is "
                "running from outside the system directory. Placing a "
                "differently-located executable under a trusted name is a "
                "long-standing and still-effective evasion."
            ),
            alternative_explanations=[
                "The path was recovered from the loaded-module list rather than "
                "from the EPROCESS record and may describe a mapped module "
                "rather than the executed image.",
                "A legitimate application coincidentally shares the name of a "
                "Windows binary.",
                "A non-standard Windows installation directory, or a mounted "
                "image analysed under a different drive letter.",
            ],
            analyst_action=(
                "Dump the executable and compare its hash against the Microsoft "
                "catalogue for the build recorded in the environment block."
            ),
            first_seen_utc=obs.get("create_time_utc"),
        )


# ── MEM-P-005 ─────────────────────────────────────────────────────────


def orphaned_process(context: DetectionContext) -> Iterable[RuleHit]:
    resident = set(context.process_by_pid)
    if not resident:
        return

    for obs in context.processes:
        ppid = obs.get("ppid")
        pid = obs.get("pid")
        if not isinstance(ppid, int) or ppid in resident or ppid == 0:
            continue
        if obs.get("exit_time_utc"):
            continue

        # explorer.exe is orphaned by design on every healthy desktop:
        # userinit.exe launches it and immediately exits. Reporting it
        # would train the analyst to ignore this rule.
        if _name(obs) == "explorer.exe":
            continue

        yield RuleHit(
            observation_refs=[obs.obs_id],
            entities={
                "pids": [pid] if isinstance(pid, int) else [],
                "processes": [obs.get("name")] if obs.get("name") else [],
            },
            observation_statement=(
                f"Process {obs.get('name')!r} (PID {pid}) records parent PID "
                f"{ppid}. No process with PID {ppid} was found by any "
                f"enumeration source, and this process has no exit time."
            ),
            interpretation=(
                "The creating process is no longer resident. This is what "
                "remains after a launcher, dropper or installer has exited, and "
                "it is also what an ordinary short-lived parent leaves behind."
            ),
            alternative_explanations=[
                "The parent exited normally before capture -- extremely common "
                "and entirely benign on its own.",
                "The parent was itself hidden or unlinked and so was not "
                "enumerated.",
                "The process was created by a parent in a different session or "
                "container namespace not covered by the plugins that ran.",
            ],
            analyst_action=(
                "Treat as context rather than as a finding in isolation. It is "
                "worth attention only where it coincides with another finding "
                "on the same PID."
            ),
            first_seen_utc=obs.get("create_time_utc"),
        )


# ── MEM-P-006 ─────────────────────────────────────────────────────────


def duplicated_singleton(context: DetectionContext) -> Iterable[RuleHit]:
    by_name: dict[str, list] = {}
    for obs in context.live_processes():
        name = _name(obs)
        if name in SINGLETON_PROCESSES:
            by_name.setdefault(name, []).append(obs)

    for name in sorted(by_name):
        instances = by_name[name]
        if len(instances) < 2:
            continue

        pids = sorted(
            o.get("pid") for o in instances if isinstance(o.get("pid"), int)
        )
        sessions = {o.get("session_id") for o in instances}

        adjustments = []
        if len(sessions) > 1:
            adjustments.append((
                -0.15,
                "-0.15 the instances are in different sessions, where some "
                "duplication is architecturally possible",
            ))

        yield RuleHit(
            observation_refs=[o.obs_id for o in instances],
            entities={"pids": pids, "processes": [name]},
            observation_statement=(
                f"{len(instances)} processes named {name!r} have no recorded "
                f"exit time. Their PIDs are "
                f"{', '.join(str(p) for p in pids)}. Windows runs exactly one "
                f"instance of this process on a healthy system."
            ),
            interpretation=(
                f"A second live {name} is consistent with a process created to "
                f"impersonate a core system component, which analysts and some "
                f"tooling identify by name alone."
            ),
            alternative_explanations=[
                "One instance terminated before capture without its exit time "
                "being recorded in the structures that were read.",
                "A pool scanner returned a stale carved copy of the same "
                "process, which the cross-source merge did not unify because "
                "the two records disagree on creation time.",
                "A virtualised or nested environment (containers, WSL, "
                "sandboxes) legitimately running its own instance.",
            ],
            analyst_action=(
                "Compare the image path, parent, session and creation time of "
                "each instance. The impostor is generally the one whose parent "
                "or path departs from the documented pattern."
            ),
            confidence_adjustments=adjustments,
        )


RULES = (
    Rule(
        "MEM-P-001", "1.0", "Process hidden from the active process list",
        "process_hiding", "CRITICAL", 0.70, hidden_process,
        ("T1014",),
        "Present in a pool scan or cross-view source, absent from pslist.",
    ),
    Rule(
        "MEM-P-002", "1.0", "Exited process still holding network sockets",
        "network", "MEDIUM", 0.55, exited_process_holding_sockets,
        ("T1041",),
        "A process with an exit time owns sockets in an active state.",
    ),
    Rule(
        "MEM-P-003", "1.0", "System process with a non-canonical parent",
        "masquerading", "HIGH", 0.60, masqueraded_system_process,
        ("T1036.005",),
        "A named Windows system process was created by an unexpected parent.",
    ),
    Rule(
        "MEM-P-004", "1.0", "System binary running from an unexpected directory",
        "masquerading", "HIGH", 0.65, system_binary_wrong_path,
        ("T1036.005",),
        "A system binary's image path is outside its expected directory.",
    ),
    Rule(
        "MEM-P-005", "1.0", "Process with no resident parent",
        "process_anomaly", "INFO", 0.25, orphaned_process,
        (),
        "PPID does not correspond to any enumerated process.",
    ),
    Rule(
        "MEM-P-006", "1.0", "Multiple instances of a singleton system process",
        "masquerading", "HIGH", 0.65, duplicated_singleton,
        ("T1036.005",),
        "More than one live instance of a process Windows runs once.",
    ),
)
