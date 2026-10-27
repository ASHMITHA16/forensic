"""
Injection rules -- MEM-I-001 through MEM-I-003.

This family carries the highest false-positive risk in the pack, and the
rules are written to say so rather than to hide it.

Every modern browser, every .NET application and every JVM allocates
private, writable, executable memory as a matter of routine: that is what
a JIT compiler is. A rule that fires on "private RWX region" alone will
produce a HIGH-severity finding for Chrome on a perfectly clean machine.
Do that twice and the analyst stops reading the tool's output, which is a
worse outcome than not having the rule.

So MEM-I-001 separates the signal into components and prices them
separately: private-and-executable is the weak base, writable-and-
executable adds to it, and a PE header at the region's start adds most.
The JIT explanation is in ``alternative_explanations`` on every hit, and
a known JIT host process lowers the score explicitly rather than being
silently exempted -- an analyst can see the adjustment and disagree with
it.
"""

from __future__ import annotations

from typing import Iterable

from ..engine import DetectionContext, Rule, RuleHit

#: Processes that legitimately allocate executable private memory as
#: part of normal operation. Not an allowlist -- findings still fire --
#: but the confidence adjustment is applied and stated.
JIT_HOST_PROCESSES = frozenset({
    "chrome.exe", "msedge.exe", "firefox.exe", "opera.exe", "brave.exe",
    "iexplore.exe", "java.exe", "javaw.exe", "javaws.exe",
    "devenv.exe", "powershell.exe", "powershell_ise.exe", "pwsh.exe",
    "w3wp.exe", "node.exe", "python.exe", "dotnet.exe", "mongod.exe",
    "code.exe", "teams.exe", "slack.exe", "discord.exe",
})

#: The process's own executable is absent from the InInit list by
#: design. Firing MEM-I-002 on it would produce one finding per process
#: on every image.
def _is_own_image(module) -> bool:
    name = str(module.get("name") or "").lower()
    process = str(module.get("process") or "").lower()
    return bool(name) and name == process


#: Files mapped as data, never handed to the loader, so they appear in no
#: PEB list by design: resource (.mui), WinRT metadata, NLS tables, fonts.
#: A path with no extension or an unknown one is still evaluated.
DATA_MAPPING_EXTENSIONS = frozenset({
    ".mui", ".winmd", ".nls", ".dat", ".ttf", ".ttc", ".fon", ".otf", ".tlb",
})


def _is_data_mapping(module) -> bool:
    path = str(module.get("mapped_path") or "").lower()
    return any(path.endswith(ext) for ext in DATA_MAPPING_EXTENSIONS)


#: Directories only TrustedInstaller can write, holding signed OS images.
PROTECTED_SYSTEM_DIRECTORIES = (
    "\\windows\\system32\\", "\\windows\\syswow64\\", "\\windows\\winsxs\\",
)


def _readable_mapped_path(module) -> str | None:
    """
    The mapped path, or None when it is missing or unreadable.

    When the FILE_OBJECT name is not resident, Vol3 decodes whatever bytes
    are there as UTF-16 and returns a "path" of CJK noise with no
    separator. That is absence of data, not a file name.
    """
    path = module.get("mapped_path")
    if not isinstance(path, str) or "\\" not in path or not path.isprintable():
        return None
    return path


# ── MEM-I-001 ─────────────────────────────────────────────────────────


def code_in_private_executable_memory(
    context: DetectionContext,
) -> Iterable[RuleHit]:
    for obs in context.injections:
        if obs.get("kind") == "image_path_discrepancy":
            continue

        executable = obs.get("executable")
        private = obs.get("private_memory")
        if executable is not True or private is not True:
            continue

        writable = obs.get("writable_and_executable") is True
        mz = obs.get("starts_with_mz")
        pid = obs.get("pid")
        process = str(obs.get("process") or "")

        adjustments = []
        if writable:
            adjustments.append((
                0.15,
                "+0.15 the region is simultaneously writable and executable "
                "(PAGE_EXECUTE_READWRITE class), which ordinary loaded code "
                "never is",
            ))
        if mz is True:
            adjustments.append((
                0.20,
                "+0.20 the region's first two bytes are 0x4D 0x5A, a DOS MZ "
                "header, indicating a complete PE image mapped into anonymous "
                "memory rather than loaded from disk",
            ))
        elif mz is None:
            adjustments.append((
                -0.10,
                "-0.10 the region's leading bytes could not be read, so no "
                "PE-header check was possible",
            ))

        if process.lower() in JIT_HOST_PROCESSES:
            adjustments.append((
                -0.25,
                f"-0.25 {process} is a known just-in-time compilation host, "
                f"which allocates private executable memory during normal "
                f"operation",
            ))

        yield RuleHit(
            observation_refs=[obs.obs_id] + [
                p.obs_id for p in context.process_by_pid.get(pid, [])
                if isinstance(pid, int)
            ],
            entities={
                "pids": [pid] if isinstance(pid, int) else [],
                "processes": [process] if process else [],
            },
            observation_statement=(
                f"The memory region at {obs.get('region_start')} in PID {pid} "
                f"({process}) is private, is marked {obs.get('protection')}, "
                f"and is {obs.get('region_size_bytes')} bytes."
                + (f" Its first bytes are {obs.get('leading_bytes_hex')}."
                   if obs.get("leading_bytes_hex") else
                   " Its leading bytes could not be read.")
                + (" No file backs this region."
                   if not obs.get("backing_file") else
                   f" It is backed by {obs.get('backing_file')!r}.")
            ),
            interpretation=(
                "Consistent with code placed into a running process's address "
                "space at runtime -- reflective PE loading, shellcode "
                "injection, or an unpacked payload writing itself into memory "
                "it allocated."
            ),
            alternative_explanations=[
                "Just-in-time compilation. .NET, JavaScript and JVM engines "
                "allocate exactly this kind of region during normal execution, "
                "and this is by a wide margin the most common cause.",
                "A legitimate packed or self-extracting application unpacking "
                "itself into memory it allocated.",
                "A software protection or anti-tamper layer, which deliberately "
                "resembles injection.",
                "An empty or uninitialised region whose leading bytes "
                "coincidentally resemble a header.",
            ],
            analyst_action=(
                "Dump the region and examine it statically. A genuine PE with "
                "coherent imports settles the question; JIT output does not "
                "look like a PE beyond the first bytes."
            ),
            confidence_adjustments=adjustments,
            severity_override=(
                "HIGH" if (writable and mz is True) else "MEDIUM"
            ),
        )


# ── MEM-I-002 ─────────────────────────────────────────────────────────


def peb_unlinked_module(context: DetectionContext) -> Iterable[RuleHit]:
    user_modules = [o for o in context.modules if o.get("scope") == "user"]

    # A live process always has its own image and ntdll in InLoadOrder, and
    # no rootkit can unlink every module and keep running. A process with
    # no module in that list had its PEB loader data paged out of the
    # image: every module reads as "absent", which says nothing about hiding.
    readable_pids = {
        o.get("pid") for o in user_modules
        if (o.get("peb_lists") or {}).get("in_load") is True
    }
    unreadable = sorted(
        {(o.get("pid"), str(o.get("process") or "?")) for o in user_modules
         if o.get("pid") not in readable_pids},
        key=lambda item: (item[0] is None, item[0] or 0),
    )
    if unreadable:
        context.rule_notes.append(
            f"MEM-I-002 was not evaluated for {len(unreadable)} process(es) whose "
            f"PEB loader lists could not be read from the image (no module in "
            f"InLoadOrder, typically because the pages were not resident): "
            + ", ".join(f"{name} (PID {pid})" for pid, name in unreadable[:15])
            + (", ..." if len(unreadable) > 15 else "")
            + ". Unlinked modules in these processes would not be detected."
        )

    for obs in user_modules:
        if obs.get("pid") not in readable_pids:
            continue

        lists = obs.get("peb_lists") or {}
        values = {k: v for k, v in lists.items() if v is not None}
        if len(values) < 3:
            # Fewer than three lists read means the comparison the rule
            # depends on was not available for this module.
            continue
        if all(values.values()):
            continue
        if _is_own_image(obs) or _is_data_mapping(obs):
            continue

        missing = sorted(k for k, v in values.items() if v is False)
        present = sorted(k for k, v in values.items() if v is True)
        pid = obs.get("pid")
        mapped_path = _readable_mapped_path(obs)
        in_system_dir = mapped_path is not None and any(
            d in mapped_path.lower() for d in PROTECTED_SYSTEM_DIRECTORIES
        )

        adjustments = []
        severity = None
        if len(missing) == 1 and "in_init" in missing:
            adjustments.append((
                -0.25,
                "-0.25 only the InInit list is missing this module, which "
                "happens legitimately for modules the loader has mapped but "
                "not yet initialised",
            ))
            severity = "LOW"
        if not present:
            adjustments.append((
                0.10,
                "+0.10 the module is absent from every PEB list while remaining "
                "mapped and readable",
            ))
        if in_system_dir:
            adjustments.append((
                -0.20,
                "-0.20 the image is backed by a file in a TrustedInstaller-owned "
                "system directory; a loader-list walk cut short by a non-resident "
                "page leaves exactly this pattern for signed OS DLLs",
            ))
            severity = severity or "MEDIUM"
        elif mapped_path is None and not present:
            adjustments.append((
                0.10,
                "+0.10 no readable file backs this image mapping, so the code "
                "cannot be attributed to anything on disk",
            ))

        yield RuleHit(
            observation_refs=[obs.obs_id],
            entities={
                "pids": [pid] if isinstance(pid, int) else [],
                "processes": [obs.get("process")] if obs.get("process") else [],
                "files": [obs.get("path")] if obs.get("path") else [],
            },
            observation_statement=(
                f"The module mapped at {obs.get('base')} in PID {pid} "
                f"({obs.get('process')}) is present in PEB list(s) "
                f"{', '.join(present) or 'none'} and absent from "
                f"{', '.join(missing)}. Its mapped path is "
                + (mapped_path if mapped_path else
                   "unreadable (not resident in the image)"
                   if obs.get("mapped_path") else "not recorded")
                + "."
            ),
            interpretation=(
                "A module mapped into the process but missing from one or more "
                "loader lists. Unlinking from those lists hides a DLL from "
                "ordinary module enumeration while it continues to execute."
            ),
            alternative_explanations=[
                "Manual mapping by a legitimate loader, packer or DRM system, "
                "which produces the same list state without malicious intent.",
                "A module mapped as data rather than as an image -- a mapped "
                "resource file appears in no loader list by design.",
                "A partially-completed load captured mid-flight, where the "
                "loader had not yet linked the module into every list.",
                "A loader-list node that was paged out when the image was "
                "taken, which breaks the walk and makes every later module "
                "in that list read as absent.",
            ],
            analyst_action=(
                "Dump the region at the recorded base address and identify it. "
                "A recognisable signed system DLL that is merely unlinked "
                "raises different questions than an unidentifiable image."
            ),
            confidence_adjustments=adjustments,
            severity_override=severity,
        )


# ── MEM-I-003 ─────────────────────────────────────────────────────────


def process_hollowing_indicator(context: DetectionContext) -> Iterable[RuleHit]:
    for obs in context.injections:
        if obs.get("kind") != "image_path_discrepancy":
            continue
        if obs.get("paths_agree") is not False:
            continue

        pid = obs.get("pid")
        yield RuleHit(
            observation_refs=[obs.obs_id] + [
                p.obs_id for p in context.process_by_pid.get(pid, [])
                if isinstance(pid, int)
            ],
            entities={
                "pids": [pid] if isinstance(pid, int) else [],
                "processes": [obs.get("process")] if obs.get("process") else [],
                "files": [p for p in (obs.get("eprocess_image_path"),
                                      obs.get("vad_backing_path")) if p],
            },
            observation_statement=(
                f"PID {pid} ({obs.get('process')}) records image path "
                f"{obs.get('eprocess_image_path')!r} in its process structure, "
                f"while the memory mapped at its image base is backed by "
                f"{obs.get('vad_backing_path')!r}."
            ),
            interpretation=(
                "The executable a process claims to be running and the "
                "executable actually mapped at its base address are different "
                "files. This is the defining signature of process hollowing: a "
                "legitimate process is created suspended, its image is "
                "unmapped, and a different image is written in its place."
            ),
            alternative_explanations=[
                "A legitimate self-updating application that re-maps its own "
                "image after patching itself on disk.",
                "Path rendering differences between the two sources -- a "
                "device path against a DOS path, or a junction resolved on one "
                "side only.",
                "A process whose backing file was deleted or replaced on disk "
                "after it started, leaving the mapping to describe the "
                "replacement.",
            ],
            analyst_action=(
                "Dump the mapped image and compare it against the file at the "
                "recorded EPROCESS path. A hollowed process yields two "
                "genuinely different executables."
            ),
        )


RULES = (
    Rule(
        "MEM-I-001", "1.0", "Executable code in private memory",
        "code_injection", "MEDIUM", 0.45, code_in_private_executable_memory,
        ("T1055", "T1055.002"),
        "A private, committed, executable region -- scored on writability "
        "and the presence of a PE header.",
    ),
    Rule(
        "MEM-I-002", "1.0", "Module absent from one or more PEB loader lists",
        "code_injection", "HIGH", 0.60, peb_unlinked_module,
        ("T1055.001", "T1574"),
        "InLoad/InInit/InMem disagreement for a mapped module.",
    ),
    Rule(
        "MEM-I-003", "1.0", "Process image does not match its mapped executable",
        "code_injection", "CRITICAL", 0.75, process_hollowing_indicator,
        ("T1055.012",),
        "EPROCESS image path differs from the VAD backing the image base.",
    ),
)
