"""
Module and service rules -- MEM-M-001 and MEM-S-001.

MEM-M-001 is the kernel-mode counterpart of MEM-P-001 and inherits its
one critical constraint: absence from ``windows.modules`` counts only
when ``windows.modules`` actually ran. The cross-view field is tri-state
and the rule tests ``is False``, never falsy.

MEM-S-001 is a directory-membership test, and the honest version of it
has to account for path expansion. A service binary recorded as
``%SystemRoot%\\Temp\\x.exe`` is in a temp directory; one recorded as
``%ProgramFiles%\\Vendor\\x.exe`` is not. The extractor expands what it
can and lists what it could not, and this rule declines to judge a path
whose variables are unresolved rather than guessing at it.
"""

from __future__ import annotations

from typing import Iterable

from ..engine import DetectionContext, Rule, RuleHit

#: Directories from which a registered service binary is unusual.
#: Ordered longest-first so the most specific match is reported.
UNUSUAL_SERVICE_DIRECTORIES: tuple[tuple[str, str, float], ...] = (
    ("\\users\\public\\", "the public user profile, world-writable by design",
     0.15),
    ("\\appdata\\local\\temp\\", "a per-user temporary directory", 0.20),
    ("\\appdata\\roaming\\", "a per-user roaming profile directory", 0.10),
    ("\\appdata\\local\\", "a per-user local profile directory", 0.10),
    ("\\windows\\temp\\", "the system temporary directory", 0.20),
    ("\\temp\\", "a temporary directory", 0.15),
    ("\\programdata\\", "a shared writable data directory", 0.05),
    ("\\downloads\\", "a downloads directory", 0.20),
    ("\\recycle", "the recycle bin", 0.30),
)

#: Service binaries that legitimately live outside Program Files.
KNOWN_SYSTEM_SERVICE_HOSTS = frozenset({
    "svchost.exe", "services.exe", "lsass.exe", "spoolsv.exe", "msiexec.exe",
})


# ── MEM-M-001 ─────────────────────────────────────────────────────────


def hidden_kernel_module(context: DetectionContext) -> Iterable[RuleHit]:
    for obs in context.modules:
        if obs.get("scope") != "kernel":
            continue

        cross = obs.get("cross_view") or {}
        # `is False` / `is True`, not truthiness: None means the source
        # did not run, and would otherwise read as "absent".
        if cross.get("modules") is not False or cross.get("modscan") is not True:
            continue

        name = obs.get("name")
        yield RuleHit(
            observation_refs=[obs.obs_id],
            entities={
                "modules": [name] if name else [],
                "files": [obs.get("path")] if obs.get("path") else [],
            },
            observation_statement=(
                f"Kernel module {name!r} at base {obs.get('base')} was returned "
                f"by windows.modscan but not by windows.modules, which ran "
                f"successfully."
            ),
            interpretation=(
                "A driver present in kernel memory but absent from the loaded-"
                "module list. Unlinking a driver from that list hides it from "
                "ordinary enumeration while it continues to execute in kernel "
                "mode -- the rootkit equivalent of a hidden process."
            ),
            alternative_explanations=[
                "A driver that was unloaded before capture, whose pool memory "
                "had not yet been reused. This is common and benign.",
                "A false positive from the pool scanner, which carves by tag "
                "signature and can match on stale or coincidental data.",
                "A legitimate driver loaded by a method that does not register "
                "it in the standard list, which some virtualisation and "
                "anti-cheat products do deliberately.",
            ],
            analyst_action=(
                "Dump the module and identify it. A signed driver from a known "
                "vendor is a different matter from an unidentifiable one. "
                "Kernel-level concealment means the running system can no "
                "longer be trusted to report on itself."
            ),
        )


# ── MEM-S-001 ─────────────────────────────────────────────────────────


def suspicious_service_binary(context: DetectionContext) -> Iterable[RuleHit]:
    for obs in context.services:
        path = obs.get("executable_path_normalised")
        name = str(obs.get("executable_name") or "").lower()

        if not path:
            continue
        if obs.get("path_variables_unresolved"):
            # The path contains a variable this build could not expand, so
            # a directory comparison would be unsound. Declining to judge
            # is the correct behaviour; the extractor already recorded the
            # gap as a limitation.
            continue
        if name in KNOWN_SYSTEM_SERVICE_HOSTS:
            continue

        match = next(
            ((d, why, w) for d, why, w in UNUSUAL_SERVICE_DIRECTORIES
             if d in path),
            None,
        )
        if match is None:
            continue

        directory, why, weight = match
        service = obs.get("name")

        adjustments = [(weight, f"+{weight:.2f} located in {why}")]
        # Volatility renders this as SERVICE_AUTO_START, not "Auto".
        # A startswith() check silently never fires.
        if "auto" in str(obs.get("start_type") or "").lower():
            adjustments.append((
                0.10,
                "+0.10 the service is configured to start automatically, so it "
                "survives reboot without user action",
            ))

        yield RuleHit(
            observation_refs=[obs.obs_id],
            entities={
                "services": [service] if service else [],
                "files": [obs.get("binary_raw")] if obs.get("binary_raw") else [],
                "pids": [obs.get("pid")] if isinstance(obs.get("pid"), int) else [],
            },
            observation_statement=(
                f"Service {service!r} (display name "
                f"{obs.get('display_name')!r}, start type "
                f"{obs.get('start_type')}, state {obs.get('state')}) launches "
                f"{obs.get('binary_raw')!r}. The executable path normalises to "
                f"{path!r}, which is under {directory!r}."
            ),
            interpretation=(
                "A registered service whose binary sits in a user-writable or "
                "temporary directory. Services start before user logon and "
                "commonly run as SYSTEM, which makes them a durable and "
                "privileged persistence mechanism."
            ),
            alternative_explanations=[
                "A legitimate installer that registered a service from a "
                "temporary extraction directory and had not yet moved it.",
                "Portable or per-user software deliberately installed outside "
                "Program Files.",
                "A development or testing build being run from a working "
                "directory.",
            ],
            analyst_action=(
                "Identify and hash the service binary, and establish when the "
                "service was registered. Cross-reference against the registry "
                "hive on disk for the creating account and timestamp."
            ),
            confidence_adjustments=adjustments,
        )


RULES = (
    Rule(
        "MEM-M-001", "1.0", "Kernel module absent from the loaded-module list",
        "rootkit", "CRITICAL", 0.70, hidden_kernel_module,
        ("T1014",),
        "Present in modscan, absent from modules.",
    ),
    Rule(
        "MEM-S-001", "1.0", "Service binary in a user-writable directory",
        "persistence", "HIGH", 0.55, suspicious_service_binary,
        ("T1543.003",),
        "svcscan binary path under Temp, AppData, Public or similar.",
    ),
)
