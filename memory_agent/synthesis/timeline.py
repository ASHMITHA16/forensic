"""
memory_agent.synthesis.timeline
─────────────────────────────────────────────────────────────────────
Reconstruct what can be placed in time, and be explicit about what
cannot.

The honest constraint
─────────────────────
A memory image yields very few real timestamps. Process creation and
exit, socket creation, module load time, and some service records carry
one. The overwhelming majority of artifacts -- injected regions, command
history entries, unlinked modules, carved handles -- carry none at all.

The tempting move is to give everything a plausible time by inheriting
one from a neighbour. That produces a timeline that looks complete and
misleads every consumer downstream, because the correlation agent will
happily interleave an invented memory timestamp with a real MFT
timestamp and report a sequence of events that never happened.

So every event declares its ``precision``:

    exact        a timestamp read from the artifact itself
    approximate  derived from a related artifact, bounded and explained
    relative     no timestamp; ordering inferred, expressed as
                 sequence_hint only, with timestamp_utc null
    unknown      present in the image, not placeable in time at all

``relative`` and ``unknown`` events carry ``timestamp_utc: null``, and
the schema enforces it. An inferred ordering rendered as a time is
exactly the confusion this field exists to prevent.

``sequence_hint`` is a total ordering over every event, timestamped or
not, so a consumer that wants a single sequence has one -- while
``precision`` tells it how much of that sequence is evidence and how
much is inference.
"""

from __future__ import annotations

from typing import Any, Iterable, Sequence

from ..core.rows import iso_to_datetime
from ..core.schema import Finding, IdFactory, Observation, TimelineEvent

#: Confidence attached to an event by how well it is placed. These are
#: about the *placement*, not about whether the artifact is malicious.
PRECISION_CONFIDENCE = {
    "exact": 0.95,
    "approximate": 0.70,
    "relative": 0.40,
    "unknown": 0.20,
}


def _entities(**kwargs: Any) -> dict[str, list[Any]]:
    return {k: v for k, v in kwargs.items() if v}


def _finding_refs(findings: Sequence[Finding], obs_id: str) -> list[str]:
    return sorted(
        f.finding_id for f in findings if obs_id in f.observation_refs
    )


def build_timeline(
    observations: Sequence[Observation],
    findings: Sequence[Finding] = (),
    ids: IdFactory | None = None,
) -> tuple[list[TimelineEvent], dict[str, int]]:
    """
    Build the timeline. Returns ``(events, precision_counts)``.

    The counts go into ``coverage`` so a reader can see at a glance how
    much of the timeline is real: "112 events, 19 exact" is a materially
    different document from "112 events, 112 exact", and the difference
    should not require reading all 112.
    """
    ids = ids or IdFactory()
    staged: list[dict[str, Any]] = []

    for obs in observations:
        staged.extend(_events_for(obs, findings))

    # Order: timestamped events by time, then everything else grouped by
    # the process it belongs to. Sorting on the id last keeps the result
    # stable when two events share a timestamp -- without it, sequence
    # hints would shuffle between runs over identical input.
    def sort_key(event: dict[str, Any]) -> tuple:
        ts = event.get("timestamp_utc")
        dt = iso_to_datetime(ts) if ts else None
        has_time = 0 if dt is not None else 1
        pid_values = event.get("entities", {}).get("pids") or []
        pid = pid_values[0] if pid_values and isinstance(pid_values[0], int) else -1
        return (
            has_time,
            dt.timestamp() if dt is not None else 0.0,
            pid,
            event["artifact_type"],
            event["_primary_obs"],
        )

    staged.sort(key=sort_key)

    events: list[TimelineEvent] = []
    counts: dict[str, int] = {p: 0 for p in PRECISION_CONFIDENCE}

    for index, item in enumerate(staged):
        precision = item["precision"]
        counts[precision] = counts.get(precision, 0) + 1
        events.append(TimelineEvent(
            event_id=ids.event(),
            timestamp_utc=item.get("timestamp_utc"),
            precision=precision,
            sequence_hint=index,
            source_domain="memory",
            artifact_type=item["artifact_type"],
            description=item["description"],
            observation_refs=item["observation_refs"],
            finding_refs=item["finding_refs"],
            entities=item.get("entities", {}),
            confidence=PRECISION_CONFIDENCE[precision],
            precision_basis=item.get("precision_basis"),
        ))

    return events, counts


def _events_for(
    obs: Observation, findings: Sequence[Finding]
) -> Iterable[dict[str, Any]]:
    """Every timeline event derivable from one observation."""
    refs = [obs.obs_id]
    finding_refs = _finding_refs(findings, obs.obs_id)
    pid = obs.get("pid")
    pids = [pid] if isinstance(pid, int) else []

    def base(artifact_type: str, description: str, precision: str,
             timestamp: str | None = None, basis: str | None = None,
             extra_entities: dict[str, Any] | None = None) -> dict[str, Any]:
        entities = _entities(pids=pids, **(extra_entities or {}))
        return {
            "artifact_type": artifact_type,
            "description": description,
            "precision": precision,
            # Enforced here as well as in the schema: a null timestamp is
            # what makes a relative event legible as an inference.
            "timestamp_utc": timestamp if precision in ("exact", "approximate")
            else None,
            "precision_basis": basis,
            "observation_refs": refs,
            "finding_refs": finding_refs,
            "entities": entities,
            "_primary_obs": obs.obs_id,
        }

    if obs.type == "process":
        name = obs.get("name")
        created = obs.get("create_time_utc")
        exited = obs.get("exit_time_utc")

        if created:
            yield base(
                "process_create",
                f"Process {name} (PID {pid}) created by PID {obs.get('ppid')}",
                "exact", created,
                "EPROCESS CreateTime, a kernel-recorded timestamp",
                {"processes": [name] if name else []},
            )
        else:
            yield base(
                "process_present",
                f"Process {name} (PID {pid}) is resident in memory with no "
                f"recoverable creation time",
                "unknown", None,
                "no CreateTime was readable from the structures that were "
                "parsed",
                {"processes": [name] if name else []},
            )

        if exited:
            yield base(
                "process_exit",
                f"Process {name} (PID {pid}) exited",
                "exact", exited,
                "EPROCESS ExitTime, a kernel-recorded timestamp",
                {"processes": [name] if name else []},
            )

    elif obs.type == "network":
        created = obs.get("created_utc")
        description = (
            f"{obs.get('protocol')} socket "
            f"{obs.get('local_address')}:{obs.get('local_port')} -> "
            f"{obs.get('foreign_address')}:{obs.get('foreign_port')} "
            f"(state {obs.get('state')}) owned by PID {pid} "
            f"({obs.get('owner')})"
        )
        entities = {
            "ips": [obs.get("foreign_address")] if obs.get("foreign_address")
            else [],
            "ports": [obs.get("foreign_port")] if obs.get("foreign_port") else [],
            "processes": [obs.get("owner")] if obs.get("owner") else [],
        }
        if created:
            yield base("socket_create", description, "exact", created,
                       "socket creation time recorded in the connection "
                       "structure", entities)
        else:
            yield base("socket_present", description, "unknown", None,
                       "the connection structure carried no creation time",
                       entities)

    elif obs.type == "command":
        kind = obs.get("source_kind")
        text = str(obs.get("command_line") or "")[:200]
        entities = {"processes": [obs.get("process")] if obs.get("process")
                    else []}

        if kind == "launch_parameters":
            # The command line IS the launch, so it shares the process's
            # creation time -- but that time comes from a different
            # artifact, so it is approximate rather than exact.
            yield base(
                "command_launch",
                f"PID {pid} ({obs.get('process')}) launched with: {text}",
                "relative", None,
                "the launch parameters carry no timestamp of their own; the "
                "owning process's creation time is the correct anchor and is "
                "recorded on its own process_create event",
                entities,
            )
        else:
            yield base(
                "command_history" if kind == "typed_history" else "console_output",
                f"Command associated with PID {pid} ({obs.get('process')}) "
                f"from {kind}: {text}",
                "relative", None,
                "carved from a history or screen buffer, which records no time "
                "and can outlive the session that produced it",
                entities,
            )

    elif obs.type == "module":
        load_time = obs.get("load_time_utc")
        scope = obs.get("scope")
        name = obs.get("name")
        entities = {"modules": [name] if name else []}
        description = (
            f"{scope} module {name} mapped at {obs.get('base')}"
            + (f" in PID {pid}" if isinstance(pid, int) else "")
        )
        if load_time:
            yield base("module_load", description, "exact", load_time,
                       "load time recorded in the loader data table entry",
                       entities)
        elif scope == "kernel" or obs.get("peb_lists_complete") is False:
            # Only emit an untimed module event where the module is
            # interesting. One event per loaded DLL on a busy machine would
            # be tens of thousands of entries that place nothing in time.
            yield base("module_present", description, "unknown", None,
                       "no load time was recoverable for this module",
                       entities)

    elif obs.type == "injection":
        if obs.get("kind") == "image_path_discrepancy":
            yield base(
                "image_mismatch",
                f"PID {pid} ({obs.get('process')}) maps "
                f"{obs.get('vad_backing_path')} at its image base while "
                f"recording {obs.get('eprocess_image_path')}",
                "relative", None,
                "a mapping discrepancy has no timestamp; it is ordered "
                "relative to the owning process's creation",
                {"processes": [obs.get("process")] if obs.get("process") else []},
            )
        else:
            yield base(
                "memory_region",
                f"Private {obs.get('protection')} region at "
                f"{obs.get('region_start')} in PID {pid} "
                f"({obs.get('process')})",
                "relative", None,
                "VAD structures do not record when a region was allocated; "
                "ordering is inferred from the owning process only",
                {"processes": [obs.get("process")] if obs.get("process") else []},
            )

    elif obs.type == "service":
        name = obs.get("name")
        yield base(
            "service_registered",
            f"Service {name} ({obs.get('state')}, {obs.get('start_type')}) "
            f"launches {obs.get('binary_raw')}",
            "unknown", None,
            "svcscan recovers the service record but not when it was created; "
            "the registry hive on disk carries that timestamp",
            {"services": [name] if name else []},
        )


def timeline_summary(counts: dict[str, int]) -> str:
    """One sentence a reader can act on, for the limitations block."""
    total = sum(counts.values())
    exact = counts.get("exact", 0)
    if total == 0:
        return "No timeline events could be constructed."
    share = 100.0 * exact / total
    return (
        f"{total} timeline events, of which {exact} ({share:.0f}%) carry a "
        f"timestamp read from the artifact itself. The remainder are ordered "
        f"by inference and carry no timestamp: do not treat their "
        f"sequence_hint as a time when merging with disk or network "
        f"timelines."
    )
