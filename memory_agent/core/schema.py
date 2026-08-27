"""
memory_agent.core.schema
─────────────────────────────────────────────────────────────────────
The output contract.

This module is the agreement between this agent and the correlation
agent downstream. Everything else in the package is an implementation
detail that can be rewritten; this is the part another team depends on.

Validation is hand-written rather than delegated to Pydantic, on purpose.
The package has zero third-party dependencies, so it runs on a bare
Python install, in a locked-down evidence-handling environment, and in a
grader's virtualenv, without a wheel needing to resolve. The cost is the
explicit checks below; the benefit is that "does it run here?" is never
a question.

Two rules are enforced that a type checker would not catch, and both
exist because of what this tool is for:

1. **An observation may not express suspicion.** Observation records
   carry facts and provenance. The moment an extractor is allowed to
   write ``"suspicious": true``, the observation/interpretation boundary
   is gone and every downstream consumer inherits an unattributable
   judgement. Validation rejects observations carrying verdict fields.

2. **A finding must offer at least one alternative explanation.** An
   empty ``alternative_explanations`` list is a schema violation, not a
   stylistic lapse. The field exists so the downstream LLM cannot treat a
   rule hit as settled fact, and a rule author who cannot think of a
   benign cause has not finished thinking about the rule.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any, Iterable, Mapping

from .errors import SchemaValidationError

SCHEMA_VERSION = "1.0.0"
RULE_PACK_VERSION = "v1.0"

#: Ceiling on any confidence value this agent emits. The agent reports
#: memory artifacts; it does not have access to the disk, the network
#: capture or the user, and certainty is not available from one domain.
MAX_CONFIDENCE = 0.95

SEVERITIES = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")
STATUSES = ("COMPLETE", "PARTIAL", "INVALID")
PRECISIONS = ("exact", "approximate", "relative", "unknown")

OBSERVATION_TYPES = (
    "process", "network", "command", "module", "injection", "service",
)

#: obs_id prefixes, one per type. Stable: they appear in findings.
_OBS_PREFIX = {
    "process": "PROC",
    "network": "NET",
    "command": "CMD",
    "module": "MOD",
    "injection": "INJ",
    "service": "SVC",
}

IOC_TYPES = (
    "ipv4", "ipv6", "domain", "url", "filepath", "filename",
    "sha256", "md5", "mutex", "registry_key", "port", "process_name",
)

#: Field names an observation must never carry. Enforced, not advised.
FORBIDDEN_OBSERVATION_FIELDS = frozenset({
    "suspicious", "malicious", "is_malware", "verdict", "threat",
    "threat_level", "risk", "risk_score", "severity", "confidence",
    "interpretation", "conclusion",
})

_OBS_ID_RE = re.compile(r"^OBS-(PROC|NET|CMD|MOD|INJ|SVC)-\d{4,}$")
_FINDING_ID_RE = re.compile(r"^FND-\d{4,}$")
_RULE_ID_RE = re.compile(r"^MEM-[A-Z]-\d{3}$")
_EVENT_ID_RE = re.compile(r"^TL-\d{4,}$")
_IOC_ID_RE = re.compile(r"^IOC-\d{4,}$")
_ISO_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$"
)


# ── identifier allocation ─────────────────────────────────────────────


class IdFactory:
    """
    Sequential, zero-padded identifiers.

    Deterministic by construction: ids depend only on the order in which
    records are created, and extractors create records in a sorted order.
    Two runs over the same input therefore produce the same ids, which is
    what makes the envelopes diffable.
    """

    def __init__(self, width: int = 4) -> None:
        self._counters: dict[str, int] = {}
        self._width = width

    def next(self, kind: str) -> str:
        n = self._counters.get(kind, 0)
        self._counters[kind] = n + 1
        return f"{n:0{self._width}d}"

    def observation(self, obs_type: str) -> str:
        prefix = _OBS_PREFIX.get(obs_type)
        if prefix is None:
            raise SchemaValidationError(
                f"Unknown observation type {obs_type!r}",
                known=sorted(_OBS_PREFIX),
            )
        return f"OBS-{prefix}-{self.next(prefix)}"

    def finding(self) -> str:
        return f"FND-{self.next('FND')}"

    def event(self) -> str:
        return f"TL-{self.next('TL')}"

    def ioc(self) -> str:
        return f"IOC-{self.next('IOC')}"


# ── records ───────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Provenance:
    """Where a fact came from, precisely enough to re-derive it by hand."""

    plugin: str
    row_index: int
    offset: str | None = None
    argv_ref: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "plugin": self.plugin,
            "row_index": self.row_index,
            "offset": self.offset,
            "argv_ref": self.argv_ref,
        }


@dataclass
class Observation:
    """
    One normalised fact about the captured system.

    Judgement-free by contract. ``notes`` may record how a value was
    *parsed* ("timestamp carried no timezone") but never what it means.
    """

    obs_id: str
    type: str
    provenance: Provenance
    fields: dict[str, Any] = field(default_factory=dict)
    corroborating_plugins: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "obs_id": self.obs_id,
            "type": self.type,
            "provenance": self.provenance.to_dict(),
        }
        out.update(self.fields)
        if self.corroborating_plugins:
            out["corroborating_plugins"] = sorted(set(self.corroborating_plugins))
        if self.notes:
            out["parse_notes"] = list(self.notes)
        return out

    def get(self, key: str, default: Any = None) -> Any:
        return self.fields.get(key, default)


@dataclass
class Finding:
    """
    A rule-derived interpretation, anchored to observations.

    The four-field split -- statement, interpretation, alternatives,
    action -- is the mechanism by which this agent keeps observation and
    interpretation separable all the way to the consumer, rather than
    merely claiming to.
    """

    finding_id: str
    rule_id: str
    rule_version: str
    title: str
    category: str
    severity: str
    confidence: float
    confidence_basis: str
    observation_refs: list[str]
    entities: dict[str, list[Any]]
    observation_statement: str
    interpretation: str
    alternative_explanations: list[str]
    analyst_action: str
    first_seen_utc: str | None = None
    mitre_attack: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["confidence"] = round(float(self.confidence), 4)
        return d


@dataclass
class TimelineEvent:
    """One placeable event, honest about how well it is placed."""

    event_id: str
    timestamp_utc: str | None
    precision: str
    sequence_hint: int
    source_domain: str
    artifact_type: str
    description: str
    observation_refs: list[str] = field(default_factory=list)
    finding_refs: list[str] = field(default_factory=list)
    entities: dict[str, list[Any]] = field(default_factory=dict)
    confidence: float = 0.0
    precision_basis: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["confidence"] = round(float(self.confidence), 4)
        return d


@dataclass
class IOC:
    """An indicator, with the context that makes it actionable."""

    ioc_id: str
    type: str
    value: str
    context: str
    observation_refs: list[str] = field(default_factory=list)
    finding_refs: list[str] = field(default_factory=list)
    confidence: float = 0.0
    false_positive_risk: str = "unknown"

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["confidence"] = round(float(self.confidence), 4)
        return d


# ── validation ────────────────────────────────────────────────────────


def _is_iso(value: Any) -> bool:
    return isinstance(value, str) and bool(_ISO_RE.match(value))


def _check_confidence(value: Any, where: str, errors: list[str]) -> None:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        errors.append(f"{where}: confidence must be a number, got {type(value).__name__}")
        return
    if not 0.0 <= float(value) <= MAX_CONFIDENCE:
        errors.append(
            f"{where}: confidence {value} outside [0.0, {MAX_CONFIDENCE}]. This "
            f"agent never asserts certainty from a single evidence domain."
        )


def validate_observation(obs: Mapping[str, Any], where: str) -> list[str]:
    errors: list[str] = []

    obs_id = obs.get("obs_id")
    if not isinstance(obs_id, str) or not _OBS_ID_RE.match(obs_id):
        errors.append(f"{where}: obs_id {obs_id!r} is not of the form OBS-XXX-0000")

    if obs.get("type") not in OBSERVATION_TYPES:
        errors.append(f"{where}: type {obs.get('type')!r} is not a known observation type")

    prov = obs.get("provenance")
    if not isinstance(prov, Mapping):
        errors.append(f"{where}: provenance is missing")
    else:
        if not isinstance(prov.get("plugin"), str) or not prov.get("plugin"):
            errors.append(f"{where}: provenance.plugin is missing")
        if not isinstance(prov.get("row_index"), int):
            errors.append(f"{where}: provenance.row_index must be an integer")

    # The observation/interpretation boundary, enforced.
    for forbidden in sorted(FORBIDDEN_OBSERVATION_FIELDS & set(obs)):
        errors.append(
            f"{where}: observation carries the judgement field {forbidden!r}. "
            f"Observations state facts; interpretation belongs in a finding."
        )

    return errors


def validate_finding(finding: Mapping[str, Any], where: str,
                     known_obs: set[str] | None = None) -> list[str]:
    errors: list[str] = []

    fid = finding.get("finding_id")
    if not isinstance(fid, str) or not _FINDING_ID_RE.match(fid):
        errors.append(f"{where}: finding_id {fid!r} is not of the form FND-0000")

    rid = finding.get("rule_id")
    if not isinstance(rid, str) or not _RULE_ID_RE.match(rid):
        errors.append(f"{where}: rule_id {rid!r} is not of the form MEM-X-000")

    if finding.get("severity") not in SEVERITIES:
        errors.append(
            f"{where}: severity {finding.get('severity')!r} not in {SEVERITIES}"
        )

    _check_confidence(finding.get("confidence"), where, errors)

    for required in ("observation_statement", "interpretation", "analyst_action",
                     "confidence_basis", "title", "category", "rule_version"):
        value = finding.get(required)
        if not isinstance(value, str) or not value.strip():
            errors.append(f"{where}: {required} is missing or empty")

    alternatives = finding.get("alternative_explanations")
    if not isinstance(alternatives, list) or not alternatives:
        errors.append(
            f"{where}: alternative_explanations must be a non-empty list. A "
            f"finding with no benign explanation on offer invites the consumer "
            f"to treat a rule hit as established fact."
        )
    elif any(not isinstance(a, str) or not a.strip() for a in alternatives):
        errors.append(f"{where}: alternative_explanations contains an empty entry")

    refs = finding.get("observation_refs")
    if not isinstance(refs, list) or not refs:
        errors.append(
            f"{where}: observation_refs is empty -- every finding must cite the "
            f"observations it was derived from"
        )
    elif known_obs is not None:
        for ref in refs:
            if ref not in known_obs:
                errors.append(f"{where}: observation_refs cites unknown {ref!r}")

    entities = finding.get("entities")
    if not isinstance(entities, Mapping):
        errors.append(f"{where}: entities must be an object")

    seen = finding.get("first_seen_utc")
    if seen is not None and not _is_iso(seen):
        errors.append(f"{where}: first_seen_utc {seen!r} is not RFC-3339 UTC")

    return errors


def validate_timeline_event(event: Mapping[str, Any], where: str) -> list[str]:
    errors: list[str] = []

    eid = event.get("event_id")
    if not isinstance(eid, str) or not _EVENT_ID_RE.match(eid):
        errors.append(f"{where}: event_id {eid!r} is not of the form TL-0000")

    precision = event.get("precision")
    if precision not in PRECISIONS:
        errors.append(f"{where}: precision {precision!r} not in {PRECISIONS}")

    ts = event.get("timestamp_utc")
    if precision == "exact":
        if not _is_iso(ts):
            errors.append(
                f"{where}: precision 'exact' requires an RFC-3339 timestamp, "
                f"got {ts!r}"
            )
    elif precision in ("relative", "unknown"):
        if ts is not None:
            errors.append(
                f"{where}: precision {precision!r} must not carry a timestamp "
                f"({ts!r}); an inferred order rendered as a time is exactly the "
                f"confusion the precision field exists to prevent"
            )
    elif ts is not None and not _is_iso(ts):
        errors.append(f"{where}: timestamp_utc {ts!r} is not RFC-3339 UTC")

    if not isinstance(event.get("sequence_hint"), int):
        errors.append(f"{where}: sequence_hint must be an integer")

    if event.get("source_domain") != "memory":
        errors.append(
            f"{where}: source_domain must be 'memory' -- it is the field the "
            f"correlation agent merges cross-domain timelines on"
        )

    _check_confidence(event.get("confidence"), where, errors)
    return errors


def validate_ioc(ioc: Mapping[str, Any], where: str) -> list[str]:
    errors: list[str] = []

    iid = ioc.get("ioc_id")
    if not isinstance(iid, str) or not _IOC_ID_RE.match(iid):
        errors.append(f"{where}: ioc_id {iid!r} is not of the form IOC-0000")

    if ioc.get("type") not in IOC_TYPES:
        errors.append(f"{where}: type {ioc.get('type')!r} not in {IOC_TYPES}")

    if not isinstance(ioc.get("value"), str) or not ioc.get("value"):
        errors.append(f"{where}: value is missing")

    if not isinstance(ioc.get("context"), str) or not ioc.get("context").strip():
        errors.append(
            f"{where}: context is missing -- a bare indicator with no account of "
            f"where it came from cannot be triaged by the receiving analyst"
        )

    if ioc.get("false_positive_risk") not in ("low", "medium", "high", "unknown"):
        errors.append(
            f"{where}: false_positive_risk {ioc.get('false_positive_risk')!r} "
            f"is not one of low/medium/high/unknown"
        )

    _check_confidence(ioc.get("confidence"), where, errors)
    return errors


def validate_envelope(envelope: Mapping[str, Any], strict: bool = True) -> list[str]:
    """
    Validate a complete output envelope.

    Returns the list of problems. With ``strict`` (the default) a
    non-empty list is raised as ``SchemaValidationError`` -- the
    correlation agent is entitled to assume the contract holds, and
    letting a malformed envelope out pushes the failure into another
    agent where it is much harder to trace.
    """
    errors: list[str] = []

    if envelope.get("schema_version") != SCHEMA_VERSION:
        errors.append(
            f"schema_version {envelope.get('schema_version')!r} != "
            f"{SCHEMA_VERSION!r}"
        )

    for block in ("agent", "case", "evidence", "environment", "execution",
                  "observations", "findings", "timeline", "iocs", "coverage",
                  "limitations", "audit"):
        if block not in envelope:
            errors.append(f"envelope is missing the {block!r} block")

    agent = envelope.get("agent")
    if isinstance(agent, Mapping):
        if agent.get("status") not in STATUSES:
            errors.append(f"agent.status {agent.get('status')!r} not in {STATUSES}")
        for key in ("name", "version", "run_id", "started_utc", "completed_utc"):
            if not agent.get(key):
                errors.append(f"agent.{key} is missing")
    else:
        errors.append("agent block is not an object")

    evidence = envelope.get("evidence")
    if isinstance(evidence, Mapping):
        hashes = evidence.get("hashes")
        if not isinstance(hashes, Mapping):
            errors.append("evidence.hashes is missing")
        else:
            if not isinstance(hashes.get("integrity_verified"), bool):
                errors.append("evidence.hashes.integrity_verified must be a bool")
            for key in ("sha256_before", "sha256_after"):
                value = hashes.get(key)
                if value is not None and (
                    not isinstance(value, str) or len(value) != 64
                ):
                    errors.append(f"evidence.hashes.{key} is not a SHA-256 digest")
    else:
        errors.append("evidence block is not an object")

    # ── observations ─────────────────────────────────────────────────
    known_obs: set[str] = set()
    observations = envelope.get("observations")
    if isinstance(observations, Mapping):
        for group, items in observations.items():
            if not isinstance(items, list):
                errors.append(f"observations.{group} is not a list")
                continue
            for i, obs in enumerate(items):
                where = f"observations.{group}[{i}]"
                if not isinstance(obs, Mapping):
                    errors.append(f"{where} is not an object")
                    continue
                errors.extend(validate_observation(obs, where))
                oid = obs.get("obs_id")
                if isinstance(oid, str):
                    if oid in known_obs:
                        errors.append(f"{where}: duplicate obs_id {oid!r}")
                    known_obs.add(oid)
    else:
        errors.append("observations block is not an object")

    # ── findings ─────────────────────────────────────────────────────
    known_findings: set[str] = set()
    findings = envelope.get("findings")
    if isinstance(findings, list):
        for i, finding in enumerate(findings):
            where = f"findings[{i}]"
            if not isinstance(finding, Mapping):
                errors.append(f"{where} is not an object")
                continue
            errors.extend(validate_finding(finding, where, known_obs))
            fid = finding.get("finding_id")
            if isinstance(fid, str):
                if fid in known_findings:
                    errors.append(f"{where}: duplicate finding_id {fid!r}")
                known_findings.add(fid)
    else:
        errors.append("findings block is not a list")

    # ── timeline ─────────────────────────────────────────────────────
    timeline = envelope.get("timeline")
    if isinstance(timeline, list):
        for i, event in enumerate(timeline):
            where = f"timeline[{i}]"
            if not isinstance(event, Mapping):
                errors.append(f"{where} is not an object")
                continue
            errors.extend(validate_timeline_event(event, where))
            for ref in event.get("observation_refs") or []:
                if known_obs and ref not in known_obs:
                    errors.append(f"{where}: cites unknown observation {ref!r}")
            for ref in event.get("finding_refs") or []:
                if known_findings and ref not in known_findings:
                    errors.append(f"{where}: cites unknown finding {ref!r}")
    else:
        errors.append("timeline block is not a list")

    # ── iocs ─────────────────────────────────────────────────────────
    iocs = envelope.get("iocs")
    if isinstance(iocs, list):
        seen_values: set[tuple[str, str]] = set()
        for i, ioc in enumerate(iocs):
            where = f"iocs[{i}]"
            if not isinstance(ioc, Mapping):
                errors.append(f"{where} is not an object")
                continue
            errors.extend(validate_ioc(ioc, where))
            key = (str(ioc.get("type")), str(ioc.get("value")).lower())
            if key in seen_values:
                errors.append(f"{where}: duplicate IOC {key[0]}:{key[1]}")
            seen_values.add(key)
    else:
        errors.append("iocs block is not a list")

    execution = envelope.get("execution")
    if isinstance(execution, list):
        for i, record in enumerate(execution):
            if not isinstance(record, Mapping):
                errors.append(f"execution[{i}] is not an object")
                continue
            if record.get("status") not in (
                "ok", "failed", "timeout", "unavailable", "skipped"
            ):
                errors.append(
                    f"execution[{i}]: status {record.get('status')!r} is not a "
                    f"known execution status"
                )
            if not isinstance(record.get("argv"), list):
                errors.append(f"execution[{i}]: argv must be a list")
    else:
        errors.append("execution block is not a list")

    if not isinstance(envelope.get("limitations"), list):
        errors.append("limitations block is not a list")

    if strict and errors:
        raise SchemaValidationError(
            f"The output envelope violates the contract in {len(errors)} "
            f"place(s); it was not emitted.",
            errors=errors[:25],
            total_errors=len(errors),
        )
    return errors


def clamp_confidence(value: float) -> float:
    """Confidence, bounded. The upper bound is a design commitment."""
    return max(0.0, min(MAX_CONFIDENCE, round(float(value), 4)))


def group_observations(observations: Iterable[Observation]) -> dict[str, list[dict]]:
    """Bucket observations into the envelope's ``observations`` block."""
    groups: dict[str, list[dict]] = {
        "processes": [], "network": [], "commands": [],
        "modules": [], "injections": [], "services": [],
    }
    bucket = {
        "process": "processes", "network": "network", "command": "commands",
        "module": "modules", "injection": "injections", "service": "services",
    }
    for obs in observations:
        groups[bucket[obs.type]].append(obs.to_dict())
    return groups
