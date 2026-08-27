"""
memory_agent.detectors.engine
─────────────────────────────────────────────────────────────────────
Tier 3: observations → findings.

The engine never touches the memory image. It reads observations, runs
rules, and produces findings that cite the observations they came from.
That constraint is what makes every finding re-derivable by hand: an
analyst who disagrees can follow ``observation_refs`` to a plugin, a row
index and an offset, and go look.

Three properties are enforced here rather than left to rule authors.

**Isolation.** A rule that raises is recorded as errored and the other
sixteen still run. A detection tool that loses fifteen findings because
the sixteenth hit an unexpected ``None`` has failed at the thing it
exists to do.

**"Not evaluated" is distinct from "no findings".** When the plugin a
rule depends on failed, the rule is reported as ``not_evaluated`` with
the reason. Rendering that as a clean result would be an active lie --
the most dangerous output this tool could produce is a confident empty
findings list on a compromised machine.

**Confidence is arithmetic, not vibes.**

    confidence = clamp(base_confidence + Σ adjustments, 0.0, 0.95)

Every term is stated in ``confidence_basis`` in plain text, including
the corroboration bonuses added after the fact. A reviewer can disagree
with a base value; they cannot be confused about how the number was
reached. The 0.95 ceiling is a design commitment: this agent sees one
evidence domain and never asserts certainty.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Sequence

from ..core.errors import DuplicateRuleId
from ..core.schema import (
    MAX_CONFIDENCE,
    RULE_PACK_VERSION,
    Finding,
    IdFactory,
    Observation,
    clamp_confidence,
)

#: Added to a finding for each *other* finding in a different category
#: that names the same PID. Corroboration across independent artifact
#: families is the strongest signal this agent can produce on its own --
#: an injected region and an outbound connection in the same process are
#: individually ambiguous and jointly much less so.
CORROBORATION_BONUS = 0.05
MAX_CORROBORATION = 0.15


@dataclass
class RuleHit:
    """
    What a rule returns. Not yet a finding -- it has no id and no final
    confidence until the engine has seen every other hit.
    """

    observation_refs: list[str]
    observation_statement: str
    interpretation: str
    alternative_explanations: list[str]
    analyst_action: str
    entities: dict[str, list[Any]] = field(default_factory=dict)
    confidence_adjustments: list[tuple[float, str]] = field(default_factory=list)
    first_seen_utc: str | None = None
    severity_override: str | None = None
    title_override: str | None = None


@dataclass(frozen=True)
class Rule:
    """One detection rule, versioned and self-describing."""

    rule_id: str
    version: str
    title: str
    category: str
    severity: str
    base_confidence: float
    evaluate: Callable[["DetectionContext"], Iterable[RuleHit]]
    mitre_attack: tuple[str, ...] = ()
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "version": self.version,
            "title": self.title,
            "category": self.category,
            "severity": self.severity,
            "base_confidence": self.base_confidence,
            "mitre_attack": list(self.mitre_attack),
            "description": self.description,
        }


class DetectionContext:
    """
    Indexed observations, built once and shared by every rule.

    Rules do linear scans over small collections and lookups by PID; the
    indexes exist so seventeen rules do not each re-walk every
    observation, which on a busy image is the difference between a fast
    pass and a slow one.
    """

    def __init__(
        self,
        observations: Sequence[Observation],
        environment: dict[str, Any] | None = None,
    ) -> None:
        self.observations = list(observations)
        self.environment = environment or {}
        self.by_id: dict[str, Observation] = {o.obs_id: o for o in observations}

        self.by_type: dict[str, list[Observation]] = {}
        for obs in observations:
            self.by_type.setdefault(obs.type, []).append(obs)

        self.processes = self.by_type.get("process", [])
        self.network = self.by_type.get("network", [])
        self.commands = self.by_type.get("command", [])
        self.modules = self.by_type.get("module", [])
        self.injections = self.by_type.get("injection", [])
        self.services = self.by_type.get("service", [])

        self.process_by_pid: dict[int, list[Observation]] = {}
        for obs in self.processes:
            pid = obs.get("pid")
            if isinstance(pid, int):
                self.process_by_pid.setdefault(pid, []).append(obs)

        self.network_by_pid: dict[int, list[Observation]] = {}
        for obs in self.network:
            pid = obs.get("pid")
            if isinstance(pid, int):
                self.network_by_pid.setdefault(pid, []).append(obs)

        self.commands_by_pid: dict[int, list[Observation]] = {}
        for obs in self.commands:
            pid = obs.get("pid")
            if isinstance(pid, int):
                self.commands_by_pid.setdefault(pid, []).append(obs)

    def process_name(self, pid: Any) -> str | None:
        if not isinstance(pid, int):
            return None
        for obs in self.process_by_pid.get(pid, []):
            name = obs.get("name")
            if name:
                return str(name)
        return None

    def live_processes(self) -> list[Observation]:
        """Processes with no recorded exit time."""
        return [o for o in self.processes if not o.get("exit_time_utc")]


@dataclass
class RuleOutcome:
    """Per-rule accounting, emitted in the envelope's coverage block."""

    rule_id: str
    status: str  # evaluated | not_evaluated | error
    hits: int = 0
    reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "status": self.status,
            "findings": self.hits,
            "reason": self.reason,
        }


class RuleEngine:
    """Runs a rule pack over a set of observations."""

    def __init__(self, rules: Sequence[Rule], pack_version: str = RULE_PACK_VERSION):
        seen: dict[str, Rule] = {}
        for rule in rules:
            if rule.rule_id in seen:
                raise DuplicateRuleId(
                    f"Two rules claim {rule.rule_id!r}; findings citing it would "
                    f"be unattributable.",
                    rule_id=rule.rule_id,
                )
            seen[rule.rule_id] = rule
        # Sorted so evaluation order -- and therefore finding_id
        # allocation -- does not depend on how the pack was assembled.
        self.rules = sorted(rules, key=lambda r: r.rule_id)
        self.pack_version = pack_version

    def run(
        self,
        context: DetectionContext,
        ids: IdFactory | None = None,
        not_evaluable: dict[str, list[str]] | None = None,
        audit: Any = None,
    ) -> tuple[list[Finding], list[RuleOutcome], list[str]]:
        """
        Evaluate every rule.

        Returns ``(findings, outcomes, limitations)``. ``not_evaluable``
        comes from ``planner.missing_rule_coverage`` and gates rules whose
        input plugins did not produce rows.
        """
        ids = ids or IdFactory()
        not_evaluable = not_evaluable or {}
        outcomes: list[RuleOutcome] = []
        limitations: list[str] = []
        staged: list[tuple[Rule, RuleHit]] = []

        for rule in self.rules:
            blockers = not_evaluable.get(rule.rule_id)
            if blockers:
                outcomes.append(RuleOutcome(
                    rule.rule_id, "not_evaluated",
                    reason=f"input unavailable: {'; '.join(blockers)}",
                ))
                limitations.append(
                    f"{rule.rule_id} ({rule.title}) was NOT evaluated because "
                    f"{'; '.join(blockers)}. Absence of this finding type is "
                    f"therefore not evidence of its absence on the system."
                )
                if audit is not None:
                    audit.record("rule.skipped", rule_id=rule.rule_id,
                                 reason=blockers)
                continue

            try:
                hits = list(rule.evaluate(context))
            except Exception as exc:  # noqa: BLE001 - isolation is the point
                outcomes.append(RuleOutcome(
                    rule.rule_id, "error",
                    reason=f"{type(exc).__name__}: {exc}",
                ))
                limitations.append(
                    f"{rule.rule_id} ({rule.title}) raised "
                    f"{type(exc).__name__} while evaluating and produced no "
                    f"findings. Other rules were unaffected."
                )
                if audit is not None:
                    audit.record(
                        "rule.error", rule_id=rule.rule_id,
                        error_type=type(exc).__name__, message=str(exc),
                    )
                continue

            outcomes.append(RuleOutcome(rule.rule_id, "evaluated", hits=len(hits)))
            for hit in hits:
                staged.append((rule, hit))
            if audit is not None:
                audit.record("rule.evaluated", rule_id=rule.rule_id,
                             hits=len(hits))

        findings = self._finalise(staged, ids)
        return findings, outcomes, limitations

    # ── confidence arithmetic ─────────────────────────────────────────

    def _finalise(
        self, staged: list[tuple[Rule, RuleHit]], ids: IdFactory
    ) -> list[Finding]:
        """Apply corroboration, then allocate ids in a stable order."""
        # Sort before anything else. Corroboration text and finding ids
        # must not depend on the order rules happened to append in.
        staged.sort(key=lambda pair: (
            pair[0].rule_id,
            sorted(pair[1].observation_refs)[0] if pair[1].observation_refs else "",
            sorted(str(p) for p in pair[1].entities.get("pids", [])),
        ))

        pid_categories: dict[int, set[str]] = {}
        for rule, hit in staged:
            for pid in hit.entities.get("pids", []):
                if isinstance(pid, int):
                    pid_categories.setdefault(pid, set()).add(rule.category)

        findings: list[Finding] = []
        for rule, hit in staged:
            terms: list[tuple[float, str]] = [
                (rule.base_confidence, f"base {rule.base_confidence:.2f} ({rule.title})")
            ]
            terms.extend(hit.confidence_adjustments)

            corroboration = 0.0
            corroborating: list[str] = []
            for pid in sorted(
                p for p in hit.entities.get("pids", []) if isinstance(p, int)
            ):
                others = sorted(pid_categories.get(pid, set()) - {rule.category})
                for category in others:
                    if corroboration >= MAX_CORROBORATION:
                        break
                    corroboration += CORROBORATION_BONUS
                    corroborating.append(f"{category} finding on PID {pid}")

            if corroboration:
                terms.append((
                    round(corroboration, 4),
                    f"+{corroboration:.2f} corroborated by "
                    f"{', '.join(corroborating)}",
                ))

            total = round(sum(value for value, _ in terms), 4)
            confidence = clamp_confidence(total)
            basis = "; ".join(text for _, text in terms)
            # Compare the *rounded* total. Binary floating point makes
            # 0.55 + 0.15 come out as 0.7000000000000001, and an
            # unrounded comparison would append "capped at 0.70" to a
            # finding that was never capped -- telling the reader the
            # agent hit its ceiling when it did not.
            if total > MAX_CONFIDENCE:
                basis += (
                    f"; arithmetic total {total:.2f} capped at {confidence:.2f} "
                    f"-- this agent examines one evidence domain and does not "
                    f"assert certainty"
                )
            elif total < 0.0:
                basis += (
                    f"; arithmetic total {total:.2f} raised to 0.00 -- the "
                    f"corroborating evidence did not survive the adjustments"
                )

            findings.append(Finding(
                finding_id=ids.finding(),
                rule_id=rule.rule_id,
                rule_version=rule.version,
                title=hit.title_override or rule.title,
                category=rule.category,
                severity=hit.severity_override or rule.severity,
                confidence=confidence,
                confidence_basis=basis,
                observation_refs=sorted(set(hit.observation_refs)),
                entities={k: _sorted_entities(v) for k, v in
                          sorted(hit.entities.items()) if v},
                observation_statement=hit.observation_statement,
                interpretation=hit.interpretation,
                alternative_explanations=list(hit.alternative_explanations),
                analyst_action=hit.analyst_action,
                first_seen_utc=hit.first_seen_utc,
                mitre_attack=list(rule.mitre_attack),
            ))

        return findings


def _sorted_entities(values: Iterable[Any]) -> list[Any]:
    """Stable ordering for mixed-type entity lists."""
    items = list(values)
    try:
        return sorted(set(items), key=lambda v: (type(v).__name__, v))
    except TypeError:
        return sorted({str(v) for v in items})
