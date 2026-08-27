"""
Tests for the output contract, the timeline and the IOC extractor.

The contract tests are the ones that matter most to anyone downstream.
Two invariants are enforced by the schema rather than by convention, and
both are here because a violation would be invisible in normal use and
corrosive over time:

* an observation may not carry a judgement field
* a finding may not have an empty ``alternative_explanations``
"""

from __future__ import annotations

import unittest

from memory_agent.core.errors import SchemaValidationError
from memory_agent.core.schema import (
    MAX_CONFIDENCE,
    IOC,
    Finding,
    IdFactory,
    Observation,
    Provenance,
    TimelineEvent,
    clamp_confidence,
    validate_envelope,
    validate_finding,
    validate_ioc,
    validate_observation,
    validate_timeline_event,
)
from memory_agent.synthesis import build_timeline, defang, extract_iocs
from memory_agent.synthesis.iocs import is_emittable_ip, registrable_domain


def good_finding(**overrides) -> dict:
    base = {
        "finding_id": "FND-0001", "rule_id": "MEM-P-001", "rule_version": "1.0",
        "title": "t", "category": "c", "severity": "HIGH", "confidence": 0.5,
        "confidence_basis": "base 0.5", "observation_refs": ["OBS-PROC-0001"],
        "entities": {"pids": [1]}, "observation_statement": "a fact",
        "interpretation": "a hypothesis",
        "alternative_explanations": ["something benign"],
        "analyst_action": "go look",
    }
    base.update(overrides)
    return base


class IdAllocationTests(unittest.TestCase):
    def test_ids_are_sequential_and_typed(self) -> None:
        ids = IdFactory()
        self.assertEqual(ids.observation("process"), "OBS-PROC-0000")
        self.assertEqual(ids.observation("process"), "OBS-PROC-0001")
        self.assertEqual(ids.observation("network"), "OBS-NET-0000")
        self.assertEqual(ids.finding(), "FND-0000")
        self.assertEqual(ids.event(), "TL-0000")
        self.assertEqual(ids.ioc(), "IOC-0000")

    def test_an_unknown_observation_type_is_refused(self) -> None:
        with self.assertRaises(SchemaValidationError):
            IdFactory().observation("nonsense")


class ObservationContractTests(unittest.TestCase):
    def test_a_judgement_field_on_an_observation_is_a_violation(self) -> None:
        for field in ("suspicious", "malicious", "severity", "confidence",
                      "interpretation", "risk_score"):
            errors = validate_observation({
                "obs_id": "OBS-PROC-0001", "type": "process",
                "provenance": {"plugin": "p", "row_index": 0},
                field: True,
            }, "test")
            self.assertTrue(
                any("judgement field" in e for e in errors),
                f"{field} was accepted on an observation",
            )

    def test_provenance_is_required(self) -> None:
        errors = validate_observation(
            {"obs_id": "OBS-PROC-0001", "type": "process"}, "test"
        )
        self.assertTrue(any("provenance" in e for e in errors))

    def test_malformed_ids_are_rejected(self) -> None:
        errors = validate_observation({
            "obs_id": "PROC-1", "type": "process",
            "provenance": {"plugin": "p", "row_index": 0},
        }, "test")
        self.assertTrue(any("obs_id" in e for e in errors))


class FindingContractTests(unittest.TestCase):
    def test_a_well_formed_finding_validates(self) -> None:
        self.assertEqual(validate_finding(good_finding(), "test"), [])

    def test_empty_alternatives_are_a_violation(self) -> None:
        errors = validate_finding(
            good_finding(alternative_explanations=[]), "test"
        )
        self.assertTrue(any("non-empty list" in e for e in errors))

    def test_a_finding_must_cite_observations(self) -> None:
        errors = validate_finding(good_finding(observation_refs=[]), "test")
        self.assertTrue(any("observation_refs is empty" in e for e in errors))

    def test_a_dangling_observation_reference_is_caught(self) -> None:
        errors = validate_finding(good_finding(), "test", known_obs={"OBS-PROC-9999"})
        self.assertTrue(any("unknown" in e for e in errors))

    def test_confidence_above_the_ceiling_is_rejected(self) -> None:
        errors = validate_finding(good_finding(confidence=0.99), "test")
        self.assertTrue(any("outside" in e for e in errors))

    def test_the_four_narrative_fields_may_not_be_blank(self) -> None:
        for field in ("observation_statement", "interpretation",
                      "analyst_action", "confidence_basis"):
            errors = validate_finding(good_finding(**{field: "   "}), "test")
            self.assertTrue(any(field in e for e in errors), field)

    def test_clamping_respects_the_ceiling(self) -> None:
        self.assertEqual(clamp_confidence(1.5), MAX_CONFIDENCE)
        self.assertEqual(clamp_confidence(-1.0), 0.0)


class TimelineContractTests(unittest.TestCase):
    def base(self, **overrides) -> dict:
        record = {
            "event_id": "TL-0001", "timestamp_utc": "2026-04-12T02:18:03Z",
            "precision": "exact", "sequence_hint": 0, "source_domain": "memory",
            "artifact_type": "process_create", "description": "d",
            "confidence": 0.9,
        }
        record.update(overrides)
        return record

    def test_exact_precision_demands_a_timestamp(self) -> None:
        errors = validate_timeline_event(
            self.base(timestamp_utc=None), "test"
        )
        self.assertTrue(any("requires an RFC-3339" in e for e in errors))

    def test_relative_precision_may_not_carry_a_timestamp(self) -> None:
        # An inferred ordering rendered as a time is precisely the
        # confusion the precision field exists to prevent.
        errors = validate_timeline_event(
            self.base(precision="relative"), "test"
        )
        self.assertTrue(any("must not carry a timestamp" in e for e in errors))

    def test_source_domain_is_pinned_to_memory(self) -> None:
        errors = validate_timeline_event(self.base(source_domain="disk"), "test")
        self.assertTrue(any("source_domain" in e for e in errors))


class IocContractTests(unittest.TestCase):
    def test_context_is_mandatory(self) -> None:
        errors = validate_ioc({
            "ioc_id": "IOC-0001", "type": "ipv4", "value": "1.2.3.4",
            "context": "", "confidence": 0.5, "false_positive_risk": "low",
        }, "test")
        self.assertTrue(any("context is missing" in e for e in errors))

    def test_unknown_types_are_rejected(self) -> None:
        errors = validate_ioc({
            "ioc_id": "IOC-0001", "type": "vibes", "value": "x",
            "context": "c", "confidence": 0.5, "false_positive_risk": "low",
        }, "test")
        self.assertTrue(any("type" in e for e in errors))


class EnvelopeValidationTests(unittest.TestCase):
    def test_strict_mode_raises_and_lists_the_problems(self) -> None:
        with self.assertRaises(SchemaValidationError) as caught:
            validate_envelope({"schema_version": "0.0.1"}, strict=True)
        self.assertIn("errors", caught.exception.context)

    def test_non_strict_mode_returns_the_problems(self) -> None:
        errors = validate_envelope({"schema_version": "0.0.1"}, strict=False)
        self.assertGreater(len(errors), 5)


# ── timeline ──────────────────────────────────────────────────────────


def obs(obs_type, obs_id, **fields) -> Observation:
    return Observation(obs_id=obs_id, type=obs_type,
                       provenance=Provenance("p", 0), fields=fields)


class TimelineBuildTests(unittest.TestCase):
    def test_a_timestamped_process_yields_exact_events(self) -> None:
        events, counts = build_timeline([obs(
            "process", "OBS-PROC-0001", pid=2456, ppid=812, name="a.exe",
            create_time_utc="2026-04-12T02:18:03Z",
            exit_time_utc="2026-04-12T02:21:00Z",
        )], ids=IdFactory())
        self.assertEqual(counts["exact"], 2)
        self.assertEqual({e.artifact_type for e in events},
                         {"process_create", "process_exit"})

    def test_an_untimed_process_is_unknown_not_invented(self) -> None:
        events, counts = build_timeline(
            [obs("process", "OBS-PROC-0001", pid=1, name="a.exe")],
            ids=IdFactory(),
        )
        self.assertEqual(counts["unknown"], 1)
        self.assertIsNone(events[0].timestamp_utc)

    def test_relative_and_unknown_events_carry_no_timestamp(self) -> None:
        events, _ = build_timeline([
            obs("command", "OBS-CMD-0001", pid=1, process="a.exe",
                source_kind="typed_history", command_line="whoami"),
            obs("injection", "OBS-INJ-0001", pid=1, process="a.exe",
                protection="PAGE_EXECUTE_READWRITE", region_start="0x1000"),
            obs("service", "OBS-SVC-0001", name="S", binary_raw="x.exe"),
        ], ids=IdFactory())
        for event in events:
            if event.precision in ("relative", "unknown"):
                self.assertIsNone(event.timestamp_utc)
                self.assertIsNotNone(event.precision_basis)

    def test_sequence_hints_are_dense_and_time_ordered(self) -> None:
        events, _ = build_timeline([
            obs("process", "OBS-PROC-0001", pid=2, name="b.exe",
                create_time_utc="2026-04-12T02:20:00Z"),
            obs("process", "OBS-PROC-0002", pid=1, name="a.exe",
                create_time_utc="2026-04-12T02:10:00Z"),
        ], ids=IdFactory())
        self.assertEqual([e.sequence_hint for e in events], [0, 1])
        self.assertEqual(events[0].timestamp_utc, "2026-04-12T02:10:00Z")

    def test_events_validate_against_the_contract(self) -> None:
        events, _ = build_timeline([
            obs("process", "OBS-PROC-0001", pid=1, name="a.exe",
                create_time_utc="2026-04-12T02:10:00Z"),
            obs("command", "OBS-CMD-0001", pid=1, process="a.exe",
                source_kind="launch_parameters", command_line="a.exe -x"),
        ], ids=IdFactory())
        for event in events:
            self.assertEqual(validate_timeline_event(event.to_dict(), "t"), [])

    def test_findings_are_linked_back_onto_their_events(self) -> None:
        finding = Finding(**good_finding(observation_refs=["OBS-PROC-0001"]))
        events, _ = build_timeline(
            [obs("process", "OBS-PROC-0001", pid=1, name="a.exe",
                 create_time_utc="2026-04-12T02:10:00Z")],
            findings=[finding], ids=IdFactory(),
        )
        self.assertEqual(events[0].finding_refs, ["FND-0001"])


# ── IOCs ──────────────────────────────────────────────────────────────


class IocExtractionTests(unittest.TestCase):
    def test_non_routable_addresses_are_never_emitted(self) -> None:
        for address in ("10.0.2.15", "192.168.1.1", "127.0.0.1",
                        "169.254.1.1", "224.0.0.1", "::1"):
            self.assertFalse(is_emittable_ip(address), address)

    def test_public_addresses_are_emitted(self) -> None:
        self.assertTrue(is_emittable_ip("185.77.22.90"))
        self.assertTrue(is_emittable_ip("2606:4700::1111"))

    def test_vendor_ranges_are_kept_unless_explicitly_allowlisted(self) -> None:
        self.assertTrue(is_emittable_ip("20.1.2.3"))
        self.assertFalse(is_emittable_ip("20.1.2.3", allowlist_vendor=True))

    def test_a_finding_backed_indicator_outranks_a_bare_one(self) -> None:
        network = obs(
            "network", "OBS-NET-0001", pid=1, owner="x.exe", protocol="TCPv4",
            state="ESTABLISHED", foreign_address="185.77.22.90",
            foreign_port=4444, foreign_scope="public",
        )
        bare, _ = extract_iocs([network], [], ids=IdFactory())
        finding = Finding(**good_finding(
            observation_refs=["OBS-NET-0001"],
            entities={"ips": ["185.77.22.90"], "pids": [1]},
        ))
        backed, _ = extract_iocs([network], [finding], ids=IdFactory())
        self.assertGreater(backed[0].confidence, bare[0].confidence)
        self.assertIn("MEM-P-001", backed[0].context)

    def test_indicators_are_deduplicated_case_insensitively(self) -> None:
        commands = [
            obs("command", "OBS-CMD-0001", pid=1, process="a.exe",
                source_kind="typed_history",
                command_line="curl HTTP://EVIL.TEST/a"),
            obs("command", "OBS-CMD-0002", pid=1, process="a.exe",
                source_kind="typed_history",
                command_line="curl http://evil.test/a"),
        ]
        iocs, _ = extract_iocs(commands, [], ids=IdFactory())
        urls = [i for i in iocs if i.type == "url"]
        self.assertEqual(len(urls), 1)
        self.assertEqual(len(urls[0].observation_refs), 2)

    def test_ubiquitous_process_names_are_filtered_with_a_reason(self) -> None:
        finding = Finding(**good_finding(entities={"processes": ["svchost.exe"]}))
        iocs, notes = extract_iocs([], [finding], ids=IdFactory())
        self.assertFalse([i for i in iocs if i.type == "process_name"])
        self.assertTrue(any("too common" in n for n in notes))

    def test_an_empty_result_says_what_it_does_and_does_not_mean(self) -> None:
        iocs, notes = extract_iocs([], [], ids=IdFactory())
        self.assertEqual(iocs, [])
        self.assertTrue(any("not that the image is clean" in n for n in notes))

    def test_every_indicator_validates(self) -> None:
        network = obs(
            "network", "OBS-NET-0001", pid=1, owner="x.exe", protocol="TCPv4",
            state="ESTABLISHED", foreign_address="185.77.22.90",
            foreign_port=4444, foreign_scope="public",
        )
        iocs, _ = extract_iocs([network], [], ids=IdFactory())
        for ioc in iocs:
            self.assertEqual(validate_ioc(ioc.to_dict(), "t"), [])

    def test_defanging_is_a_rendering_not_a_stored_value(self) -> None:
        self.assertEqual(defang("1.2.3.4", "ipv4"), "1[.]2[.]3[.]4")
        self.assertEqual(defang("http://evil.test/a", "url"),
                         "hxxp[://]evil.test/a")
        self.assertEqual(defang("evil.test", "domain"), "evil[.]test")

    def test_registrable_domain(self) -> None:
        self.assertEqual(registrable_domain("a.b.evil.test"), "evil.test")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
