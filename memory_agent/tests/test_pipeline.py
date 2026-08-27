"""
End-to-end tests, including the reproducibility claim.

The design document asserts that the same dump analysed with the same
rule pack produces byte-identical output. Taken literally that is false
-- the envelope carries a run id, wall-clock timestamps and durations --
so the claim is scoped to ``report.deterministic_core``, and this file
is where the scoped claim is actually checked rather than asserted.

The full-pipeline test uses ``replay``, which runs S4-S8 against
captured plugin output. That covers the normalisation, detection,
timeline, IOC and envelope-assembly code without needing a memory image
or a Volatility install on the machine running the tests.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from memory_agent.analyze import load_raw_results, replay_analysis
from memory_agent.core.schema import SCHEMA_VERSION, validate_envelope
from memory_agent.report import (
    core_digest,
    deterministic_core,
    summarise,
    write_envelope,
)

from .fixtures import WINDOWS_CASE


class PipelineTestBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.TemporaryDirectory()
        cls.envelope = replay_analysis(
            raw_dir=WINDOWS_CASE, case_id="DF-TEST-001",
            output_dir=Path(cls.tmp.name) / "cases",
            investigator="Test Runner",
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls.tmp.cleanup()


class EnvelopeTests(PipelineTestBase):
    def test_the_envelope_satisfies_its_own_contract(self) -> None:
        self.assertEqual(validate_envelope(self.envelope, strict=False), [])
        self.assertEqual(self.envelope["schema_version"], SCHEMA_VERSION)

    def test_a_replay_is_invalid_and_says_why(self) -> None:
        # Not a defect. No evidence was sealed, so nothing is admissible,
        # and the reason given must be the replay, not a hash mismatch.
        self.assertEqual(self.envelope["agent"]["status"], "INVALID")
        self.assertIn("replayed", self.envelope["agent"]["status_basis"])
        self.assertIn("NOT EVIDENCE", self.envelope["limitations"][0])

    def test_every_block_of_the_contract_is_present(self) -> None:
        for block in ("agent", "case", "evidence", "environment", "execution",
                      "observations", "findings", "timeline", "iocs",
                      "coverage", "limitations", "audit"):
            self.assertIn(block, self.envelope)

    def test_the_corpus_produces_findings_across_every_family(self) -> None:
        families = {f["rule_id"].split("-")[1] for f in self.envelope["findings"]}
        self.assertEqual(families, {"P", "I", "N", "C", "M", "S"})

    def test_findings_are_ordered_most_severe_first(self) -> None:
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        ranks = [order[f["severity"]] for f in self.envelope["findings"]]
        self.assertEqual(ranks, sorted(ranks))

    def test_every_finding_cites_observations_that_exist(self) -> None:
        known = {
            obs["obs_id"]
            for group in self.envelope["observations"].values()
            for obs in group
        }
        for finding in self.envelope["findings"]:
            for ref in finding["observation_refs"]:
                self.assertIn(ref, known)

    def test_provenance_walks_back_to_a_plugin_that_ran(self) -> None:
        executed = {
            record["plugin"] for record in self.envelope["execution"]
            if record["status"] == "ok"
        }
        for group in self.envelope["observations"].values():
            for obs in group:
                self.assertIn(obs["provenance"]["plugin"], executed)

    def test_coverage_accounts_for_every_rule(self) -> None:
        coverage = self.envelope["coverage"]
        self.assertEqual(coverage["rules_total"], 17)
        self.assertEqual(
            coverage["rules_evaluated"] + coverage["rules_not_evaluated"]
            + coverage["rules_errored"],
            17,
        )

    def test_the_timeline_declares_how_much_of_it_is_real(self) -> None:
        precision = self.envelope["coverage"]["timeline_precision"]
        self.assertGreater(precision.get("exact", 0), 0)
        self.assertGreater(sum(precision.values()), precision.get("exact", 0))
        self.assertTrue(any("carry a timestamp read from the artifact"
                            in item for item in self.envelope["limitations"]))

    def test_no_confidence_anywhere_exceeds_the_ceiling(self) -> None:
        values = (
            [f["confidence"] for f in self.envelope["findings"]]
            + [e["confidence"] for e in self.envelope["timeline"]]
            + [i["confidence"] for i in self.envelope["iocs"]]
        )
        self.assertTrue(values)
        self.assertLessEqual(max(values), 0.95)

    def test_no_private_address_reached_the_indicator_list(self) -> None:
        for ioc in self.envelope["iocs"]:
            if ioc["type"] == "ipv4":
                self.assertFalse(ioc["value"].startswith(("10.", "192.168.",
                                                          "127.")))

    def test_the_envelope_was_written_with_lf_endings(self) -> None:
        path = Path(self.envelope["workspace"]["envelope_path"])
        self.assertTrue(path.is_file())
        self.assertNotIn(b"\r\n", path.read_bytes())

    def test_the_audit_trail_records_the_analysis_stages(self) -> None:
        path = Path(self.envelope["workspace"]["audit_path"])
        events = {
            json.loads(line)["event"]
            for line in path.read_text(encoding="utf-8").splitlines() if line
        }
        for event in ("run.begin", "extract.begin", "detect.begin",
                      "timeline.built", "iocs.extracted", "audit.close"):
            self.assertIn(event, events)


class ReproducibilityTests(unittest.TestCase):
    def test_two_runs_produce_an_identical_deterministic_core(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            first = replay_analysis(WINDOWS_CASE, "DF-REPRO",
                                    output_dir=Path(tmp) / "a")
            second = replay_analysis(WINDOWS_CASE, "DF-REPRO",
                                     output_dir=Path(tmp) / "b")

        self.assertNotEqual(first["agent"]["run_id"], second["agent"]["run_id"])
        self.assertEqual(deterministic_core(first), deterministic_core(second))
        self.assertEqual(core_digest(first), core_digest(second))

    def test_the_core_strips_what_legitimately_varies(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            envelope = replay_analysis(WINDOWS_CASE, "DF-REPRO",
                                       output_dir=Path(tmp))
        core = deterministic_core(envelope)
        serialised = json.dumps(core)
        self.assertNotIn(envelope["agent"]["run_id"], serialised)
        self.assertNotIn("started_utc", core["agent"])
        self.assertNotIn("duration_s", serialised)

    def test_the_core_keeps_the_analysis_itself(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            envelope = replay_analysis(WINDOWS_CASE, "DF-REPRO",
                                       output_dir=Path(tmp))
        core = deterministic_core(envelope)
        self.assertEqual(len(core["findings"]), len(envelope["findings"]))
        self.assertEqual(len(core["timeline"]), len(envelope["timeline"]))
        self.assertEqual(len(core["iocs"]), len(envelope["iocs"]))
        self.assertTrue(core["limitations"])

    def test_the_digest_moves_when_the_analysis_does(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            baseline = replay_analysis(WINDOWS_CASE, "DF-REPRO",
                                       output_dir=Path(tmp) / "a")

            reduced = Path(tmp) / "reduced"
            reduced.mkdir()
            for name in ("windows.info.json", "windows.pslist.json"):
                (reduced / name).write_bytes((WINDOWS_CASE / name).read_bytes())
            changed = replay_analysis(reduced, "DF-REPRO",
                                      output_dir=Path(tmp) / "b")

        self.assertNotEqual(core_digest(baseline), core_digest(changed))


class RawLoaderTests(unittest.TestCase):
    def test_every_fixture_loads_as_parsed_rows(self) -> None:
        results = load_raw_results(WINDOWS_CASE)
        self.assertGreaterEqual(len(results), 15)
        for plugin, result in results.items():
            self.assertTrue(result.parsed, plugin)
            self.assertEqual(result.status, "ok", plugin)

    def test_a_corrupt_file_becomes_a_failed_plugin_not_an_exception(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            (path / "windows.pslist.json").write_text("{not json", encoding="utf-8")
            results = load_raw_results(path)
        self.assertEqual(results["windows.pslist"].status, "failed")

    def test_missing_plugins_degrade_coverage_rather_than_aborting(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            case = Path(tmp) / "case"
            case.mkdir()
            for name in ("windows.info.json", "windows.pslist.json"):
                (case / name).write_bytes((WINDOWS_CASE / name).read_bytes())
            envelope = replay_analysis(case, "DF-SPARSE",
                                       output_dir=Path(tmp) / "out")

        self.assertEqual(validate_envelope(envelope, strict=False), [])
        coverage = envelope["coverage"]
        self.assertGreater(coverage["rules_not_evaluated"], 0)
        # The point of the whole exercise: silence must be explained.
        self.assertTrue(any(
            "NOT evaluated" in item and "not evidence of its absence" in item
            for item in envelope["limitations"]
        ))


class SummaryTests(PipelineTestBase):
    def test_the_summary_names_status_coverage_and_counts(self) -> None:
        text = summarise(self.envelope)
        for token in ("status", "plugins", "rules", "observations",
                      "findings", "timeline", "iocs"):
            self.assertIn(token, text)

    def test_write_envelope_round_trips(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = write_envelope(self.envelope, Path(tmp) / "out.json")
            reloaded = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(reloaded["agent"]["run_id"],
                         self.envelope["agent"]["run_id"])


class AdapterTests(PipelineTestBase):
    def test_the_llm_summary_separates_fact_from_hypothesis(self) -> None:
        from memory_agent.autogen_adapter import summarise_for_llm

        text = summarise_for_llm(self.envelope)
        self.assertIn("FACT:", text)
        self.assertIn("HYPOTHESIS:", text)
        self.assertIn("ALTERNATIVES:", text)
        self.assertIn("LIMITATIONS", text)

    def test_a_failure_never_looks_like_a_clean_result(self) -> None:
        from memory_agent.autogen_adapter import analyze_memory_dump

        result = analyze_memory_dump("/nonexistent/dump.raw", case_id="DF-X")
        self.assertEqual(result["record_type"], "error")
        self.assertNotIn("findings", result)
        self.assertIn("NOT a result showing a clean system", result["guidance"])

    def test_the_tool_description_tells_the_model_how_to_read_absence(self) -> None:
        from memory_agent.autogen_adapter import TOOL_DESCRIPTION

        self.assertIn("limitations", TOOL_DESCRIPTION)
        self.assertIn("NOT because the system was clean", TOOL_DESCRIPTION)

    def test_registration_rejects_an_incompatible_agent_clearly(self) -> None:
        from memory_agent.autogen_adapter import register

        class NotAnAgent:
            pass

        with self.assertRaises(RuntimeError) as caught:
            register(NotAnAgent())
        self.assertIn("register_for_llm", str(caught.exception))

    def test_registration_works_against_the_autogen_api_shape(self) -> None:
        from memory_agent.autogen_adapter import TOOL_NAME, register

        class FakeAgent:
            def __init__(self) -> None:
                self.llm_tools: list[str] = []
                self.exec_tools: list[str] = []

            def register_for_llm(self, name, description):
                self.llm_tools.append(name)
                return lambda func: func

            def register_for_execution(self, name):
                self.exec_tools.append(name)
                return lambda func: func

        agent = FakeAgent()
        registered = register(agent, include_replay=True)
        self.assertEqual(len(registered), 2)
        self.assertIn(TOOL_NAME, agent.llm_tools)
        self.assertEqual(agent.llm_tools, agent.exec_tools)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
