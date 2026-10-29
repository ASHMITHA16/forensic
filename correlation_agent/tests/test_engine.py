"""Rule pack, confidence arithmetic, and the honesty properties (C3–C6)."""

from __future__ import annotations

import unittest
from unittest import mock

from correlation_agent.core.constants import CONFIDENCE_CEILING
from correlation_agent.correlate import run_correlation
from correlation_agent.rules import RULE_PACK

from .fixtures import MEM_C2, MEM_HOLLOW, load, memory


def rule(env: dict, rule_id: str) -> list[dict]:
    return [c for c in env["correlations"] if c["rule_id"] == rule_id]


STAGE2_ON_DISK = {"type": "Suspicious Executable", "severity": "high",
                  "filePath": "Users/jdoe/AppData/Roaming/stage2.exe", "fileName": "stage2.exe"}


class PairRuleTests(unittest.TestCase):
    def test_memory_and_network_link_on_a_public_address(self) -> None:
        env = run_correlation({"memory": memory(MEM_C2), "network": {"findings": [
            {"type": "Beaconing Activity", "ip": "185.77.22.90", "detail": "412 packets"}]}})
        [c] = rule(env, "COR-001")
        self.assertEqual(c["domains"], ["network", "memory"])
        self.assertEqual(c["linking_entities"], [{"type": "ip", "value": "185.77.22.90", "strength": "strong"}])
        self.assertIn("base 0.55", c["confidence_basis"])
        self.assertIn("beaconing", c["confidence_basis"])
        self.assertIn("data_transfer (PID 2456)", c["interpretation"])
        # The network input carries no hash-checked provenance: not established, not "true"
        self.assertIsNone(c["admissible"])

    def test_admissible_only_when_every_cited_domain_is(self) -> None:
        env = run_correlation({"memory": memory(MEM_C2), "network": {
            "findings": [{"type": "External Connection", "ip": "185.77.22.90"}],
            "provenance": {"evidenceHash": "ab12"}}})
        self.assertIs(rule(env, "COR-001")[0]["admissible"], True)

    def test_confidence_is_capped_and_states_its_arithmetic(self) -> None:
        env = run_correlation({"memory": memory(MEM_C2), "network": {"findings": [
            {"type": "Known Malicious IP", "ip": "185.77.22.90"},
            {"type": "Beaconing Activity", "ip": "185.77.22.90"}]}})
        c = rule(env, "COR-001")[0]
        # 0.55 + 0.10 strong + 0.15 threat intel + 0.10 beaconing = 0.90
        self.assertEqual(c["confidence"], 0.9)
        for c in env["correlations"]:
            self.assertLessEqual(c["confidence"], CONFIDENCE_CEILING)
            self.assertTrue(c["alternative_explanations"])
            self.assertTrue(c["observation_statement"] and c["interpretation"] and c["analyst_action"])

    def test_a_path_and_a_name_for_one_file_make_one_correlation(self) -> None:
        env = run_correlation({"memory": memory(MEM_HOLLOW), "disk": {"findings": [STAGE2_ON_DISK]}})
        [c] = rule(env, "COR-002")
        self.assertEqual(sorted(e["type"] for e in c["linking_entities"]), ["image", "path"])
        self.assertIn("+0.05 2 independent shared entities", c["confidence_basis"])

    def test_a_deleted_file_backing_a_live_process_is_called_out(self) -> None:
        env = run_correlation({"memory": memory(MEM_C2), "disk": {"findings": [
            {"type": "Deleted File", "severity": "high", "deleted": True,
             "filePath": "Users/jdoe/AppData/Local/Temp/data_transfer.exe", "fileName": "data_transfer.exe"}]}})
        [c] = rule(env, "COR-002")
        self.assertEqual(c["title"], "Running process backed by a deleted file")
        self.assertIn("T1070.004", c["mitre_attack"])

    def test_names_on_every_host_never_correlate_alone(self) -> None:
        env = run_correlation({
            "log": {"findings": [{"type": "Suspicious Command", "severity": "high", "lineNumber": 1,
                                  "rawLine": "process=svchost.exe started"}]},
            "memory": memory({**MEM_C2, "entities": {"processes": ["svchost.exe"], "pids": [700]}}),
        })
        self.assertEqual(env["correlations"], [])
        self.assertEqual(env["entity_links"][0]["strength"], "weak")
        self.assertEqual(env["coverage"]["weak_links_ignored"], 1)

    def test_a_shared_private_address_is_down_weighted(self) -> None:
        env = run_correlation({
            "log": {"findings": [{"type": "Failed Login", "severity": "medium", "ip": "192.168.56.10", "lineNumber": 3}]},
            "network": {"findings": [{"type": "External Connection", "ip": "8.8.8.8",
                                      "detail": "External communication from 192.168.56.10"}]},
        })
        [c] = rule(env, "COR-003")
        self.assertIn("private (RFC1918)", c["confidence_basis"])

    def test_a_link_is_no_stronger_than_its_weakest_finding(self) -> None:
        weak = {**MEM_C2, "confidence": 0.25}
        env = run_correlation({"memory": memory(weak), "network": {"findings": [{"type": "External Connection", "ip": "185.77.22.90"}]}})
        self.assertIn("low-confidence (max 0.25)", rule(env, "COR-001")[0]["confidence_basis"])


class TemporalTests(unittest.TestCase):
    def net(self, ts: str) -> dict:
        return {"findings": [{"type": "External Connection", "ip": "185.77.22.90", "timestamp": ts}]}

    def test_close_timestamps_raise_confidence_and_distant_ones_lower_it(self) -> None:
        near = rule(run_correlation({"memory": memory(MEM_C2), "network": self.net("2026-04-12T02:20:00Z")}), "COR-001")[0]
        far = rule(run_correlation({"memory": memory(MEM_C2), "network": self.net("2026-04-20T02:20:00Z")}), "COR-001")[0]
        self.assertIn("within the 900s window", near["confidence_basis"])
        self.assertIn("h apart", far["confidence_basis"])
        self.assertGreater(near["confidence"], far["confidence"])

    def test_no_timestamp_is_invented(self) -> None:
        env = run_correlation({"memory": memory(MEM_C2), "network": {"findings": [{"type": "External Connection", "ip": "185.77.22.90"}]}})
        self.assertEqual([e["source_domain"] for e in env["timeline"]], ["memory"])
        self.assertEqual(env["untimed_findings"]["network"], 1)

    def test_a_known_memory_clock_skew_is_removed(self) -> None:
        mem = memory(MEM_C2)
        mem["envelope"]["environment"]["clock_skew_seconds"] = 120
        env = run_correlation({"memory": mem, "log": {"findings": [
            {"type": "Failed Login", "severity": "medium", "timestamp": "2026-04-12T02:17:00Z", "lineNumber": 1}]}})
        event = next(e for e in env["timeline"] if e["source_domain"] == "memory")
        self.assertEqual(event["timestamp_utc"], "2026-04-12T02:16:09Z")
        self.assertEqual(event["clock_adjustment_s"], -120)


class HonestyTests(unittest.TestCase):
    def test_an_invalid_memory_envelope_stays_non_admissible(self) -> None:
        env = run_correlation({
            "memory": memory(MEM_C2, status="INVALID", status_basis="This run replayed captured output."),
            "network": {"findings": [{"type": "External Connection", "ip": "185.77.22.90"}]},
        })
        c = rule(env, "COR-001")[0]
        self.assertIs(c["admissible"], False)
        self.assertIn("non-admissible", c["confidence_basis"])
        self.assertIs(env["assessment"]["admissible"], False)
        self.assertTrue(any("demo replay" in l for l in env["limitations"]))

    def test_missing_domains_are_not_evaluated_never_clean(self) -> None:
        env = run_correlation({"log": {"findings": [{"type": "Failed Login", "severity": "medium", "lineNumber": 1}]}})
        self.assertEqual(env["agent"]["status"], "INSUFFICIENT")
        self.assertEqual(env["coverage"]["rules_evaluated"], [])
        self.assertEqual(len(env["coverage"]["rules_not_evaluated"]), len(RULE_PACK))
        self.assertTrue(any("No memory evidence was supplied" in l for l in env["limitations"]))
        self.assertTrue(any("absence is not evidence" in l for l in env["limitations"]))

    def test_legacy_empty_arrays_mean_not_supplied(self) -> None:
        env = run_correlation({"logData": [], "networkData": [], "memoryData": [], "diskData": []})
        self.assertEqual(env["coverage"]["domains_supplied"], [])
        self.assertIn("not evidence that the system is clean", env["summary"])

    def test_one_failing_rule_does_not_stop_the_others(self) -> None:
        with mock.patch("correlation_agent.engine._run_pivot", side_effect=RuntimeError("boom")):
            env = run_correlation({"memory": memory(MEM_C2), "network": {"findings": [{"type": "External Connection", "ip": "185.77.22.90"}]},
                                   "log": {"findings": [{"type": "IP Detected", "ip": "185.77.22.90", "lineNumber": 1}]}})
        self.assertEqual(env["coverage"]["rules_errored"][0]["rule_id"], "COR-008")
        self.assertTrue(rule(env, "COR-001"))
        self.assertEqual(env["agent"]["status"], "PARTIAL")
        self.assertTrue(any("COR-008 raised an error" in l for l in env["limitations"]))


class DemoFixtureTests(unittest.TestCase):
    """Log/network/disk demo fixtures without memory: no memory_agent needed."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.env = run_correlation({"log": load("log.json"), "network": {"findings": load("network_findings.json")},
                                   "disk": {"findings": load("disk_findings.json")}})

    def test_the_brute_force_source_links_logs_and_the_port_scan(self) -> None:
        c = next(c for c in rule(self.env, "COR-003") if c["linking_entities"][0]["value"] == "45.155.205.18")
        self.assertIn("brute-force", c["confidence_basis"])
        self.assertIn("scanning ports", c["confidence_basis"])

    def test_the_persistence_binary_links_logs_and_disk(self) -> None:
        self.assertTrue(any(e["value"] == "users/public/upd.exe" for c in rule(self.env, "COR-006") for e in c["linking_entities"]))

    def test_anti_forensics_is_co_occurrence_and_says_so(self) -> None:
        [c] = rule(self.env, "COR-007")
        self.assertEqual(c["link_basis"], "co-occurrence")
        self.assertIn("No entity is shared", c["observation_statement"])

    def test_a_tool_present_only_on_disk_stays_unlinked(self) -> None:
        by_ref = {i["ref"]: i for i in self.env["evidence_items"]}
        cited = {r for c in self.env["correlations"] for r in c["evidence_refs"] if c["link_basis"] == "shared-entity"}
        self.assertFalse(any("mimikatz" in by_ref[r]["entities"]["images"] for r in cited))


if __name__ == "__main__":
    unittest.main()
