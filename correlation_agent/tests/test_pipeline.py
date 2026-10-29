"""
End to end: the demo case through memory_agent's own replay, the
envelope contract, reproducibility, workspace, CLI and adapter.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from correlation_agent.autogen_adapter import TOOL_NAME, correlate_findings, register, summarise_for_llm
from correlation_agent.core.errors import InputNotFound
from correlation_agent.core.schema import validate_envelope
from correlation_agent.correlate import build_demo_payload, run_correlation
from correlation_agent.report import compact_envelope, core_digest, write_workspace

from .fixtures import MEM_C2, VALID_MEMORY_ENVELOPE

REPO_ROOT = Path(__file__).resolve().parents[2]


class DemoCaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.payload = build_demo_payload()
        cls.env = run_correlation(cls.payload, mode="demo")

    def test_the_envelope_satisfies_its_own_contract(self) -> None:
        self.assertEqual(validate_envelope(self.env), [])
        self.assertEqual(self.env["agent"]["status"], "COMPLETE")

    def test_memory_is_read_from_the_memory_agents_envelope(self) -> None:
        mem = self.env["inputs"]["memory"]
        self.assertEqual(mem["memory_source"], "envelope")
        self.assertEqual(mem["source_status"], "INVALID")  # a replay is never admissible
        self.assertIs(mem["admissible"], False)

    def test_the_planted_activity_is_found(self) -> None:
        rules = {c["rule_id"] for c in self.env["correlations"]}
        self.assertTrue({"COR-001", "COR-002", "COR-003", "COR-004", "COR-005", "COR-006", "COR-007", "COR-008"} <= rules)
        titles = [c["title"] for c in self.env["correlations"]]
        self.assertIn("Running process backed by a deleted file", titles)

    def test_the_benign_look_alike_ranks_last(self) -> None:
        last = self.env["correlations"][-1]
        self.assertEqual(last["linking_entities"][0]["value"], "142.250.72.196")
        self.assertIn("low-confidence", last["confidence_basis"])

    def test_reasoning_weighs_two_hypotheses(self) -> None:
        h1, h0 = self.env["hypotheses"]
        self.assertAlmostEqual(h1["confidence"] + h0["confidence"], 1.0, places=2)
        self.assertGreater(h1["confidence"], h0["confidence"])
        self.assertIn("rests partly on non-admissible evidence", h1["confidence_basis"])
        self.assertGreaterEqual(len(self.env["attack_chain"]["phases"]), 5)

    def test_same_input_gives_the_same_core_digest(self) -> None:
        again = run_correlation(self.payload, mode="demo")
        self.assertNotEqual(again["agent"]["run_id"], self.env["agent"]["run_id"])
        self.assertEqual(again["core_digest"], self.env["core_digest"])
        self.assertEqual(core_digest(again), again["core_digest"])

    def test_compaction_keeps_every_cited_item(self) -> None:
        compact = compact_envelope(self.env)
        kept = {i["ref"] for i in compact["evidence_items"]}
        self.assertTrue(all(r in kept for c in compact["correlations"] for r in c["evidence_refs"]))
        self.assertEqual(compact["evidence_items_total"], len(self.env["evidence_items"]))
        self.assertEqual(validate_envelope(compact), [])


class MemoryInputTests(unittest.TestCase):
    def test_envelope_path_from_the_node_summary_is_followed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "memory_agent_output.json"
            path.write_text(json.dumps(VALID_MEMORY_ENVELOPE), encoding="utf-8")
            env = run_correlation({"memory": {"findings": [], "meta": {"envelopePath": str(path), "status": "INVALID"}},
                                   "network": {"findings": [{"type": "External Connection", "ip": "185.77.22.90"}]}})
        self.assertEqual(env["inputs"]["memory"]["memory_source"], "envelope")
        self.assertIs(env["inputs"]["memory"]["admissible"], True)  # the envelope, not the summary, is authoritative
        self.assertEqual(env["inputs"]["memory"]["findings"], 2)

    def test_a_vanished_stored_envelope_falls_back_and_says_so(self) -> None:
        env = run_correlation({"memory": {"findings": [{**MEM_C2}], "meta": {"envelopePath": "/nope/x.json", "status": "COMPLETE"}},
                               "network": {"findings": [{"type": "External Connection", "ip": "185.77.22.90"}]}})
        self.assertEqual(env["inputs"]["memory"]["memory_source"], "summary")
        self.assertTrue(any("no longer on disk" in l for l in env["limitations"]))

    def test_an_explicit_missing_envelope_is_an_error(self) -> None:
        with self.assertRaises(InputNotFound):
            run_correlation({"memory": {"envelope_path": "/nope/x.json"}})


class WorkspaceTests(unittest.TestCase):
    def test_the_stored_input_reproduces_the_digest(self) -> None:
        payload = {"memory": {"envelope": VALID_MEMORY_ENVELOPE},
                   "network": {"findings": [{"type": "External Connection", "ip": "185.77.22.90"}]}}
        with tempfile.TemporaryDirectory() as tmp:
            env = write_workspace(run_correlation(payload, case_id="DF-T"), payload, tmp)
            stored = json.loads(Path(env["workspace"]["input_path"]).read_text(encoding="utf-8"))
            self.assertTrue(Path(env["workspace"]["envelope_path"]).is_file())
        self.assertEqual(run_correlation(stored, case_id="DF-T")["core_digest"], env["core_digest"])


class CliTests(unittest.TestCase):
    def run_cli(self, *args: str, stdin: str | None = None) -> subprocess.CompletedProcess:
        return subprocess.run([sys.executable, "-m", "correlation_agent", *args], input=stdin, capture_output=True,
                              text=True, encoding="utf-8", cwd=REPO_ROOT, env={**os.environ, "PYTHONIOENCODING": "utf-8"})

    def test_correlate_reads_stdin_and_writes_json(self) -> None:
        payload = {"memory": {"envelope": VALID_MEMORY_ENVELOPE},
                   "network": {"findings": [{"type": "External Connection", "ip": "185.77.22.90"}]}}
        result = self.run_cli("correlate", "--input", "-", "--json", "--compact", stdin=json.dumps(payload))
        self.assertEqual(result.returncode, 0, result.stderr)
        env = json.loads(result.stdout)
        self.assertEqual(env["correlations"][0]["rule_id"], "COR-001")

    def test_bad_input_is_a_structured_error_with_exit_code_1(self) -> None:
        result = self.run_cli("correlate", "--input", "-", "--json", stdin="{not json")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads(result.stdout)["error_code"], "CA-E-102")

    def test_rules_and_validate(self) -> None:
        rules = json.loads(self.run_cli("rules", "--json").stdout)
        self.assertEqual(len(rules["rules"]), 8)
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "bad.json"
            bad.write_text(json.dumps({"schema_version": "1.0.0"}), encoding="utf-8")
            self.assertEqual(self.run_cli("validate", str(bad)).returncode, 2)


class AdapterTests(unittest.TestCase):
    def test_the_tool_never_raises(self) -> None:
        out = correlate_findings(memory_envelope_path="/does/not/exist.json")
        self.assertEqual(out["record_type"], "error")
        self.assertEqual(out["error"]["error_code"], "CA-E-101")
        self.assertIn("NOT a result", out["guidance"])
        self.assertIn("CORRELATION FAILED", summarise_for_llm(out))

    def test_registration_uses_the_autogen_api(self) -> None:
        calls = []

        class FakeAgent:
            def register_for_llm(self, name: str, description: str):
                calls.append(("llm", name))
                return lambda f: f

            def register_for_execution(self, name: str):
                calls.append(("exec", name))
                return lambda f: f

        register(FakeAgent())
        self.assertEqual(calls, [("llm", TOOL_NAME), ("exec", TOOL_NAME)])

    def test_summary_carries_facts_hypotheses_and_limitations(self) -> None:
        env = correlate_findings(network={"findings": [{"type": "External Connection", "ip": "185.77.22.90"}]},
                                 memory={"envelope": VALID_MEMORY_ENVELOPE})
        text = summarise_for_llm(env)
        for marker in ("FACT:", "HYPOTHESIS:", "ALTERNATIVES:", "LIMITATIONS"):
            self.assertIn(marker, text)


if __name__ == "__main__":
    unittest.main()
