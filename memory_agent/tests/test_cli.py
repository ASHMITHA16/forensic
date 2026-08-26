"""End-to-end tests for the CLI and the verify pipeline."""

from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from memory_agent.cli import (
    EXIT_ERROR,
    EXIT_INTEGRITY_FAILURE,
    EXIT_NOT_IMPLEMENTED,
    EXIT_OK,
    main,
)
from memory_agent.core.audit import AuditLog
from memory_agent.verify import run_verify


class CliTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.cases = self.dir / "cases"
        self.dump = self.dir / "evidence" / "test.raw"
        self.dump.parent.mkdir(parents=True)
        # 2 MiB so it clears the implausible-size warning threshold
        self.dump.write_bytes(os.urandom(2 * 1024 * 1024))

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def run_cli(self, argv: list[str]) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = main(argv)
        return code, out.getvalue(), err.getvalue()


class TestVerifyPipeline(CliTestBase):
    def test_produces_complete_custody_record(self):
        record = run_verify(
            dump_path=self.dump,
            case_id="DF-2026-001",
            investigator="Bhoomi",
            output_dir=self.cases,
        )

        self.assertEqual(record["record_type"], "chain_of_custody")
        self.assertEqual(record["case"]["case_id"], "DF-2026-001")
        self.assertEqual(record["case"]["investigator"], "Bhoomi")
        self.assertEqual(record["agent"]["status"], "COMPLETE")
        self.assertTrue(record["integrity"]["integrity_verified"])
        self.assertEqual(len(record["evidence"]["sha256"]), 64)
        self.assertTrue(record["evidence"]["read_only_enforced"])

    def test_writes_custody_file_and_audit_trail(self):
        record = run_verify(
            dump_path=self.dump, case_id="C1", output_dir=self.cases
        )
        custody = Path(record["workspace"]["custody_path"])
        audit = Path(record["workspace"]["audit_path"])

        self.assertTrue(custody.is_file())
        self.assertTrue(audit.is_file())
        self.assertEqual(json.loads(custody.read_text())["case"]["case_id"], "C1")

    def test_audit_trail_verifies_after_a_run(self):
        record = run_verify(dump_path=self.dump, case_id="C1", output_dir=self.cases)
        report = AuditLog.verify_chain(record["workspace"]["audit_path"])
        self.assertTrue(report["valid"], report["reason"])

    def test_audit_trail_records_the_seal(self):
        record = run_verify(dump_path=self.dump, case_id="C1", output_dir=self.cases)
        events = {e["event"]: e for e in AuditLog.read(record["workspace"]["audit_path"])}

        self.assertIn("evidence.seal.complete", events)
        self.assertEqual(
            events["evidence.seal.complete"]["data"]["sha256"],
            record["evidence"]["sha256"],
        )
        self.assertIn("run.begin", events)
        self.assertIn("run.end", events)

    def test_custody_events_are_recorded_in_order(self):
        record = run_verify(dump_path=self.dump, case_id="C1", output_dir=self.cases)
        actions = [e["action"] for e in record["chain_of_custody"]["events"]]
        self.assertEqual(
            actions, ["evidence_received", "evidence_sealed", "integrity_verified"]
        )

    def test_paranoid_mode_rereads_and_reports_the_method(self):
        record = run_verify(
            dump_path=self.dump, case_id="C1", output_dir=self.cases, reread=True
        )
        self.assertEqual(record["integrity"]["verification_method"], "reread")
        self.assertTrue(record["integrity"]["integrity_verified"])

    def test_default_mode_does_not_reread(self):
        record = run_verify(dump_path=self.dump, case_id="C1", output_dir=self.cases)
        self.assertEqual(record["integrity"]["verification_method"], "seal_only")

    def test_custody_json_uses_unix_line_endings(self):
        """custody.json is a forensic document an examiner may hash; its
        digest must not depend on which OS wrote it."""
        record = run_verify(dump_path=self.dump, case_id="C1", output_dir=self.cases)
        raw = Path(record["workspace"]["custody_path"]).read_bytes()
        self.assertNotIn(b"\r\n", raw)

    def test_evidence_is_unchanged_by_the_run(self):
        before = self.dump.read_bytes()
        run_verify(dump_path=self.dump, case_id="C1", output_dir=self.cases)
        self.assertEqual(self.dump.read_bytes(), before)

    def test_nothing_is_written_beside_the_evidence(self):
        before = sorted(p.name for p in self.dump.parent.iterdir())
        run_verify(dump_path=self.dump, case_id="C1", output_dir=self.cases)
        after = sorted(p.name for p in self.dump.parent.iterdir())
        self.assertEqual(before, after)

    def test_two_runs_of_the_same_evidence_agree(self):
        """Reproducibility: the seal is a property of the bytes, not the run."""
        a = run_verify(dump_path=self.dump, case_id="C1", output_dir=self.cases)
        b = run_verify(dump_path=self.dump, case_id="C1", output_dir=self.cases)
        self.assertEqual(a["evidence"]["sha256"], b["evidence"]["sha256"])
        self.assertNotEqual(a["agent"]["run_id"], b["agent"]["run_id"])


class TestCliVerify(CliTestBase):
    def test_exit_zero_and_prints_summary(self):
        code, out, _ = self.run_cli(
            ["verify", str(self.dump), "--case-id", "DF-2026-001",
             "-o", str(self.cases)]
        )
        self.assertEqual(code, EXIT_OK)
        self.assertIn("CHAIN OF CUSTODY", out)
        self.assertIn("SHA-256", out)
        self.assertIn("VERIFIED", out)

    def test_json_mode_emits_parseable_record(self):
        code, out, _ = self.run_cli(
            ["verify", str(self.dump), "--case-id", "C1", "-o", str(self.cases), "--json"]
        )
        self.assertEqual(code, EXIT_OK)
        record = json.loads(out)
        self.assertEqual(record["record_type"], "chain_of_custody")

    def test_quiet_mode_prints_nothing(self):
        code, out, _ = self.run_cli(
            ["verify", str(self.dump), "--case-id", "C1", "-o", str(self.cases), "-q"]
        )
        self.assertEqual(code, EXIT_OK)
        self.assertEqual(out.strip(), "")

    def test_missing_file_exits_one_with_structured_error(self):
        code, out, err = self.run_cli(
            ["verify", str(self.dir / "nope.raw"), "--case-id", "C1",
             "-o", str(self.cases), "--json"]
        )
        self.assertEqual(code, EXIT_ERROR)
        payload = json.loads(out)
        self.assertEqual(payload["error_code"], "MA-E-101")
        self.assertEqual(payload["error_type"], "EvidenceNotFound")

    def test_empty_file_exits_one(self):
        empty = self.dir / "empty.raw"
        empty.touch()
        code, out, _ = self.run_cli(
            ["verify", str(empty), "--case-id", "C1", "-o", str(self.cases), "--json"]
        )
        self.assertEqual(code, EXIT_ERROR)
        self.assertEqual(json.loads(out)["error_code"], "MA-E-104")

    def test_acquisition_metadata_is_carried_through(self):
        code, out, _ = self.run_cli(
            ["verify", str(self.dump), "--case-id", "C1", "-o", str(self.cases),
             "--json", "--acquisition-tool", "WinPmem",
             "--acquired-utc", "2026-04-12T02:00:00Z"]
        )
        self.assertEqual(code, EXIT_OK)
        acq = json.loads(out)["evidence"]["acquisition"]
        self.assertEqual(acq["tool"], "WinPmem")
        self.assertEqual(acq["acquired_utc"], "2026-04-12T02:00:00Z")


class TestCliAuditVerify(CliTestBase):
    def test_reports_intact_chain_and_verifies_the_anchor(self):
        record = run_verify(dump_path=self.dump, case_id="C1", output_dir=self.cases)
        code, out, _ = self.run_cli(["audit-verify", record["workspace"]["audit_path"]])
        self.assertEqual(code, EXIT_OK)
        self.assertIn("Chain links    : consistent", out)
        self.assertIn("complete (opens and closes correctly)", out)
        self.assertIn("External anchor: VERIFIED", out)

    def test_says_so_plainly_when_no_anchor_is_available(self):
        """Without the anchor the tool must not claim the trail is intact --
        a hash chain has no secret and can be re-linked wholesale."""
        record = run_verify(dump_path=self.dump, case_id="C1", output_dir=self.cases)
        code, out, _ = self.run_cli(
            ["audit-verify", record["workspace"]["audit_path"], "--no-anchor"]
        )
        self.assertEqual(code, EXIT_OK)
        self.assertIn("NOT CHECKED", out)
        self.assertIn("does NOT prove", out)

    def test_detects_a_full_rewrite_via_the_anchor(self):
        import hashlib as _h

        record = run_verify(dump_path=self.dump, case_id="C1", output_dir=self.cases)
        audit_path = Path(record["workspace"]["audit_path"])

        entries = [json.loads(l) for l in audit_path.read_text().strip().split("\n")]
        entries[3]["data"]["sha256"] = "0" * 64          # forge the sealed hash
        prev = "0" * 64
        rebuilt = []
        for i, e in enumerate(entries):
            e["seq"] = i
            e["prev_hash"] = prev
            line = json.dumps(e, sort_keys=True, separators=(",", ":"))
            rebuilt.append(line)
            prev = _h.sha256(line.encode()).hexdigest()
        audit_path.write_text("\n".join(rebuilt) + "\n")

        # Blind check cannot see it...
        code_blind, out_blind, _ = self.run_cli(
            ["audit-verify", str(audit_path), "--no-anchor"]
        )
        self.assertEqual(code_blind, EXIT_OK)

        # ...but the anchor in custody.json does.
        code, out, _ = self.run_cli(["audit-verify", str(audit_path)])
        self.assertEqual(code, EXIT_INTEGRITY_FAILURE)
        self.assertIn("MISMATCH", out)

    def test_detects_tampering_and_exits_two(self):
        record = run_verify(dump_path=self.dump, case_id="C1", output_dir=self.cases)
        audit_path = Path(record["workspace"]["audit_path"])

        lines = audit_path.read_text().strip().split("\n")
        entry = json.loads(lines[1])
        entry["data"]["path"] = "/somewhere/else.raw"
        lines[1] = json.dumps(entry, sort_keys=True, separators=(",", ":"))
        audit_path.write_text("\n".join(lines) + "\n")

        code, out, _ = self.run_cli(["audit-verify", str(audit_path)])
        self.assertEqual(code, EXIT_INTEGRITY_FAILURE)
        self.assertIn("BROKEN", out)


class TestCliAnalyzeStub(CliTestBase):
    def test_analyze_reports_not_implemented(self):
        code, _out, err = self.run_cli(
            ["analyze", str(self.dump), "--case-id", "C1"]
        )
        self.assertEqual(code, EXIT_NOT_IMPLEMENTED)
        self.assertIn("Phase 5", err)


if __name__ == "__main__":
    unittest.main()
