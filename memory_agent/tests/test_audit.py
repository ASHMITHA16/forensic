"""Tests for the tamper-evident audit trail and the case workspace."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from memory_agent.core.audit import GENESIS_HASH, AuditLog
from memory_agent.core.errors import AuditError, UnsafeWorkspace
from memory_agent.core.workspace import create_workspace, sanitize_segment


class AuditTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.log_path = self.dir / "audit.jsonl"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def write_trail(self, n: int = 3) -> AuditLog:
        audit = AuditLog(self.log_path, run_id="run-1", case_id="DF-2026-001")
        for i in range(n):
            audit.record("test.event", index=i, note=f"entry {i}")
        audit.seal()
        return audit

    def read_lines(self) -> list[str]:
        return self.log_path.read_text(encoding="utf-8").strip().split("\n")

    def rewrite_lines(self, lines: list[str]) -> None:
        self.log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


class TestAuditWriting(AuditTestBase):
    def test_creates_file_with_open_entry(self):
        audit = AuditLog(self.log_path, run_id="r", case_id="c")
        audit.seal()
        entries = list(AuditLog.read(self.log_path))
        self.assertEqual(entries[0]["event"], "audit.open")
        self.assertEqual(entries[0]["seq"], 0)
        self.assertEqual(entries[0]["prev_hash"], GENESIS_HASH)

    def test_sequence_numbers_are_contiguous(self):
        self.write_trail(n=5)
        entries = list(AuditLog.read(self.log_path))
        self.assertEqual([e["seq"] for e in entries], list(range(len(entries))))

    def test_seal_reports_digest_and_count(self):
        audit = self.write_trail(n=3)
        info = audit.seal_info
        assert info is not None
        self.assertEqual(len(info["log_sha256"]), 64)
        # open + 3 events + close
        self.assertEqual(info["entries"], 5)
        self.assertTrue(info["sealed_utc"].endswith("Z"))

    def test_refuses_to_append_to_existing_trail(self):
        self.write_trail(n=1)
        with self.assertRaises(AuditError):
            AuditLog(self.log_path, run_id="r2", case_id="c")

    def test_cannot_record_after_seal(self):
        audit = self.write_trail(n=1)
        with self.assertRaises(AuditError):
            audit.record("too.late")

    def test_context_manager_seals_on_exit(self):
        with AuditLog(self.log_path, run_id="r", case_id="c") as audit:
            audit.record("work.done")
        self.assertIsNotNone(audit.seal_info)
        self.assertTrue(AuditLog.verify_chain(self.log_path)["valid"])

    def test_context_manager_records_abort_on_exception(self):
        try:
            with AuditLog(self.log_path, run_id="r", case_id="c") as audit:
                audit.record("work.begin")
                raise ValueError("plugin exploded")
        except ValueError:
            pass

        events = [e["event"] for e in AuditLog.read(self.log_path)]
        self.assertIn("audit.abort", events)
        # The trail is still valid after an abort -- the failure is part of
        # the record, not a corruption of it.
        self.assertTrue(AuditLog.verify_chain(self.log_path)["valid"])


class TestChainVerification(AuditTestBase):
    def test_intact_trail_verifies(self):
        self.write_trail(n=4)
        report = AuditLog.verify_chain(self.log_path)
        self.assertTrue(report["valid"])
        self.assertIsNone(report["broken_at_seq"])
        self.assertEqual(len(report["final_chain_hash"]), 64)

    def test_modified_entry_is_detected_at_that_sequence(self):
        self.write_trail(n=5)
        lines = self.read_lines()

        entry = json.loads(lines[3])
        entry["data"]["note"] = "quietly altered"
        lines[3] = json.dumps(entry, sort_keys=True, separators=(",", ":"))
        self.rewrite_lines(lines)

        report = AuditLog.verify_chain(self.log_path)
        self.assertFalse(report["valid"])
        # Entry 3 still links to entry 2 correctly, so the break surfaces at
        # entry 4, whose prev_hash no longer matches the rewritten line 3.
        self.assertEqual(report["broken_at_seq"], 4)
        self.assertIn("hash chain broken", report["reason"])

    def test_deleted_entry_is_detected(self):
        self.write_trail(n=5)
        lines = self.read_lines()
        del lines[2]
        self.rewrite_lines(lines)

        report = AuditLog.verify_chain(self.log_path)
        self.assertFalse(report["valid"])
        self.assertEqual(report["broken_at_seq"], 2)
        self.assertIn("sequence gap", report["reason"])

    def test_appended_entry_with_wrong_link_is_detected(self):
        self.write_trail(n=2)
        lines = self.read_lines()
        forged = {
            "seq": len(lines),
            "ts_utc": "2026-01-01T00:00:00.000Z",
            "event": "evidence.seal.complete",
            "data": {"sha256": "0" * 64},
            "prev_hash": "f" * 64,
        }
        lines.append(json.dumps(forged, sort_keys=True, separators=(",", ":")))
        self.rewrite_lines(lines)

        report = AuditLog.verify_chain(self.log_path)
        self.assertFalse(report["valid"])
        self.assertEqual(report["broken_at_seq"], len(lines) - 1)

    def test_truncated_trail_is_valid_but_incomplete(self):
        """Truncation leaves a chain that still links correctly -- the links
        cannot catch it. The audit.close bookend is what does."""
        self.write_trail(n=6)
        lines = self.read_lines()
        self.rewrite_lines(lines[:4])

        report = AuditLog.verify_chain(self.log_path)
        self.assertTrue(report["valid"])          # links are fine
        self.assertFalse(report["complete"])      # but the trail was cut
        self.assertEqual(report["entries"], 4)
        self.assertIn("does not end with", report["reason"])

    def test_append_after_seal_is_detected_as_incomplete(self):
        """A competent attacker continues the chain correctly. The entry
        count declared in audit.close is what exposes the addition."""
        self.write_trail(n=2)
        lines = self.read_lines()

        import hashlib as _h
        last_hash = _h.sha256(lines[-1].encode()).hexdigest()
        forged = {
            "seq": len(lines),
            "ts_utc": "2026-01-01T00:00:00.000Z",
            "event": "evidence.seal.complete",
            "data": {"sha256": "0" * 64},
            "prev_hash": last_hash,          # correctly linked
        }
        lines.append(json.dumps(forged, sort_keys=True, separators=(",", ":")))
        self.rewrite_lines(lines)

        report = AuditLog.verify_chain(self.log_path)
        self.assertTrue(report["valid"])           # links are correct
        self.assertFalse(report["complete"])       # bookend check catches it
        self.assertIn("does not end with audit.close", report["reason"])

    def test_entry_count_mismatch_is_detected(self):
        """Removing an entry from the middle and renumbering keeps the chain
        linkable; the count declared in audit.close is the backstop."""
        self.write_trail(n=4)
        import hashlib as _h

        entries = [json.loads(l) for l in self.read_lines()]
        del entries[2]                              # drop one, keep the close

        prev = "0" * 64
        rebuilt = []
        for i, e in enumerate(entries):
            e["seq"] = i
            e["prev_hash"] = prev
            line = json.dumps(e, sort_keys=True, separators=(",", ":"))
            rebuilt.append(line)
            prev = _h.sha256(line.encode()).hexdigest()
        self.rewrite_lines(rebuilt)

        report = AuditLog.verify_chain(self.log_path)
        self.assertTrue(report["valid"])
        self.assertFalse(report["complete"])
        self.assertIn("count mismatch", report["reason"])

    def test_blank_line_padding_is_detected(self):
        self.write_trail(n=3)
        lines = self.read_lines()
        lines.insert(2, "")
        self.rewrite_lines(lines)

        report = AuditLog.verify_chain(self.log_path)
        self.assertFalse(report["valid"])
        self.assertIn("blank", report["reason"])

    def test_full_rewrite_passes_links_but_fails_the_anchor(self):
        """The central honesty test: a hash chain has no secret, so an
        attacker who controls the file can re-link everything. Only the
        external anchor catches it -- and the report must say so."""
        audit = self.write_trail(n=3)
        real_anchor = audit.seal_info["final_chain_hash"]
        real_log_sha = audit.seal_info["log_sha256"]

        import hashlib as _h
        entries = [json.loads(l) for l in self.read_lines()]
        entries[2]["data"]["note"] = "evidence never existed"

        prev = "0" * 64
        rebuilt = []
        for i, e in enumerate(entries):
            e["seq"] = i
            e["prev_hash"] = prev
            line = json.dumps(e, sort_keys=True, separators=(",", ":"))
            rebuilt.append(line)
            prev = _h.sha256(line.encode()).hexdigest()
        self.rewrite_lines(rebuilt)

        # Without the anchor the rewrite is invisible -- as it must be.
        blind = AuditLog.verify_chain(self.log_path)
        self.assertTrue(blind["valid"])
        self.assertIsNone(blind["anchor_verified"])

        # With the anchor it is caught.
        anchored = AuditLog.verify_chain(
            self.log_path,
            expected_final_hash=real_anchor,
            expected_log_sha256=real_log_sha,
        )
        self.assertFalse(anchored["anchor_verified"])
        self.assertIn("rewritten", anchored["reason"])

    def test_anchor_verifies_on_an_untouched_trail(self):
        audit = self.write_trail(n=3)
        report = AuditLog.verify_chain(
            self.log_path,
            expected_final_hash=audit.seal_info["final_chain_hash"],
            expected_log_sha256=audit.seal_info["log_sha256"],
        )
        self.assertTrue(report["valid"])
        self.assertTrue(report["complete"])
        self.assertTrue(report["anchor_verified"])

    def test_corrupt_json_is_detected(self):
        self.write_trail(n=3)
        lines = self.read_lines()
        lines[2] = '{"seq": 2, "broken'
        self.rewrite_lines(lines)

        report = AuditLog.verify_chain(self.log_path)
        self.assertFalse(report["valid"])
        self.assertIn("not valid JSON", report["reason"])

    def test_missing_trail_raises(self):
        with self.assertRaises(AuditError):
            AuditLog.verify_chain(self.dir / "absent.jsonl")


class TestSerialisationSafety(AuditTestBase):
    def test_mixed_type_dict_keys_do_not_raise(self):
        """Phase 2 plugin output is PID-keyed. sort_keys=True cannot order
        mixed-type keys, so they must be normalised before serialisation."""
        with AuditLog(self.log_path, run_id="r", case_id="c") as audit:
            audit.record("plugin.result", table={1: "explorer.exe", "b": 2})
        self.assertTrue(AuditLog.verify_chain(self.log_path)["valid"])

    def test_bytes_are_recorded_losslessly_not_stringified(self):
        with AuditLog(self.log_path, run_id="r", case_id="c") as audit:
            audit.record("vad.header", magic=b"MZ\x90\x00")
        entry = [e for e in AuditLog.read(self.log_path) if e["event"] == "vad.header"][0]
        self.assertEqual(entry["data"]["magic"]["__bytes_hex__"], "4d5a9000")

    def test_unserialisable_value_is_marked_not_silently_coerced(self):
        with AuditLog(self.log_path, run_id="r", case_id="c") as audit:
            audit.record("weird", obj=object())
        entry = [e for e in AuditLog.read(self.log_path) if e["event"] == "weird"][0]
        self.assertIn("__coerced__", entry["data"]["obj"])
        self.assertEqual(entry["data"]["obj"]["__type__"], "object")

    def test_sets_become_sorted_lists(self):
        with AuditLog(self.log_path, run_id="r", case_id="c") as audit:
            audit.record("pids", seen={3, 1, 2})
        entry = [e for e in AuditLog.read(self.log_path) if e["event"] == "pids"][0]
        self.assertEqual(entry["data"]["seen"], [1, 2, 3])

    def test_failed_open_record_does_not_poison_the_path(self):
        """A zero-byte audit.jsonl would make every retry fail on 'x' mode."""
        import unittest.mock as mock

        with mock.patch.object(AuditLog, "record", side_effect=RuntimeError("boom")):
            with self.assertRaises(RuntimeError):
                AuditLog(self.log_path, run_id="r", case_id="c")

        self.assertFalse(self.log_path.exists(), "stale trail left behind")
        # Retry must now succeed.
        with AuditLog(self.log_path, run_id="r2", case_id="c") as audit:
            audit.record("ok")


class TestWorkspace(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_creates_expected_layout(self):
        ws = create_workspace(case_id="DF-2026-001", output_dir=self.dir / "cases")
        for d in (ws.root, ws.raw_dir, ws.cache_dir, ws.artifacts_dir):
            self.assertTrue(d.is_dir(), f"{d} was not created")
        self.assertEqual(ws.audit_path.name, "audit.jsonl")
        self.assertEqual(ws.custody_path.name, "custody.json")

    def test_case_id_is_sanitised_into_path(self):
        ws = create_workspace(
            case_id="DF/2026:001 <bad>", output_dir=self.dir / "cases"
        )
        self.assertNotIn("/", ws.root.parent.name)
        self.assertNotIn(":", ws.root.parent.name)

    def test_runs_are_isolated_from_each_other(self):
        a = create_workspace(case_id="C1", output_dir=self.dir / "cases")
        b = create_workspace(case_id="C1", output_dir=self.dir / "cases")
        self.assertNotEqual(a.root, b.root)

    def test_refuses_workspace_inside_evidence_directory(self):
        evidence_dir = self.dir / "evidence"
        evidence_dir.mkdir()
        dump = evidence_dir / "dump.raw"
        dump.write_bytes(b"x" * 128)

        with self.assertRaises(UnsafeWorkspace):
            create_workspace(
                case_id="C1", output_dir=evidence_dir / "cases", evidence_path=dump
            )

    def test_same_volume_workspace_warns(self):
        evidence_dir = self.dir / "evidence"
        evidence_dir.mkdir()
        dump = evidence_dir / "dump.raw"
        dump.write_bytes(b"x" * 128)

        ws = create_workspace(
            case_id="C1", output_dir=self.dir / "cases", evidence_path=dump
        )
        self.assertTrue(ws.warnings)
        self.assertIn("same volume", ws.warnings[0])

    def test_refuses_case_aliased_evidence_directory(self):
        """String comparison of resolved paths is not enough on
        case-insensitive filesystems; the guard compares inode identity."""
        evidence_dir = self.dir / "Evidence"
        evidence_dir.mkdir()
        dump = evidence_dir / "dump.raw"
        dump.write_bytes(b"x" * 128)

        # A symlink is the portable stand-in for a filesystem alias.
        alias = self.dir / "alias"
        try:
            alias.symlink_to(evidence_dir, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable on this platform")

        with self.assertRaises(UnsafeWorkspace):
            create_workspace(
                case_id="C1", output_dir=alias / "out", evidence_path=dump
            )

    def test_allows_workspace_outside_evidence_directory(self):
        evidence_dir = self.dir / "evidence"
        evidence_dir.mkdir()
        dump = evidence_dir / "dump.raw"
        dump.write_bytes(b"x" * 128)

        ws = create_workspace(
            case_id="C1", output_dir=self.dir / "cases", evidence_path=dump
        )
        self.assertTrue(ws.root.is_dir())

    def test_sanitize_segment_handles_empty_input(self):
        self.assertEqual(sanitize_segment("///", fallback="case"), "case")


if __name__ == "__main__":
    unittest.main()
