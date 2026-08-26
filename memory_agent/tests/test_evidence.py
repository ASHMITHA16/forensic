"""Tests for evidence sealing, read-only access and integrity verification."""

from __future__ import annotations

import hashlib
import io
import os
import tempfile
import unittest
from pathlib import Path

from memory_agent.core.errors import (
    EvidenceEmpty,
    EvidenceNotAFile,
    EvidenceNotFound,
    EvidenceTampered,
)
from memory_agent.core.evidence import (
    ChainOfCustody,
    compute_hashes,
    open_readonly,
    seal_evidence,
    validate_evidence_path,
    verify_from_seal,
    verify_seal,
)


class EvidenceTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def make_file(self, name: str = "dump.raw", data: bytes = b"A" * 4096) -> Path:
        p = self.dir / name
        p.write_bytes(data)
        return p


class TestValidation(EvidenceTestBase):
    def test_missing_file_raises_not_found(self):
        with self.assertRaises(EvidenceNotFound):
            validate_evidence_path(self.dir / "nope.raw")

    def test_directory_raises_not_a_file(self):
        d = self.dir / "subdir"
        d.mkdir()
        with self.assertRaises(EvidenceNotAFile):
            validate_evidence_path(d)

    def test_empty_file_raises_empty(self):
        p = self.dir / "empty.raw"
        p.touch()
        with self.assertRaises(EvidenceEmpty):
            validate_evidence_path(p)

    def test_valid_file_returns_resolved_path(self):
        p = self.make_file()
        resolved = validate_evidence_path(p)
        self.assertTrue(resolved.is_absolute())
        self.assertEqual(resolved.name, "dump.raw")


class TestHashing(EvidenceTestBase):
    def test_hashes_match_hashlib(self):
        data = os.urandom(200_000)
        p = self.make_file(data=data)
        sha, md5, elapsed = compute_hashes(p)
        self.assertEqual(sha, hashlib.sha256(data).hexdigest())
        self.assertEqual(md5, hashlib.md5(data).hexdigest())
        self.assertGreaterEqual(elapsed, 0.0)

    def test_hashing_is_chunk_size_independent(self):
        """A multi-gigabyte dump is read in chunks; the digest must not depend
        on how the stream happens to be split."""
        data = os.urandom(100_000)
        p = self.make_file(data=data)
        a, _, _ = compute_hashes(p, chunk_size=1024)
        b, _, _ = compute_hashes(p, chunk_size=64 * 1024)
        c, _, _ = compute_hashes(p, chunk_size=7)  # deliberately awkward
        self.assertEqual(a, b)
        self.assertEqual(b, c)

    def test_progress_callback_reaches_total(self):
        data = os.urandom(50_000)
        p = self.make_file(data=data)
        seen: list[tuple[int, int]] = []
        compute_hashes(p, chunk_size=4096, progress=lambda d, t: seen.append((d, t)))
        self.assertTrue(seen)
        self.assertEqual(seen[-1][0], len(data))
        self.assertEqual(seen[-1][1], len(data))


class TestReadOnlyAccess(EvidenceTestBase):
    def test_handle_is_readable(self):
        p = self.make_file(data=b"hello forensic world")
        with open_readonly(p) as fh:
            self.assertEqual(fh.read(5), b"hello")

    def test_handle_rejects_writes(self):
        """The point of O_RDONLY: the agent cannot modify evidence even by
        mistake."""
        p = self.make_file()
        with open_readonly(p) as fh:
            with self.assertRaises((OSError, ValueError, io.UnsupportedOperation)):
                fh.write(b"tamper")

    def test_file_unchanged_after_read(self):
        p = self.make_file(data=b"X" * 1024)
        before = p.stat().st_size, hashlib.sha256(p.read_bytes()).hexdigest()
        with open_readonly(p) as fh:
            fh.read()
        after = p.stat().st_size, hashlib.sha256(p.read_bytes()).hexdigest()
        self.assertEqual(before, after)


class TestSealAndVerify(EvidenceTestBase):
    def test_seal_captures_expected_fields(self):
        data = b"MEMORYDUMP" * 500
        p = self.make_file(data=data)
        seal = seal_evidence(p, evidence_id="EV-MEM-TEST")

        self.assertEqual(seal.evidence_id, "EV-MEM-TEST")
        self.assertEqual(seal.file_name, "dump.raw")
        self.assertEqual(seal.size_bytes, len(data))
        self.assertEqual(seal.sha256, hashlib.sha256(data).hexdigest())
        self.assertEqual(len(seal.sha256), 64)
        self.assertTrue(seal.computed_utc.endswith("Z"))

    def test_seal_generates_evidence_id_when_absent(self):
        seal = seal_evidence(self.make_file())
        self.assertTrue(seal.evidence_id.startswith("EV-MEM-"))

    def test_small_file_produces_warning_but_not_failure(self):
        seal = seal_evidence(self.make_file(data=b"tiny"))
        self.assertTrue(seal.warnings)
        self.assertIn("implausibly small", seal.warnings[0])

    def test_verify_passes_on_untouched_evidence(self):
        p = self.make_file(data=os.urandom(20_000))
        seal = seal_evidence(p)
        report = verify_seal(seal, p)
        self.assertTrue(report.integrity_verified)
        self.assertEqual(report.discrepancies, [])
        self.assertEqual(report.sha256_before, report.sha256_after)

    def test_verify_detects_modified_content(self):
        p = self.make_file(data=b"original content here")
        seal = seal_evidence(p)

        p.write_bytes(b"tampered content!!!!!")  # same length, different bytes

        report = verify_seal(seal, p)
        self.assertFalse(report.integrity_verified)
        self.assertTrue(
            any("SHA-256 mismatch" in d for d in report.discrepancies),
            report.discrepancies,
        )

    def test_verify_detects_size_change(self):
        p = self.make_file(data=b"A" * 2048)
        seal = seal_evidence(p)
        p.write_bytes(b"A" * 4096)

        report = verify_seal(seal, p)
        self.assertFalse(report.integrity_verified)
        self.assertTrue(any("Size changed" in d for d in report.discrepancies))

    def test_verify_detects_deleted_evidence(self):
        p = self.make_file()
        seal = seal_evidence(p)
        p.unlink()

        report = verify_seal(seal, p)
        self.assertFalse(report.integrity_verified)
        self.assertIn("no longer present", report.discrepancies[0])

    def test_verify_raises_when_asked(self):
        p = self.make_file(data=b"before")
        seal = seal_evidence(p)
        p.write_bytes(b"after!")
        with self.assertRaises(EvidenceTampered):
            verify_seal(seal, p, raise_on_failure=True)

    def test_verify_reports_mtime_drift_without_invalidating(self):
        """Content intact but the file was touched: worth recording, not worth
        throwing out the analysis -- and it must NOT land in `discrepancies`,
        because a caller checking `len(discrepancies) > 0` would then raise a
        false tamper alarm on every ordinary run."""
        p = self.make_file(data=b"stable bytes")
        seal = seal_evidence(p)

        st = p.stat()
        os.utime(p, ns=(st.st_atime_ns, st.st_mtime_ns + 1_000_000_000))

        report = verify_seal(seal, p)
        self.assertTrue(report.integrity_verified)
        self.assertFalse(report.metadata_stable)
        self.assertEqual(report.discrepancies, [])
        self.assertTrue(any("Modification time" in n for n in report.metadata_notes))

    def test_substituted_file_invalidates_and_reports_unstable_metadata(self):
        """A different inode with identical content is a substitution.
        `metadata_stable` must be False -- it previously inverted to True in
        exactly this case, putting the opposite of the truth into custody.json."""
        p = self.make_file(data=b"identical content")
        seal = seal_evidence(p)

        # Replace with a different file object carrying the same bytes.
        replacement = self.dir / "replacement.raw"
        replacement.write_bytes(b"identical content")
        p.unlink()
        replacement.rename(p)

        report = verify_seal(seal, p)
        if seal.inode_available and p.stat().st_ino != seal.st_ino:
            self.assertFalse(report.integrity_verified)
            self.assertFalse(report.metadata_stable)
            self.assertTrue(any("Inode changed" in d for d in report.discrepancies))

    def test_seal_records_stability_across_the_hash_pass(self):
        p = self.make_file(data=os.urandom(50_000))
        seal = seal_evidence(p)
        self.assertTrue(seal.stable_during_hash)

    def test_growing_file_is_flagged_as_unreproducible(self):
        """A dump still being written yields a (size, digest) pair covering an
        indeterminate byte range that nobody can reproduce. It must be flagged,
        not emitted as authoritative."""
        p = self.make_file(data=b"A" * 100_000)

        real_hashes = compute_hashes

        def grow_midway(path, chunk_size=8 << 20, progress=None):
            result = real_hashes(path, chunk_size=chunk_size, progress=progress)
            with open(path, "ab") as fh:      # simulate acquisition still running
                fh.write(b"B" * 50_000)
            return result

        import memory_agent.core.evidence as ev_mod

        ev_mod.compute_hashes = grow_midway
        try:
            seal = seal_evidence(p)
        finally:
            ev_mod.compute_hashes = real_hashes

        self.assertFalse(seal.stable_during_hash)
        self.assertTrue(any("CHANGED WHILE" in w for w in seal.warnings))

    def test_verify_from_seal_does_not_reread(self):
        """The seal-only path must not touch the dump again -- on a 32 GB
        image the extra pass costs minutes for no evidentiary gain."""
        p = self.make_file(data=os.urandom(10_000))
        seal = seal_evidence(p)

        report = verify_from_seal(seal)
        self.assertTrue(report.integrity_verified)
        self.assertEqual(report.verification_method, "seal_only")
        self.assertEqual(report.sha256_before, report.sha256_after)


class TestChainOfCustody(unittest.TestCase):
    def test_events_are_sequenced_and_timestamped(self):
        coc = ChainOfCustody(case_id="DF-2026-001", evidence_id="EV-1", run_id="r1")
        coc.add_event("evidence_received", path="/x/dump.raw")
        coc.add_event("evidence_sealed", sha256="deadbeef")

        self.assertEqual(len(coc.events), 2)
        self.assertEqual([e["seq"] for e in coc.events], [0, 1])
        self.assertTrue(all(e["ts_utc"].endswith("Z") for e in coc.events))
        self.assertEqual(coc.events[0]["actor"], "memory_analysis_agent")
        self.assertEqual(coc.events[1]["detail"]["sha256"], "deadbeef")

    def test_serialises_to_dict(self):
        coc = ChainOfCustody(case_id="C", evidence_id="E", run_id="R", investigator="Bhoomi")
        coc.add_event("x")
        d = coc.to_dict()
        self.assertEqual(d["investigator"], "Bhoomi")
        self.assertEqual(len(d["events"]), 1)


if __name__ == "__main__":
    unittest.main()
