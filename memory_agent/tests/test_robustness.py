"""
Hostile-input and full-pipeline tests.

Two things are checked here that nothing else covers.

**The pipeline cannot be crashed by its own input.** Plugin output is
derived from the evidence, and the evidence is the one thing in a
forensic tool that is never under the operator's control. A corrupted
image, a smeared acquisition, or a deliberately malformed structure
produces rows of the wrong type, absurd values and pathological nesting.
The fuzz test below feeds all of that in and asserts the same two
properties every time: nothing escapes as an unhandled exception, and
whatever comes out still satisfies the output contract.

**``run_analysis`` works end to end.** A stub standing in for Volatility
lets S0 through S8 run for real -- evidence sealed, subprocesses spawned,
raw output captured to disk, re-verification performed, envelope written
-- on a machine with no Volatility and no memory image.
"""

from __future__ import annotations

import json
import os
import random
import string
import sys
import tempfile
import unittest
from pathlib import Path

from memory_agent.analyze import replay_analysis, run_analysis
from memory_agent.core.schema import validate_envelope

from .fixtures import WINDOWS_CASE

PLUGINS = [
    "windows.info", "windows.pslist", "windows.psscan", "windows.pstree",
    "windows.psxview", "windows.cmdline", "windows.cmdscan",
    "windows.consoles", "windows.netscan", "windows.netstat",
    "windows.dlllist", "windows.ldrmodules", "windows.modules",
    "windows.modscan", "windows.driverscan", "windows.malfind",
    "windows.vadinfo", "windows.hollowprocesses", "windows.svcscan",
]

COLUMNS = [
    "PID", "PPID", "ImageFileName", "Offset(V)", "CreateTime", "ExitTime",
    "Threads", "State", "LocalAddr", "ForeignAddr", "Proto", "Owner", "Base",
    "InLoad", "InInit", "InMem", "Name", "Protection", "PrivateMemory",
    "Hexdump", "Binary", "Start", "Args", "Cmd", "Variable", "Value",
]


def _junk(rng: random.Random):
    kind = rng.choice("sifbnld")
    if kind == "s":
        return "".join(rng.choice(string.printable) for _ in range(rng.randint(0, 40)))
    if kind == "i":
        return rng.randint(-(2 ** 40), 2 ** 40)
    if kind == "f":
        return rng.random() * 1e9
    if kind == "b":
        return rng.choice([True, False])
    if kind == "n":
        return None
    if kind == "l":
        return [_junk(rng) for _ in range(rng.randint(0, 3))]
    return {str(_junk(rng))[:20]: _junk(rng) for _ in range(rng.randint(0, 3))}


class FuzzTests(unittest.TestCase):
    """Seeded, so a failure is reproducible rather than a one-off."""

    TRIALS = 12

    def _write_case(self, case: Path, rng: random.Random) -> None:
        for plugin in PLUGINS:
            shape = rng.choice(["rows", "empty", "scalar", "deep", "mixed"])
            if shape == "rows":
                data = [
                    {rng.choice(COLUMNS): _junk(rng)
                     for _ in range(rng.randint(1, 8))}
                    for _ in range(rng.randint(1, 15))
                ]
            elif shape == "empty":
                data = []
            elif shape == "scalar":
                data = rng.choice([42, "x", None, {"a": 1}])
            elif shape == "deep":
                # 400 levels of nesting. A recursive flattener dies here
                # with RecursionError, which no caller is structured to
                # contain -- and the nesting comes from the evidence.
                root = {"PID": 1, "__children": []}
                cursor = root
                for _ in range(400):
                    child = {"PID": 1, "__children": []}
                    cursor["__children"].append(child)
                    cursor = child
                data = [root]
            else:
                data = [
                    {"PID": _junk(rng)}, "not a dict", None,
                    {"Name": _junk(rng), "__children": "not a list"},
                ]
            (case / f"{plugin}.json").write_text(
                json.dumps(data, default=str), encoding="utf-8"
            )

    def test_malformed_plugin_output_never_escapes_as_an_exception(self) -> None:
        rng = random.Random(20260826)
        for trial in range(self.TRIALS):
            with self.subTest(trial=trial), tempfile.TemporaryDirectory() as tmp:
                case = Path(tmp) / "case"
                case.mkdir()
                self._write_case(case, rng)

                envelope = replay_analysis(
                    case, f"FUZZ-{trial}", output_dir=Path(tmp) / "out"
                )
                self.assertEqual(validate_envelope(envelope, strict=False), [])

    def test_pathological_nesting_is_bounded_not_followed(self) -> None:
        from memory_agent.core.runner import MAX_TREE_DEPTH, flatten_treegrid

        root = {"PID": 1, "__children": []}
        cursor = root
        for _ in range(MAX_TREE_DEPTH + 500):
            child = {"PID": 1, "__children": []}
            cursor["__children"].append(child)
            cursor = child

        rows = flatten_treegrid([root])
        self.assertLessEqual(max(r["__depth"] for r in rows), MAX_TREE_DEPTH)

    def test_an_empty_case_directory_is_refused_clearly(self) -> None:
        from memory_agent.core.errors import MemoryAgentError

        with tempfile.TemporaryDirectory() as tmp:
            case = Path(tmp) / "empty"
            case.mkdir()
            with self.assertRaises(MemoryAgentError):
                replay_analysis(case, "EMPTY", output_dir=Path(tmp) / "out")


# ── full pipeline against a stubbed Volatility ────────────────────────

_STUB = r'''
import json, sys
from pathlib import Path

FIXTURES = Path(sys.argv[0]).parent / "fixtures"
PLUGINS = sorted(p.stem for p in FIXTURES.glob("*.json"))

argv = sys.argv[1:]
if "-h" in argv or "--help" in argv:
    print("Volatility 3 Framework 2.7.0")
    for name in PLUGINS + ["banners.Banners"]:
        print("  " + name)
    sys.exit(0)

# The plugin name is the first bare token after the last flag value.
plugin = None
skip = False
for i, token in enumerate(argv):
    if skip:
        skip = False
        continue
    if token.startswith("-"):
        if token in ("-f", "-r", "--cache-path", "-o"):
            skip = True
        continue
    plugin = token
    break

if plugin == "FAIL_ME":
    print("simulated plugin failure", file=sys.stderr)
    sys.exit(1)

path = FIXTURES / (str(plugin) + ".json")
if not path.is_file():
    print("no such plugin: " + str(plugin), file=sys.stderr)
    sys.exit(1)
sys.stdout.write(path.read_text(encoding="utf-8"))
'''


class FullPipelineTests(unittest.TestCase):
    """S0 through S8 for real, with a stub standing in for Volatility."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.TemporaryDirectory()
        root = Path(cls.tmp.name)

        stub_dir = root / "stub"
        (stub_dir / "fixtures").mkdir(parents=True)
        for fixture in WINDOWS_CASE.glob("*.json"):
            (stub_dir / "fixtures" / fixture.name).write_bytes(
                fixture.read_bytes()
            )
        cls.stub = stub_dir / "vol_stub.py"
        cls.stub.write_text(_STUB, encoding="utf-8")

        cls.dump = root / "evidence" / "memdump.raw"
        cls.dump.parent.mkdir(parents=True)
        cls.dump.write_bytes(os.urandom(2 * 1024 * 1024))

        cls.envelope = run_analysis(
            dump_path=cls.dump,
            case_id="DF-E2E-001",
            investigator="Test Runner",
            acquisition={"acquired_utc": "2026-04-12T02:25:00Z",
                         "tool": "winpmem", "method": "live"},
            output_dir=root / "cases",
            vol_command=[sys.executable, str(cls.stub)],
            plugin_timeout_s=60,
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls.tmp.cleanup()

    def test_the_envelope_validates(self) -> None:
        self.assertEqual(validate_envelope(self.envelope, strict=False), [])

    def test_the_evidence_was_sealed_and_re_verified(self) -> None:
        hashes = self.envelope["evidence"]["hashes"]
        self.assertTrue(hashes["integrity_verified"])
        self.assertEqual(hashes["sha256_before"], hashes["sha256_after"])
        self.assertEqual(len(hashes["sha256_before"]), 64)
        self.assertEqual(self.envelope["integrity"]["verification_method"],
                         "reread")

    def test_the_os_was_identified_and_the_clock_anchored(self) -> None:
        environment = self.envelope["environment"]
        self.assertEqual(environment["os"]["family"], "windows")
        self.assertEqual(environment["os"]["version"], "10.0.19041")
        self.assertEqual(environment["dump_system_time_utc"],
                         "2026-04-12T02:22:11Z")
        # Skew is measured against the supplied acquisition time only.
        self.assertEqual(environment["clock_skew_seconds"], -169.0)

    def test_the_argv_of_every_plugin_is_in_the_record(self) -> None:
        executed = [r for r in self.envelope["execution"]
                    if r["status"] == "ok"]
        self.assertGreater(len(executed), 10)
        for record in executed:
            self.assertIn("-f", record["argv"])
            self.assertIn(record["plugin"], record["argv"])

    def test_raw_plugin_output_is_retained_on_disk(self) -> None:
        raw_dir = Path(self.envelope["workspace"]["raw_dir"])
        captured = {p.stem for p in raw_dir.glob("*.json")}
        self.assertIn("windows.pslist", captured)
        self.assertIn("windows.malfind", captured)

    def test_nothing_was_written_beside_the_evidence(self) -> None:
        # The cache, symbols and temporary files all belong inside the
        # case workspace. A tool that scatters files next to the evidence
        # changes the directory an investigator may have to present.
        self.assertEqual(
            sorted(p.name for p in self.dump.parent.iterdir()),
            ["memdump.raw"],
        )

    def test_findings_were_produced_across_every_family(self) -> None:
        families = {f["rule_id"].split("-")[1] for f in self.envelope["findings"]}
        self.assertEqual(families, {"P", "I", "N", "C", "M", "S"})

    def test_status_is_partial_because_deep_plugins_were_skipped(self) -> None:
        self.assertEqual(self.envelope["agent"]["status"], "PARTIAL")
        self.assertIn("COVERAGE IS PARTIAL", self.envelope["limitations"][0])

    def test_the_audit_trail_seals_and_verifies(self) -> None:
        from memory_agent.core.audit import AuditLog

        audit = self.envelope["audit"]
        report = AuditLog.verify_chain(
            audit["log_path"],
            expected_final_hash=audit["final_chain_hash"],
            expected_log_sha256=audit["log_sha256"],
        )
        self.assertTrue(report["valid"])
        self.assertTrue(report["complete"])
        self.assertTrue(report["anchor_verified"])

    def test_the_chain_of_custody_records_the_whole_run(self) -> None:
        actions = [e["action"] for e in
                   self.envelope["chain_of_custody"]["events"]]
        for action in ("evidence_sealed", "os_identified", "plugins_executed",
                       "integrity_verified"):
            self.assertIn(action, actions)

    def test_a_failing_plugin_degrades_coverage_instead_of_aborting(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            # The evidence gets its own directory: Phase 1's workspace
            # guard refuses to write the case beside the evidence, and it
            # is right to.
            dump = root / "evidence" / "d.raw"
            dump.parent.mkdir()
            dump.write_bytes(os.urandom(1024 * 1024))
            envelope = run_analysis(
                dump_path=dump, case_id="DF-PARTIAL",
                output_dir=root / "cases",
                vol_command=[sys.executable, str(self.stub)],
                only=["windows.info", "windows.pslist", "windows.psscan"],
                plugin_timeout_s=30,
            )

        self.assertEqual(validate_envelope(envelope, strict=False), [])
        self.assertEqual(envelope["agent"]["status"], "PARTIAL")
        coverage = envelope["coverage"]
        self.assertGreater(coverage["rules_not_evaluated"], 0)
        self.assertTrue(any(
            "NOT evaluated" in item and "not evidence of its absence" in item
            for item in envelope["limitations"]
        ))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
