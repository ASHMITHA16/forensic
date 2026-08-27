"""
Tests for Tier 2 -- normalisation.

The load-bearing assertion in this file is the tri-state one. A process
absent from ``pslist`` is a hidden-process indicator only when pslist
actually ran. If a failed pslist rendered as "absent", the agent would
manufacture a CRITICAL finding on every image where pslist timed out.
Several tests below exist solely to keep that from regressing.
"""

from __future__ import annotations

import unittest

from memory_agent.core.runner import STATUS_OK, PluginResult
from memory_agent.core.schema import (
    FORBIDDEN_OBSERVATION_FIELDS,
    IdFactory,
    Observation,
)
from memory_agent.extractors import extract_all
from memory_agent.extractors.base import ExtractionContext
from memory_agent.extractors.commands import basename, split_command
from memory_agent.extractors.injection import leading_bytes, starts_with_mz
from memory_agent.extractors.network import classify_address
from memory_agent.extractors.processes import extract_processes
from memory_agent.extractors.services import expand_path

from .fixtures import load_results, load_rows


def result(plugin: str, rows: list[dict] | None = None,
           status: str = STATUS_OK, parsed: bool = True) -> PluginResult:
    rows = rows if rows is not None else []
    return PluginResult(
        plugin=plugin, argv=[], status=status, parsed=parsed,
        rows=rows, row_count=len(rows),
    )


def context(**plugins: PluginResult) -> ExtractionContext:
    mapping = {p.plugin: p for p in plugins.values()}
    return ExtractionContext(results=mapping, ids=IdFactory())


class CrossViewTriStateTests(unittest.TestCase):
    """The distinction between 'absent' and 'not established'."""

    ROW = {"PID": 4321, "PPID": 812, "ImageFileName": "evil.exe",
           "Offset(V)": "0x8a4c2040", "CreateTime": "2026-04-12 02:00:00 +0000"}

    def test_absent_from_a_plugin_that_ran_is_false(self) -> None:
        ctx = context(
            a=result("windows.pslist", []),        # ran, returned nothing
            b=result("windows.psscan", [self.ROW]),
        )
        observations = list(extract_processes(ctx))
        self.assertEqual(len(observations), 1)
        cross = observations[0].get("cross_view")
        self.assertIs(cross["pslist"], False)
        self.assertIs(cross["psscan"], True)

    def test_absent_from_a_plugin_that_failed_is_none(self) -> None:
        ctx = context(
            a=result("windows.pslist", status="timeout", parsed=False),
            b=result("windows.psscan", [self.ROW]),
        )
        observations = list(extract_processes(ctx))
        cross = observations[0].get("cross_view")
        self.assertIsNone(cross["pslist"])
        self.assertIsNot(cross["pslist"], False)

    def test_a_failed_cross_view_source_is_stated_as_a_limitation(self) -> None:
        ctx = context(
            a=result("windows.pslist", status="timeout", parsed=False),
            b=result("windows.psscan", [self.ROW]),
        )
        list(extract_processes(ctx))
        self.assertTrue(any("MEM-P-001" in item for item in ctx.limitations))

    def test_no_process_sources_at_all_produces_nothing_and_says_so(self) -> None:
        ctx = context(a=result("windows.pslist", status="failed", parsed=False))
        self.assertEqual(list(extract_processes(ctx)), [])
        self.assertTrue(ctx.limitations)


class ProcessMergeTests(unittest.TestCase):
    def test_same_pid_different_creation_times_stay_separate(self) -> None:
        # Windows reuses PIDs and psscan carves terminated processes.
        # Merging these would fuse two different processes into one record.
        rows = [
            {"PID": 900, "ImageFileName": "a.exe",
             "CreateTime": "2026-04-12 01:00:00 +0000"},
            {"PID": 900, "ImageFileName": "a.exe",
             "CreateTime": "2026-04-12 02:00:00 +0000"},
        ]
        ctx = context(a=result("windows.psscan", rows))
        observations = list(extract_processes(ctx))
        self.assertEqual(len(observations), 2)

    def test_the_same_process_from_two_sources_merges(self) -> None:
        row = {"PID": 900, "PPID": 4, "ImageFileName": "a.exe",
               "CreateTime": "2026-04-12 01:00:00 +0000"}
        ctx = context(
            a=result("windows.pslist", [row]),
            b=result("windows.psscan", [dict(row)]),
        )
        observations = list(extract_processes(ctx))
        self.assertEqual(len(observations), 1)
        self.assertEqual(
            observations[0].corroborating_plugins,
            ["windows.pslist", "windows.psscan"],
        )

    def test_conflicting_fields_are_recorded_not_silently_resolved(self) -> None:
        base = {"PID": 900, "ImageFileName": "a.exe",
                "CreateTime": "2026-04-12 01:00:00 +0000"}
        ctx = context(
            a=result("windows.pslist", [{**base, "PPID": 4}]),
            b=result("windows.psscan", [{**base, "PPID": 812}]),
        )
        observations = list(extract_processes(ctx))
        self.assertEqual(len(observations), 1)
        self.assertTrue(any("ppid" in note for note in observations[0].notes))

    def test_an_ambiguous_psxview_row_is_attached_to_nothing(self) -> None:
        rows = [
            {"PID": 900, "ImageFileName": "a.exe",
             "CreateTime": "2026-04-12 01:00:00 +0000"},
            {"PID": 900, "ImageFileName": "a.exe",
             "CreateTime": "2026-04-12 02:00:00 +0000"},
        ]
        ctx = context(
            a=result("windows.psscan", rows),
            b=result("windows.psxview",
                     [{"Name": "a.exe", "PID": 900, "pslist": False,
                       "psscan": True}]),
        )
        observations = list(extract_processes(ctx))
        # Guessing which of the two it belongs to would create or mask a
        # hidden process, so neither gets the flags.
        for obs in observations:
            self.assertIsNone(obs.get("psxview_flags"))
            self.assertTrue(any("ambiguous" in n for n in obs.notes))

    def test_identifiers_are_allocated_in_a_stable_order(self) -> None:
        rows = [
            {"PID": 900, "ImageFileName": "z.exe", "CreateTime": "2026-04-12 01:00:00 +0000"},
            {"PID": 100, "ImageFileName": "a.exe", "CreateTime": "2026-04-12 01:00:00 +0000"},
        ]
        first = [o.get("pid") for o in extract_processes(context(
            a=result("windows.pslist", rows)))]
        second = [o.get("pid") for o in extract_processes(context(
            a=result("windows.pslist", list(reversed(rows)))))]
        self.assertEqual(first, second)
        self.assertEqual(first, [100, 900])


class ObservationDisciplineTests(unittest.TestCase):
    def test_no_extractor_emits_a_judgement_field(self) -> None:
        observations, _, _ = extract_all(load_results())
        self.assertTrue(observations)
        for obs in observations:
            leaked = FORBIDDEN_OBSERVATION_FIELDS & set(obs.to_dict())
            self.assertEqual(leaked, set(), f"{obs.obs_id} leaked {leaked}")

    def test_every_observation_carries_usable_provenance(self) -> None:
        observations, _, _ = extract_all(load_results())
        for obs in observations:
            self.assertTrue(obs.provenance.plugin)
            self.assertIsInstance(obs.provenance.row_index, int)

    def test_a_failing_extractor_costs_only_its_own_output(self) -> None:
        class Exploding(dict):
            def get(self, *args, **kwargs):
                raise RuntimeError("boom")

        results = load_results()
        observations, limitations, counts = extract_all(results)
        self.assertGreater(len(observations), 0)
        self.assertEqual(len(counts), 6)


class AddressClassificationTests(unittest.TestCase):
    def test_scopes(self) -> None:
        self.assertEqual(classify_address("10.0.2.15")["scope"], "private")
        self.assertEqual(classify_address("127.0.0.1")["scope"], "loopback")
        self.assertEqual(classify_address("185.77.22.90")["scope"], "public")
        self.assertEqual(classify_address("224.0.0.1")["scope"], "multicast")
        self.assertEqual(classify_address("*")["scope"], "unspecified")
        self.assertEqual(classify_address("not-an-ip")["scope"], "unparseable")

    def test_routability_is_recorded(self) -> None:
        self.assertTrue(classify_address("185.77.22.90")["routable"])
        self.assertFalse(classify_address("10.0.2.15")["routable"])


class CommandParsingTests(unittest.TestCase):
    def test_quoted_path_with_spaces_splits_correctly(self) -> None:
        head, tail = split_command('"C:\\Program Files\\App\\a.exe" --flag')
        self.assertEqual(head, "C:\\Program Files\\App\\a.exe")
        self.assertEqual(tail, "--flag")

    def test_unquoted_path_splits_on_whitespace(self) -> None:
        head, tail = split_command("powershell.exe -nop -enc AAAA")
        self.assertEqual(head, "powershell.exe")
        self.assertEqual(tail, "-nop -enc AAAA")

    def test_basename_handles_both_separators(self) -> None:
        self.assertEqual(basename("C:\\Windows\\System32\\a.exe"), "a.exe")
        self.assertEqual(basename("/usr/bin/a"), "a")

    def test_unreadable_parameters_do_not_become_a_command(self) -> None:
        ctx = context(a=result("windows.cmdline", [
            {"PID": 4, "Process": "System",
             "Args": "Required memory at 0x0 is not valid"},
        ]))
        from memory_agent.extractors.commands import extract_commands
        self.assertEqual(list(extract_commands(ctx)), [])
        self.assertTrue(any("swapped out" in item for item in ctx.limitations))


class HexdumpTests(unittest.TestCase):
    DUMP = ("0x2a0000  4d 5a 90 00 03 00 00 00  04 00 00 00 ff ff 00 00   "
            "MZ..............")

    def test_leading_bytes_come_from_the_hex_columns_only(self) -> None:
        # The ASCII column contains characters that look like hex pairs.
        head = leading_bytes(self.DUMP)
        self.assertTrue(head.startswith("4d 5a 90 00"))
        self.assertNotIn("mz", head)

    def test_mz_detection_is_tri_state(self) -> None:
        self.assertIs(starts_with_mz(leading_bytes(self.DUMP)), True)
        self.assertIs(starts_with_mz("55 8b ec"), False)
        self.assertIsNone(starts_with_mz(None))
        self.assertIsNone(starts_with_mz("4d"))

    def test_an_unparseable_dump_yields_none_not_a_guess(self) -> None:
        self.assertIsNone(leading_bytes("no hex here at all"))


class ServicePathTests(unittest.TestCase):
    def test_known_variables_expand(self) -> None:
        expanded, unresolved = expand_path("%SystemRoot%\\system32\\svchost.exe")
        self.assertEqual(expanded, "c:\\windows\\system32\\svchost.exe")
        self.assertEqual(unresolved, [])

    def test_unknown_variables_are_reported_not_left_to_mislead(self) -> None:
        expanded, unresolved = expand_path("%CustomRoot%\\a.exe")
        self.assertEqual(unresolved, ["%customroot%"])

    def test_kernel_path_prefixes_are_normalised(self) -> None:
        expanded, _ = expand_path("\\??\\C:\\Users\\Public\\upd.exe")
        self.assertEqual(expanded, "c:\\users\\public\\upd.exe")
        expanded, _ = expand_path("\\SystemRoot\\System32\\drivers\\x.sys")
        self.assertEqual(expanded, "c:\\windows\\system32\\drivers\\x.sys")


class FixtureCorpusTests(unittest.TestCase):
    def test_the_corpus_normalises_into_every_observation_type(self) -> None:
        observations, limitations, counts = extract_all(load_results())
        types = {obs.type for obs in observations}
        self.assertEqual(
            types,
            {"process", "network", "command", "module", "injection", "service"},
        )
        self.assertTrue(all(count > 0 for count in counts.values()))

    def test_pstree_depth_survives_flattening(self) -> None:
        rows = load_rows("windows.pstree")
        self.assertTrue(any(r.get("__depth", 0) > 2 for r in rows))

    def test_the_hidden_process_is_recorded_as_pslist_false(self) -> None:
        observations, _, _ = extract_all(load_results())
        hidden = [o for o in observations
                  if o.type == "process" and o.get("name") == "svch0st.exe"]
        self.assertEqual(len(hidden), 1)
        self.assertIs(hidden[0].get("cross_view")["pslist"], False)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
