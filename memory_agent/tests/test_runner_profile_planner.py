"""
Tests for Phase 2: the Volatility runner, OS identification and the
plugin planner.

None of these needs Volatility installed. The runner is exercised through
its parsing and argv construction; a fake runner stands in for the
subprocess where the cascade is under test.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from memory_agent.core.errors import (
    OSIdentificationFailed,
    UnsupportedOS,
    VolatilityNotFound,
)
from memory_agent.core.planner import (
    ExecutionPlan,
    build_plan,
    missing_rule_coverage,
)
from memory_agent.core.profile import (
    LINUX,
    WINDOWS,
    identify,
    profile_from_banners,
    profile_from_raw_scan,
    profile_from_windows_info,
    scan_raw_signatures,
)
from memory_agent.core.runner import (
    STATUS_OK,
    PluginResult,
    ToolchainInfo,
    VolatilityRunner,
    _plugin_names,
    flatten_treegrid,
)


class TreeGridTests(unittest.TestCase):
    def test_nested_children_are_flattened_not_dropped(self) -> None:
        # pstree renders children under __children. A naive json.loads
        # sees only the roots, which for pstree is almost no processes.
        rows = [{
            "PID": 4, "__children": [
                {"PID": 376, "__children": [{"PID": 464, "__children": []}]},
            ],
        }]
        flat = flatten_treegrid(rows)
        self.assertEqual([r["PID"] for r in flat], [4, 376, 464])
        self.assertEqual([r["__depth"] for r in flat], [0, 1, 2])
        self.assertEqual([r["__parent_index"] for r in flat], [None, 0, 1])

    def test_children_key_is_removed_from_the_row(self) -> None:
        flat = flatten_treegrid([{"PID": 4, "__children": []}])
        self.assertNotIn("__children", flat[0])

    def test_non_dict_entries_are_skipped(self) -> None:
        self.assertEqual(flatten_treegrid([1, "x", None]), [])


class RunnerParsingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.dump = self.dir / "dump.raw"
        self.dump.write_bytes(b"\x00" * 1024)
        self.runner = VolatilityRunner(
            evidence_path=self.dump,
            raw_dir=self.dir / "raw",
            cache_dir=self.dir / "cache",
        )
        self.runner._info = ToolchainInfo(
            executable="vol", argv_prefix=("vol",), volatility_version="2.7.0",
            python_version="3.11.0", available_plugins=("windows.pslist",),
            plugin_list_source="vol -h", probe_duration_s=0.1,
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _parse(self, payload: str) -> PluginResult:
        raw = self.dir / "raw" / "t.json"
        raw.parent.mkdir(parents=True, exist_ok=True)
        raw.write_text(payload, encoding="utf-8")
        result = PluginResult(plugin="t", argv=[], status=STATUS_OK)
        self.runner._parse_into(result, raw, raw.stat().st_size)
        return result

    def test_global_options_precede_the_plugin_name(self) -> None:
        # Anything after the plugin name is parsed as an argument TO the
        # plugin, so a misplaced -f would silently change what ran.
        argv = self.runner.build_argv("windows.pslist")
        plugin_at = argv.index("windows.pslist")
        self.assertLess(argv.index("-f"), plugin_at)
        self.assertLess(argv.index("json"), plugin_at)
        self.assertEqual(argv[-1], "windows.pslist")

    def test_cache_is_redirected_into_the_case_workspace(self) -> None:
        argv = self.runner.build_argv("windows.pslist")
        self.assertIn("--cache-path", argv)
        cache = argv[argv.index("--cache-path") + 1]
        self.assertTrue(cache.endswith("cache"))
        env = self.runner._child_env()
        for key in ("TMPDIR", "TEMP", "TMP", "VOLATILITY_CACHE_PATH"):
            self.assertTrue(env[key].endswith("cache"))

    def test_empty_output_is_a_result_not_a_failure(self) -> None:
        result = self._parse("")
        self.assertEqual(result.status, STATUS_OK)
        self.assertTrue(result.parsed)
        self.assertEqual(result.row_count, 0)

    def test_malformed_json_downgrades_to_failed(self) -> None:
        result = self._parse("{not json")
        self.assertEqual(result.status, "failed")
        self.assertFalse(result.parsed)
        self.assertIn("not valid JSON", result.error)

    def test_a_scalar_where_rows_were_expected_is_a_failure(self) -> None:
        result = self._parse("42")
        self.assertEqual(result.status, "failed")
        self.assertIn("expected a JSON array", result.error)

    def test_rows_wrapped_in_an_object_are_unwrapped(self) -> None:
        result = self._parse(json.dumps({"rows": [{"PID": 1}]}))
        self.assertEqual(result.row_count, 1)

    def test_oversized_output_is_kept_but_not_parsed(self) -> None:
        self.runner.max_parse_bytes = 10
        result = self._parse(json.dumps([{"PID": i} for i in range(50)]))
        self.assertEqual(result.status, STATUS_OK)
        self.assertFalse(result.parsed)
        self.assertTrue(any("parse limit" in n for n in result.notes))

    def test_a_plugin_this_build_lacks_is_unavailable_not_failed(self) -> None:
        result = self.runner.run("windows.hollowprocesses")
        self.assertEqual(result.status, "unavailable")
        self.assertEqual(result.argv, [])

    def test_unknown_plugin_list_never_reports_a_plugin_as_missing(self) -> None:
        # None is not False: dropping a plugin we merely failed to
        # enumerate would narrow the analysis while reporting full cover.
        self.runner._info = ToolchainInfo(
            executable="vol", argv_prefix=("vol",), volatility_version="2.7.0",
            python_version="3.11.0", available_plugins=(),
            plugin_list_source="unavailable", probe_duration_s=0.1,
        )
        self.assertIsNone(self.runner.has_plugin("windows.pslist"))

    def test_plugin_list_is_parsed_from_every_line_of_vol_help(self) -> None:
        # Shape of `vol -h` from Volatility 2.28: options first, then one
        # plugin per line. Anchoring to the start of the blob alone finds none.
        help_text = (
            "Volatility 3 Framework 2.28.2\n"
            "  -h, --help            Show this help message and exit\n"
            "  PLUGIN\n"
            "    banners.Banners     Attempts to identify potential linux banners\n"
            "    windows.info.Info   Show OS & kernel details\n"
            "    windows.malfind.Malfind\n"
            "    windows.registry.hivelist.HiveList\n"
        )
        names = _plugin_names(help_text)
        # Both invocation forms are present, so callers using either resolve
        for name in ("banners.Banners", "windows.info", "windows.info.Info",
                     "windows.malfind", "windows.registry.hivelist"):
            self.assertIn(name, names)
        self.assertNotIn("banners", names)

    def test_probe_failure_names_the_attempts(self) -> None:
        runner = VolatilityRunner(
            evidence_path=self.dump, raw_dir=self.dir / "raw2",
            vol_command="/nonexistent/vol-binary",
        )
        with self.assertRaises(VolatilityNotFound) as caught:
            runner.probe(timeout_s=5)
        self.assertIn("attempts", caught.exception.context)


WINDOWS_INFO_ROWS = [
    {"Variable": "Is64Bit", "Value": True},
    {"Variable": "NtMajorVersion", "Value": 10},
    {"Variable": "NtMinorVersion", "Value": 0},
    {"Variable": "NTBuildLab", "Value": "19041.1.amd64fre.vb_release"},
    {"Variable": "SystemTime", "Value": "2026-04-12 02:22:11"},
]


class ProfileTests(unittest.TestCase):
    def test_windows_info_yields_version_arch_and_clock_anchor(self) -> None:
        profile = profile_from_windows_info(WINDOWS_INFO_ROWS)
        self.assertEqual(profile.family, WINDOWS)
        self.assertEqual(profile.version, "10.0.19041")
        self.assertEqual(profile.arch, "x64")
        self.assertEqual(profile.build, "19041")
        self.assertEqual(profile.dump_system_time_utc, "2026-04-12T02:22:11Z")
        self.assertIn("KUSER_SHARED_DATA", profile.dump_system_time_basis)

    def test_a_table_with_no_windows_keys_is_not_windows(self) -> None:
        rows = [{"Variable": "Something", "Value": "else"}]
        self.assertIsNone(profile_from_windows_info(rows))

    def test_skew_is_measured_only_against_a_supplied_acquisition_time(self) -> None:
        without = profile_from_windows_info(WINDOWS_INFO_ROWS)
        self.assertIsNone(without.clock_skew_seconds)
        self.assertIn("unknown", without.clock_skew_basis)

        with_time = profile_from_windows_info(
            WINDOWS_INFO_ROWS, acquisition_utc="2026-04-12T02:22:00Z"
        )
        self.assertEqual(with_time.clock_skew_seconds, 11.0)

    def test_banner_identifies_linux_and_names_the_symbol_requirement(self) -> None:
        rows = [{"Banner": "Linux version 5.15.0-91-generic (x86_64)"}]
        profile = profile_from_banners(rows)
        self.assertEqual(profile.family, LINUX)
        self.assertEqual(profile.version, "5.15.0-91-generic")
        self.assertEqual(profile.arch, "x64")
        self.assertIn("ISF symbol table", profile.symbol_requirement)

    def test_multiple_banners_lower_confidence_and_say_why(self) -> None:
        rows = [
            {"Banner": "Linux version 5.15.0-91-generic"},
            {"Banner": "Linux version 6.2.0-39-generic"},
        ]
        profile = profile_from_banners(rows)
        self.assertLess(profile.confidence, 0.85)
        self.assertTrue(any("distinct kernel banners" in n for n in profile.notes))

    def test_raw_scan_finds_a_planted_banner(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "img.raw"
            path.write_bytes(
                b"\x00" * 4096 + b"Linux version 5.15.0-91-generic\x00"
                + b"\x00" * 4096
            )
            scan = scan_raw_signatures(str(path))
            self.assertEqual(len(scan["linux_banners"]), 1)
            self.assertFalse(scan["scan_truncated"])
            profile = profile_from_raw_scan(scan)
            self.assertEqual(profile.family, LINUX)
            # A string in memory is not proof of the running kernel.
            self.assertLessEqual(profile.confidence, 0.6)

    def test_scan_truncation_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "img.raw"
            path.write_bytes(b"\x00" * 8192)
            scan = scan_raw_signatures(str(path), limit_bytes=4096)
            self.assertTrue(scan["scan_truncated"])
            self.assertEqual(scan["bytes_scanned"], 4096)

    def test_a_handful_of_windows_strings_is_not_an_identification(self) -> None:
        scan = {"bytes_scanned": 1000, "windows_marker_hits": 3,
                "linux_banners": [], "mac_banners": []}
        self.assertIsNone(profile_from_raw_scan(scan))

    def test_cascade_aborts_rather_than_guessing(self) -> None:
        class DeadRunner:
            def run(self, plugin, **kwargs):
                return PluginResult(plugin=plugin, argv=[], status="failed",
                                    error="no symbols")

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "img.raw"
            path.write_bytes(b"\x00" * 2048)
            with self.assertRaises(OSIdentificationFailed):
                identify(DeadRunner(), str(path))

    def test_cascade_falls_through_to_banners(self) -> None:
        class PartialRunner:
            def run(self, plugin, **kwargs):
                if plugin == "banners.Banners":
                    return PluginResult(
                        plugin=plugin, argv=[], status=STATUS_OK, parsed=True,
                        rows=[{"Banner": "Linux version 5.15.0-91-generic"}],
                        row_count=1,
                    )
                return PluginResult(plugin=plugin, argv=[], status="failed")

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "img.raw"
            path.write_bytes(b"\x00" * 2048)
            profile, attempts = identify(PartialRunner(), str(path))
        self.assertEqual(profile.family, LINUX)
        self.assertEqual(len(attempts), 2)


class PlannerTests(unittest.TestCase):
    def test_windows_plan_covers_every_domain(self) -> None:
        plan = build_plan(WINDOWS)
        domains = {e.domain for e in plan.entries}
        for domain in ("environment", "processes", "commands", "network",
                       "modules", "injection", "services"):
            self.assertIn(domain, domains)

    def test_expensive_plugins_are_skipped_and_the_skip_is_recorded(self) -> None:
        plan = build_plan(WINDOWS, deep=False)
        self.assertNotIn("windows.filescan", plan.plugins)
        self.assertTrue(any(s["plugin"] == "windows.filescan"
                            for s in plan.skipped))
        deep = build_plan(WINDOWS, deep=True)
        self.assertIn("windows.filescan", deep.plugins)

    def test_timeouts_scale_with_plugin_cost(self) -> None:
        plan = build_plan(WINDOWS, base_timeout_s=300)
        by_name = {e.plugin: e for e in plan.entries}
        self.assertLess(
            by_name["windows.info"].timeout_s(300),
            by_name["windows.psscan"].timeout_s(300),
        )

    def test_a_tiny_base_budget_cannot_produce_an_impossible_timeout(self) -> None:
        plan = build_plan(WINDOWS, base_timeout_s=10)
        self.assertTrue(all(e.timeout_s(10) >= 30 for e in plan.entries))

    def test_unavailable_plugins_are_dropped_with_the_rules_they_cost(self) -> None:
        plan = build_plan(WINDOWS, available=("windows.info", "windows.pslist"))
        self.assertNotIn("windows.psscan", plan.plugins)
        self.assertTrue(any("MEM-P-001" in item for item in plan.limitations))

    def test_an_unknown_plugin_list_keeps_every_plugin_and_says_so(self) -> None:
        plan = build_plan(WINDOWS, available=None)
        self.assertIn("windows.hollowprocesses", plan.plugins)
        self.assertTrue(any("could not be enumerated" in item
                            for item in plan.limitations))

    def test_unsupported_os_is_refused_rather_than_guessed(self) -> None:
        with self.assertRaises(UnsupportedOS):
            build_plan("unknown")
        with self.assertRaises(UnsupportedOS):
            build_plan("mac")

    def test_linux_plans_but_declares_that_it_cannot_normalise(self) -> None:
        plan = build_plan(LINUX)
        self.assertTrue(plan.entries)
        self.assertTrue(any("no Linux extractors" in item
                            for item in plan.limitations))

    def test_missing_coverage_maps_a_failed_plugin_to_its_rules(self) -> None:
        plan = build_plan(WINDOWS)
        results = {
            e.plugin: PluginResult(plugin=e.plugin, argv=[], status=STATUS_OK,
                                   parsed=True, rows=[{}])
            for e in plan.entries
        }
        results["windows.psscan"] = PluginResult(
            plugin="windows.psscan", argv=[], status="timeout"
        )
        at_risk = missing_rule_coverage(plan, results)
        self.assertIn("MEM-P-001", at_risk)
        self.assertTrue(any("psscan" in r for r in at_risk["MEM-P-001"]))

    def test_only_records_what_it_excluded_and_the_rules_it_costs(self) -> None:
        # Regression: --only used to drop plugins silently, so a
        # three-plugin triage run reported COMPLETE with most rules
        # starved of input and reporting zero findings.
        plan = build_plan(WINDOWS, only=["windows.info", "windows.pslist"])
        self.assertEqual(sorted(plan.plugins),
                         ["windows.info", "windows.pslist"])
        excluded = {s["plugin"] for s in plan.skipped}
        self.assertIn("windows.netscan", excluded)

        results = {
            e.plugin: PluginResult(plugin=e.plugin, argv=[], status=STATUS_OK,
                                   parsed=True, rows=[{}])
            for e in plan.entries
        }
        at_risk = missing_rule_coverage(plan, results)
        for rule in ("MEM-N-001", "MEM-C-001", "MEM-I-001", "MEM-S-001"):
            self.assertIn(rule, at_risk)

    def test_full_success_leaves_only_the_deep_skips_at_risk(self) -> None:
        plan = build_plan(WINDOWS, deep=True)
        results = {
            e.plugin: PluginResult(plugin=e.plugin, argv=[], status=STATUS_OK,
                                   parsed=True, rows=[{}])
            for e in plan.entries
        }
        self.assertEqual(missing_rule_coverage(plan, results), {})


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
