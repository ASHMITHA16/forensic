"""Normalisation helpers and stage C1 / C2."""

from __future__ import annotations

import unittest

from correlation_agent.core.entities import ip_scope, norm_path, round2, to_iso
from correlation_agent.linking import build_entity_index
from correlation_agent.normalise import normalise_log, normalise_memory, normalise_network


class HelperTests(unittest.TestCase):
    def test_paths_from_every_agent_compare_equal(self) -> None:
        self.assertEqual(norm_path("C:\\Users\\JDoe\\AppData\\x.exe"), "users/jdoe/appdata/x.exe")
        self.assertEqual(norm_path("Users/jdoe/AppData/x.exe"), "users/jdoe/appdata/x.exe")
        self.assertEqual(norm_path("\\Device\\HarddiskVolume2\\Windows\\System32\\a.dll"), "windows/system32/a.dll")
        self.assertEqual(norm_path("\\SystemRoot\\System32\\ntoskrnl.exe"), "windows/system32/ntoskrnl.exe")

    def test_address_scopes(self) -> None:
        self.assertEqual(ip_scope("10.1.2.3"), "private")
        self.assertEqual(ip_scope("172.16.0.1"), "private")
        self.assertEqual(ip_scope("172.32.0.1"), "public")
        self.assertEqual(ip_scope("100.64.0.1"), "private")
        self.assertEqual(ip_scope("127.0.0.1"), "loopback")
        self.assertEqual(ip_scope("169.254.1.1"), "link_local")
        self.assertEqual(ip_scope("185.77.22.90"), "public")

    def test_timestamps_normalise_to_utc_and_never_invent(self) -> None:
        self.assertEqual(to_iso("2026-04-12T02:18:09Z"), "2026-04-12T02:18:09Z")
        self.assertEqual(to_iso("2026-04-12T07:48:09+05:30"), "2026-04-12T02:18:09Z")
        self.assertEqual(to_iso("2026-04-12T02:18:09.250Z"), "2026-04-12T02:18:09.250Z")
        self.assertEqual(to_iso("2026-04-12 02:18:09"), "2026-04-12T02:18:09Z")  # zone-less = UTC
        self.assertIsNone(to_iso("not-a-date"))
        self.assertIsNone(to_iso(None))
        self.assertIsNone(to_iso(""))

    def test_rounding_is_half_up(self) -> None:
        self.assertEqual(round2(0.125), 0.13)
        self.assertEqual(round2(0.55 + 0.10 + 0.15 + 0.10), 0.9)


class NormaliserTests(unittest.TestCase):
    def test_log_entities_come_from_fields_and_the_raw_line(self) -> None:
        n = normalise_log({
            "type": "Suspicious Command", "severity": "high", "lineNumber": 8, "user": "JDoe", "process": "powershell.exe",
            "rawLine": "powershell -enc ... download http://185.77.22.90/upd.exe to C:\\Users\\Public\\upd.exe",
            "timestamp": "2026-04-12T02:14:02Z",
        })
        e = n["entities"]
        self.assertIn("185.77.22.90", e["ips"])          # from the URL host
        self.assertIn("users/public/upd.exe", e["paths"])
        self.assertIn("upd", e["images"])
        self.assertIn("powershell", e["images"])
        self.assertEqual(e["users"], ["jdoe"])
        self.assertTrue(n["fact"].startswith("Log line 8:"))

    def test_network_type_sets_severity_when_the_agent_gives_none(self) -> None:
        self.assertEqual(normalise_network({"type": "Known Malicious IP", "ip": "1.2.3.4"})["severity"], "high")
        self.assertEqual(normalise_network({"type": "External Connection", "ip": "1.2.3.4"})["severity"], "low")
        n = normalise_network({"type": "External Connection", "ip": "8.8.8.8", "detail": "External communication from 192.168.56.10"})
        self.assertEqual(n["entities"]["ips"], ["8.8.8.8", "192.168.56.10"])

    def test_memory_accepts_envelope_and_ui_shapes(self) -> None:
        raw = normalise_memory({"title": "X", "severity": "HIGH", "confidence": 0.6,
                                "entities": {"processes": ["a.exe"], "pids": [1]}})
        ui = normalise_memory({"type": "X", "severity": "high", "confidence": 60,
                               "processes": ["a.exe"], "pids": [1]})
        for n in (raw, ui):
            self.assertEqual(n["severity"], "high")
            self.assertEqual(n["source_confidence"], 0.6)
            self.assertEqual(n["entities"]["images"], ["a"])


class LinkingTests(unittest.TestCase):
    @staticmethod
    def item(ref: str, domain: str, **entities: list) -> dict:
        base = {k: [] for k in ("ips", "domains", "urls", "images", "files", "paths", "users", "hosts", "pids", "ports")}
        base.update(entities)
        return {"ref": ref, "domain": domain, "entities": base}

    def test_only_cross_domain_entities_link_and_strength_follows_rarity(self) -> None:
        links = build_entity_index([
            self.item("LOG-1", "log", ips=["185.77.22.90", "10.0.0.5"], images=["svchost"], hosts=["ws01"]),
            self.item("NET-1", "network", ips=["185.77.22.90", "10.0.0.5"]),
            self.item("MEM-1", "memory", images=["svchost"], ips=["127.0.0.1"]),
            self.item("MEM-2", "memory", ips=["127.0.0.1"]),
        ])
        by_key = {l["key"]: l for l in links}
        self.assertEqual(by_key["ip:185.77.22.90"]["strength"], "strong")
        self.assertEqual(by_key["ip:10.0.0.5"]["strength"], "moderate")
        self.assertEqual(by_key["image:svchost"]["strength"], "weak")
        self.assertNotIn("ip:127.0.0.1", by_key)  # loopback never links, and is single-domain anyway
        self.assertNotIn("host:ws01", by_key)     # one domain only
        self.assertEqual(links[0]["key"], "ip:185.77.22.90")  # strongest first


if __name__ == "__main__":
    unittest.main()
