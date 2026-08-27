"""
Tests for the tolerant row readers.

These exist because Volatility's JSON keys are display column names, not
an API. The failure mode this guards against is silent: a column rename
after ``pip install -U volatility3`` produces empty observations, and
empty observations look exactly like a clean machine.
"""

from __future__ import annotations

import unittest
from datetime import datetime, timezone

from memory_agent.core.rows import (
    IndexedRow,
    as_bool,
    as_hex,
    as_int,
    as_str,
    normalise_key,
    parse_timestamp,
    pick,
    seconds_between,
    shift_iso,
)


class NormalisationTests(unittest.TestCase):
    def test_punctuation_and_case_are_ignored(self) -> None:
        for spelling in ("Offset(V)", "Offset (V)", "offset_v", "OFFSET-V"):
            self.assertEqual(normalise_key(spelling), "offsetv")

    def test_pick_takes_the_first_present_spelling(self) -> None:
        row = {"Pid": 4, "ImageFileName": "System"}
        self.assertEqual(pick(row, "PID", "Pid", "ProcessID"), 4)
        self.assertEqual(pick(row, "ImageFileName", "Process"), "System")
        self.assertIsNone(pick(row, "Nonexistent"))

    def test_pick_skips_a_present_but_null_value(self) -> None:
        row = {"Process": None, "ImageFileName": "svchost.exe"}
        self.assertEqual(pick(row, "Process", "ImageFileName"), "svchost.exe")

    def test_duplicate_normalised_keys_keep_the_first(self) -> None:
        row = {"Offset(V)": 1, "Offset (V)": 2}
        self.assertEqual(pick(row, "Offset(V)"), 1)


class IndexedRowTests(unittest.TestCase):
    def test_unmapped_reports_columns_never_asked_for(self) -> None:
        row = IndexedRow({"PID": 4, "Name": "System", "NewColumn": "x"})
        row.get_field("PID")
        row.get_field("Name")
        self.assertEqual(row.unmapped(), ["NewColumn"])

    def test_every_candidate_name_counts_as_known(self) -> None:
        # Asking for ImageFileName-or-Process means the extractor knows
        # both spellings; neither should be reported as an unknown column.
        row = IndexedRow({"Process": "a", "ImageFileName": "b"})
        row.get_field("ImageFileName", "Process")
        self.assertEqual(row.unmapped(), [])

    def test_structural_keys_are_not_data(self) -> None:
        row = IndexedRow({"PID": 4, "__depth": 2, "__parent_index": 0})
        row.get_field("PID")
        self.assertEqual(row.unmapped(), [])


class CoercionTests(unittest.TestCase):
    def test_hex_strings_become_integers(self) -> None:
        self.assertEqual(as_int("0x8a3f2040"), 0x8A3F2040)
        self.assertEqual(as_int("2456"), 2456)
        self.assertEqual(as_int("1,024"), 1024)

    def test_booleans_are_not_integers(self) -> None:
        # True is an int subclass in Python. Letting it through would turn
        # a Wow64 flag into a plausible-looking PID.
        self.assertIsNone(as_int(True))
        self.assertIsNone(as_int(False))

    def test_nullish_renderings(self) -> None:
        for value in ("", "-", "N/A", "n/a", "Disabled", None):
            self.assertIsNone(as_str(value))
            self.assertIsNone(as_int(value))

    def test_as_bool_round_trip(self) -> None:
        self.assertTrue(as_bool("True"))
        self.assertFalse(as_bool("no"))
        self.assertIsNone(as_bool("maybe"))

    def test_offsets_render_canonically(self) -> None:
        self.assertEqual(as_hex(0x400000), "0x400000")
        self.assertEqual(as_hex("0X400000"), "0x400000")


class TimestampTests(unittest.TestCase):
    def test_volatility_default_rendering(self) -> None:
        value, note = parse_timestamp("2026-04-12 02:18:03.000000 +0000")
        self.assertEqual(value, "2026-04-12T02:18:03Z")
        self.assertIsNone(note)

    def test_iso_with_offset_is_converted_to_utc(self) -> None:
        value, note = parse_timestamp("2026-04-12T04:18:03+02:00")
        self.assertEqual(value, "2026-04-12T02:18:03Z")
        self.assertIsNone(note)

    def test_naive_timestamp_is_flagged_not_silently_localised(self) -> None:
        value, note = parse_timestamp("2026-04-12 02:18:03")
        self.assertEqual(value, "2026-04-12T02:18:03Z")
        self.assertIsNotNone(note)
        self.assertIn("timezone", note)

    def test_trailing_zone_name_is_handled(self) -> None:
        value, _ = parse_timestamp("2026-04-12 02:18:03 UTC")
        self.assertEqual(value, "2026-04-12T02:18:03Z")

    def test_datetime_objects_pass_through(self) -> None:
        dt = datetime(2026, 4, 12, 2, 18, 3, tzinfo=timezone.utc)
        value, note = parse_timestamp(dt)
        self.assertEqual(value, "2026-04-12T02:18:03Z")
        self.assertIsNone(note)

    def test_implausible_epoch_is_rejected_rather_than_rendered(self) -> None:
        # A small integer in a timestamp column is a counter, not 1970.
        value, note = parse_timestamp(42)
        self.assertIsNone(value)
        self.assertIn("not a plausible date", note)

    def test_plausible_epoch_is_accepted_and_marked(self) -> None:
        value, note = parse_timestamp(1_776_000_000)
        self.assertIsNotNone(value)
        self.assertIn("epoch", note)

    def test_unparseable_value_returns_a_reason(self) -> None:
        value, note = parse_timestamp("last tuesday")
        self.assertIsNone(value)
        self.assertIn("unrecognised", note)

    def test_arithmetic_helpers(self) -> None:
        self.assertEqual(
            seconds_between("2026-04-12T02:18:03Z", "2026-04-12T02:18:00Z"), 3.0
        )
        self.assertEqual(
            shift_iso("2026-04-12T02:18:00Z", 63), "2026-04-12T02:19:03Z"
        )
        self.assertIsNone(seconds_between("nonsense", "2026-04-12T02:18:00Z"))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
