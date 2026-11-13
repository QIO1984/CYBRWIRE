"""World clock: your time plus reference cities"""

import os
import sys
import unittest
from datetime import datetime, timezone
from unittest import mock
from zoneinfo import ZoneInfo

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import isolated  # noqa: E402,F401

from cybrwire import clocks  # noqa: E402

NOW = datetime(2026, 11, 12, 22, 48, tzinfo=timezone.utc)  # Winter: no daylight saving anywhere shown


class Palette:
    accent = text = muted = "white"


class ClockTests(unittest.TestCase):
    def test_defaults_cover_the_reference_cities(self):
        self.assertEqual([label for label, _ in clocks.parse_clocks(None)], ["NYC", "LAX", "LON", "ROM", "SPB", "TYO"])

    def test_render_shows_each_city_and_marks_a_different_day(self):
        text = clocks.render(NOW, ZoneInfo("America/New_York"), clocks.parse_clocks(None), Palette()).plain
        self.assertTrue(text.startswith("LOC 17:48 EST"))
        for expected in ("NYC 17:48", "LAX 14:48", "LON 22:48", "ROM 23:48", "SPB 01:48+1", "TYO 07:48+1"):
            self.assertIn(expected, text)

    def test_an_80_column_window_gets_a_squeezed_line_that_still_fits(self):
        zones = clocks.parse_clocks(None)
        full = clocks.render(NOW, ZoneInfo("America/New_York"), zones, Palette())
        fitted = clocks.render(NOW, ZoneInfo("America/New_York"), zones, Palette(), 78)
        self.assertGreater(full.cell_len, 78)
        self.assertLessEqual(fitted.cell_len, 78)
        self.assertIn("TYO 07:48+1", fitted.plain)  # Every city is still there
        tiny = clocks.render(NOW, ZoneInfo("America/New_York"), zones, Palette(), 40)
        self.assertLess(tiny.cell_len, full.cell_len)  # Too narrow for everything: the tightest layout

    def test_your_own_cities_in_any_of_three_shapes(self):
        shapes = ["Tokyo: Asia/Tokyo", {"label": "syd", "zone": "Australia/Sydney"}, {"par": "Europe/Paris"}]
        self.assertEqual([label for label, _ in clocks.parse_clocks(shapes)], ["TOKY", "SYD", "PAR"])

    def test_bad_zones_are_skipped_and_nothing_usable_means_defaults(self):
        self.assertEqual([label for label, _ in clocks.parse_clocks(["OK: Asia/Tokyo", "BAD: Nowhere/City"])], ["OK"])
        self.assertEqual(len(clocks.parse_clocks(["BAD: Nowhere/City", 5])), 6)
        self.assertEqual(len(clocks.parse_clocks("not a list")), 6)

    def test_local_zone_prefers_tz_then_setting_then_machine(self):
        with mock.patch.dict(os.environ, {"TZ": "Asia/Tokyo"}):
            self.assertEqual(str(clocks.local_zone("Europe/Rome")), "Asia/Tokyo")
        with mock.patch.dict(os.environ, {"TZ": "Nowhere/City"}):
            self.assertEqual(str(clocks.local_zone("Europe/Rome")), "Europe/Rome")
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("TZ", None)
            self.assertIsNotNone(clocks.local_zone(None))


if __name__ == "__main__":
    unittest.main()
