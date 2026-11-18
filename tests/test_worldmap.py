"""The world map: land mask, placement, pulsing markers, and what the alerts put on it"""

import os
import sys
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import isolated  # noqa: E402,F401
from cybrwire import worldmap  # noqa: E402
from cybrwire.theme import COLD_WAR, PALETTES  # noqa: E402
from cybrwire.worldmap import Spot  # noqa: E402

NOW = datetime.now(timezone.utc)
NEON = PALETTES["neon"]


def alert(title, source="Feed", kind="news", hours=1, **extra):
    return {"title": title, "source": source, "kind": kind, "ts": NOW - timedelta(hours=hours), **extra}


def land_at(lat, lon):
    row = int((worldmap.LAT_TOP - lat) / (worldmap.LAT_TOP - worldmap.LAT_BOTTOM) * worldmap.DOTS_HIGH)
    col = int((lon + 180) / 360 * worldmap.DOTS_WIDE)
    return worldmap.is_land(row, col)


class LandMask(unittest.TestCase):
    def test_the_mask_has_the_expected_size_and_land(self):
        self.assertEqual(len(worldmap._MASK) * 8, worldmap.DOTS_WIDE * worldmap.DOTS_HIGH)
        count = sum(worldmap.is_land(r, c) for r in range(worldmap.DOTS_HIGH) for c in range(worldmap.DOTS_WIDE))
        self.assertGreater(count, 4000)
        self.assertLess(count, 6000)

    def test_known_places_are_land_or_water(self):
        for name, lat, lon in (("Kansas", 39, -98), ("Germany", 51, 10), ("Sahara", 25, 10), ("Australia", -25, 134),
                               ("Brazil", -10, -52), ("India", 22, 79), ("Japan", 36, 138)):
            self.assertTrue(land_at(lat, lon), name)
        for name, lat, lon in (("mid-Atlantic", 30, -40), ("mid-Pacific", 0, -150), ("Indian Ocean", -30, 80)):
            self.assertFalse(land_at(lat, lon), name)

    def test_every_country_and_service_sits_inside_the_map(self):
        for code, (lat, lon) in worldmap.COUNTRIES.items():
            self.assertTrue(worldmap.LAT_BOTTOM <= lat <= worldmap.LAT_TOP and -180 <= lon <= 180, code)
        for name, (_place, lat, lon) in worldmap.SERVICE_HOMES.items():
            self.assertTrue(worldmap.LAT_BOTTOM <= lat <= worldmap.LAT_TOP and -180 <= lon <= 180, name)


class Layout(unittest.TestCase):
    def test_fit_keeps_the_shape_and_never_exceeds_the_room(self):
        for width, height in ((100, 24), (45, 30), (200, 10), (30, 30), (10, 10)):
            cols, rows = worldmap.fit(width, height)
            self.assertEqual(cols, rows * 5)
            self.assertGreaterEqual(rows, worldmap.MIN_ROWS)
            if width >= worldmap.MIN_ROWS * 5 and height >= worldmap.MIN_ROWS:
                self.assertLessEqual(cols, width)
                self.assertLessEqual(rows, height)

    def test_render_makes_exactly_cols_by_rows_cells(self):
        for cols, rows in ((100, 20), (45, 9), (25, 5)):
            lines = worldmap.render(cols, rows, [], 0, NEON).plain.split("\n")
            self.assertEqual(len(lines), rows)
            self.assertTrue(all(len(line) == cols for line in lines))

    def test_the_continents_show_up_as_braille_and_water_stays_blank(self):
        lines = worldmap.render(100, 20, [], 0, NEON).plain.split("\n")
        self.assertTrue(all(0x2800 <= ord(ch) <= 0x28FF or ch == " " for line in lines for ch in line))
        self.assertGreater(sum(ch != " " for line in lines for ch in line), 500)
        self.assertEqual(lines[10][40:44], "    ")  # Open Atlantic


class Markers(unittest.TestCase):
    def cell(self, text, spot, cols=100, rows=20):
        r, c = worldmap.cell_of(spot, cols, rows)
        return text.plain.split("\n")[r][c]

    def test_a_victim_marker_pulses_through_its_glyphs(self):
        us = Spot(39, -98, "victim", "US", 14)
        seen = {self.cell(worldmap.render(100, 20, [us], step, NEON), us) for step in range(4)}
        self.assertEqual(seen, set(worldmap.PULSE))

    def test_markers_are_out_of_step_with_each_other(self):
        spots = [Spot(*worldmap.COUNTRIES[code], "victim", code, 3) for code in ("US", "DE", "BR", "IN", "AU", "JP")]
        text = worldmap.render(100, 20, spots, 0, NEON)
        self.assertGreater(len({self.cell(text, s) for s in spots}), 1)  # Not all showing the same step at once

    def test_an_outage_is_a_steady_diamond_in_the_warning_colour(self):
        aws = Spot(38.9, -77.4, "outage", "AWS")
        for step in range(3):
            text = worldmap.render(100, 20, [aws], step, NEON)
            self.assertEqual(self.cell(text, aws), "◆")
        r, c = worldmap.cell_of(aws, 100, 20)
        offset = sum(len(line) + 1 for line in text.plain.split("\n")[:r]) + c
        style = next(span.style for span in text.spans if span.start <= offset < span.end)
        self.assertIn(NEON.warn, str(style))

    def test_a_marker_outside_the_map_is_skipped(self):
        self.assertIsNone(worldmap.cell_of(Spot(-80, 0, "victim", "AQ"), 100, 20))
        worldmap.render(100, 20, [Spot(-80, 0, "victim", "AQ")], 0, NEON)  # Doesn't raise

    def test_labels_fit_and_never_overlap_each_other_or_markers(self):
        spots = [Spot(39, -98, "victim", "US", 14), Spot(38.9, -77.4, "outage", "AWS"), Spot(54, -2, "victim", "GB", 5),
                 Spot(51, 10, "victim", "DE", 6), Spot(46, 2, "victim", "FR", 4)]
        text = worldmap.render(100, 20, spots, 0, NEON).plain
        self.assertEqual({len(line) for line in text.split("\n")}, {100})
        for label in ("US 14", "DE 6"):
            self.assertIn(label, text)

    def test_a_small_map_leaves_its_markers_unlabelled_and_a_big_one_names_them(self):
        spots = [Spot(39, -98, "victim", "US", 14)]
        self.assertNotIn("US 14", worldmap.render(45, 9, spots, 0, NEON).plain)
        self.assertIn("US 14", worldmap.render(100, 20, spots, 0, NEON).plain)

    def test_the_cold_war_palette_draws_too(self):
        text = worldmap.render(60, 12, [Spot(39, -98, "victim", "US", 3)], 1, COLD_WAR)
        self.assertEqual(len(text.plain.split("\n")), 12)


class FromAlerts(unittest.TestCase):
    def test_victims_are_counted_by_country_and_ignore_old_or_unknown(self):
        alerts = [alert("RANSOMWARE VICTIM: A (lockbit) [US]"), alert("RANSOMWARE VICTIM: B (play) [US]"),
                  alert("RANSOMWARE VICTIM: C (play) [DE]"), alert("RANSOMWARE VICTIM: D (play) [ZZ]"),
                  alert("RANSOMWARE VICTIM: E (play)"), alert("RANSOMWARE VICTIM: F (play) [FR]", hours=24 * 9),
                  alert("Some news story")]
        spots = {s.label: s for s in worldmap.gather_spots(alerts, NOW)}
        self.assertEqual({k: v.count for k, v in spots.items()}, {"US": 2, "DE": 1})
        self.assertTrue(all(s.kind == "victim" for s in spots.values()))

    def test_active_outages_group_by_home_and_resolved_ones_are_left_out(self):
        alerts = [alert("OUTAGE · Cloudflare: errors", "Cloudflare Status", "outage"),
                  alert("OUTAGE · GitHub: slow", "GitHub Status", "outage"),
                  alert("OUTAGE · AWS: gone", "AWS Status", "outage", resolved=True),
                  alert("OUTAGE · Azure: degraded", "Azure Status", "outage"),
                  alert("OUTAGE · Unknown: x", "Mystery Status", "outage")]
        spots = worldmap.gather_spots(alerts, NOW)
        by_label = {s.label: s for s in spots}
        self.assertEqual(set(by_label), {"Cloudflare, GitHub", "Azure"})
        self.assertEqual(by_label["Cloudflare, GitHub"].count, 2)

    def test_actors_come_from_attribution_in_apt_headlines_and_advisories_from_the_issuing_source(self):
        alerts = [alert("China-linked APT41 targets telecoms", "BleepingComputer", severity="apt"),
                  alert("Lazarus group steals crypto", "The Hacker News", severity="apt"),
                  alert("Fancy Bear phishing wave", "Krebs", severity="apt"),
                  alert("Russia strikes a bank (not tagged APT)", "Krebs", severity="info"),
                  alert("Advisory A", "CISA Advisories", "advisory"), alert("Advisory B", "CISA KEV", "advisory"),
                  alert("Advisory C", "JPCERT/CC", "advisory"), alert("Old", "NCSC UK Alerts", "advisory", hours=24 * 9)]
        spots = worldmap.gather_spots(alerts, NOW)
        actors = {s.label: s.count for s in spots if s.kind == "actor"}
        advisories = {s.label: s.count for s in spots if s.kind == "advisory"}
        self.assertEqual(actors, {"CN": 1, "KP": 1, "RU": 1})
        self.assertEqual(advisories, {"US": 2, "JP": 1})

    def test_the_legend_has_one_line_per_layer_with_totals_and_the_busiest_places(self):
        spots = [Spot(0, 0, "victim", "US", 9), Spot(0, 0, "victim", "DE", 3), Spot(0, 0, "outage", "AWS", 1),
                 Spot(0, 0, "actor", "CN", 4), Spot(0, 0, "advisory", "GB", 6)]
        lines = [line.plain for line in worldmap.legend(spots, NEON, width=100)]
        text = "\n".join(lines)
        self.assertEqual(len(lines), len(worldmap.LAYERS) + 1)  # A line per layer, then the note
        for expected in ("Ransomware victims  12", "United States 9", "Active outages  1", "AWS", "Attributed activity  4",
                         "China 4", "National advisories  6", "United Kingdom 6"):
            self.assertIn(expected, text)

    def test_every_legend_line_fits_a_narrow_panel(self):
        spots = [Spot(0, 0, "victim", c, 3) for c in ("US", "DE", "GB", "FR")] + [Spot(0, 0, "outage", "Cloudflare, GitHub; AWS, Azure, Slack", 5)]
        for width in (40, 56, 100):
            self.assertTrue(all(line.cell_len <= width for line in worldmap.legend(spots, NEON, width=width)), width)

    def test_an_empty_legend_still_shows_every_layer_at_zero(self):
        text = "\n".join(line.plain for line in worldmap.legend([], NEON))
        for _name, _glyph, label, _role in worldmap.LAYERS:
            self.assertIn(f"{label}  0", text)

    def test_markers_that_share_a_country_are_nudged_apart_so_every_layer_shows(self):
        spots = [Spot(*worldmap.COUNTRIES["US"], kind, "US", 3) for kind in ("victim", "advisory", "actor", "outage")]
        text = worldmap.render(100, 20, spots, 0, NEON).plain
        self.assertIn("◆", text)
        self.assertIn("■", text)
        self.assertTrue("▲" in text or "△" in text)  # The attributed-activity marker pulses between the two
        self.assertTrue(any(ch in text for ch in worldmap.PULSE))

    def test_the_layers_use_different_colours(self):
        roles = [getattr(NEON, role) for *_rest, role in worldmap.LAYERS]
        self.assertEqual(len(set(roles)), len(roles))


if __name__ == "__main__":
    unittest.main()
