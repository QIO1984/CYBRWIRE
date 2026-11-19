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


def _blend_hex(color, ground, keep):
    return worldmap._blend(color, ground, keep)


def channels(color):
    return [int(color[i:i + 2], 16) for i in (1, 3, 5)]


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
    def test_fit_never_exceeds_the_room_and_keeps_within_the_allowed_stretch(self):
        for width, height in ((100, 24), (45, 30), (200, 10), (300, 20), (30, 30), (10, 10)):
            cols, rows = worldmap.fit(width, height)
            self.assertGreaterEqual(rows, worldmap.MIN_ROWS)
            self.assertGreaterEqual(cols, rows * 5)
            self.assertLessEqual(cols, int(rows * 5 * worldmap.STRETCH))
            if width >= worldmap.MIN_ROWS * 5 and height >= worldmap.MIN_ROWS:
                self.assertLessEqual(cols, width)
                self.assertLessEqual(rows, height)

    def test_a_wide_short_area_is_filled_by_stretching_the_map(self):
        cols, rows = worldmap.fit(150, 20)
        self.assertEqual(rows, 20)
        self.assertEqual(cols, 150)  # 100 columns is true shape; 150 is the most it stretches
        cols, rows = worldmap.fit(400, 20)
        self.assertEqual((cols, rows), (150, 20))  # Past that it stays put and is centred

    def test_an_area_with_room_to_spare_in_height_keeps_the_true_shape(self):
        self.assertEqual(worldmap.fit(100, 60), (100, 20))

    def test_render_makes_exactly_cols_by_rows_cells(self):
        for cols, rows in ((100, 20), (45, 9), (25, 5)):
            lines = worldmap.render(cols, rows, [], 0, NEON).plain.split("\n")
            self.assertEqual(len(lines), rows)
            self.assertTrue(all(len(line) == cols for line in lines))

    def test_the_continents_show_up_as_braille_and_water_stays_blank(self):
        lines = worldmap.render(100, 20, [], 0, NEON).plain.split("\n")
        self.assertTrue(all(0x2800 <= ord(ch) <= 0x28FF or ch in " ☼" for line in lines for ch in line))  # Land, water and the sun
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

    def test_a_radar_sweep_moves_across_the_land_without_changing_the_drawing(self):
        a, b = worldmap.render(100, 20, [], 5, NEON), worldmap.render(100, 20, [], 40, NEON)
        self.assertEqual(a.plain, b.plain)                       # Same land
        self.assertNotEqual([str(sp.style) for sp in a.spans], [str(sp.style) for sp in b.spans])  # Brightened elsewhere

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


class DayAndNight(unittest.TestCase):
    NOON_UTC = datetime(2026, 3, 20, 12, 0, tzinfo=timezone.utc)      # Near the equinox, the sun is over longitude 0
    MIDNIGHT_UTC = datetime(2026, 3, 20, 0, 0, tzinfo=timezone.utc)   # ...and over 180 twelve hours later

    def test_the_sun_is_over_the_right_place(self):
        lat, lon = worldmap.sun_position(self.NOON_UTC)
        self.assertAlmostEqual(lat, 0, delta=2.5)
        self.assertAlmostEqual(lon, 0, delta=1)
        lat, lon = worldmap.sun_position(self.MIDNIGHT_UTC)
        self.assertAlmostEqual(abs(lon), 180, delta=1)
        june = worldmap.sun_position(datetime(2026, 6, 21, 12, 0, tzinfo=timezone.utc))[0]
        december = worldmap.sun_position(datetime(2026, 12, 21, 12, 0, tzinfo=timezone.utc))[0]
        self.assertAlmostEqual(june, 23.4, delta=1.5)
        self.assertAlmostEqual(december, -23.4, delta=1.5)

    def test_daylight_is_full_under_the_sun_and_zero_opposite_it(self):
        sun = worldmap.sun_position(self.NOON_UTC)
        self.assertEqual(worldmap.daylight(0, 0, sun), 1.0)
        self.assertEqual(worldmap.daylight(0, 180, sun), 0.0)
        self.assertEqual(worldmap.daylight(0, 90, sun), 0.0 + worldmap.daylight(0, 90, sun))  # A quarter turn is dusk or dawn
        self.assertTrue(0 < worldmap.daylight(0, 95, sun) < 1 or worldmap.daylight(0, 95, sun) in (0.0, 1.0))

    def brightness_at(self, text, lat, lon, cols=100, rows=20):
        r, c = worldmap.cell_of(Spot(lat, lon, "victim", "X"), cols, rows)
        offset = sum(len(line) + 1 for line in text.plain.split("\n")[:r]) + c
        style = next(span.style for span in reversed(text.spans) if span.start <= offset < span.end)
        return sum(channels(str(style).split()[-1] if " " in str(style) else str(style)))

    def test_the_night_side_is_dimmer_and_the_picture_otherwise_the_same(self):
        noon = worldmap.render(100, 20, [], 0, NEON, when=self.NOON_UTC)
        midnight = worldmap.render(100, 20, [], 0, NEON, when=self.MIDNIGHT_UTC)
        self.assertEqual(noon.plain.replace("☼", " "), midnight.plain.replace("☼", " "))
        # Africa is in daylight at noon UTC and in the dark at midnight; the Pacific the other way round
        self.assertGreater(self.brightness_at(noon, 5, 20), self.brightness_at(midnight, 5, 20))
        self.assertGreater(self.brightness_at(midnight, -25, 134), self.brightness_at(noon, -25, 134))

    def test_a_sun_marks_where_it_is_noon(self):
        text = worldmap.render(100, 20, [], 0, NEON, when=self.NOON_UTC).plain
        self.assertIn("☼", text)
        row = next(line for line in text.split("\n") if "☼" in line)
        self.assertAlmostEqual(row.index("☼"), 50, delta=3)  # Longitude 0 is the middle of the map

    def test_shading_works_in_the_cold_war_look_too(self):
        worldmap.render(100, 20, [], 0, COLD_WAR, when=self.NOON_UTC)


class Arcs(unittest.TestCase):
    def apt(self, title, hours=1):
        return alert(title, hours=hours, severity="apt")

    def test_an_arc_runs_from_the_attributed_country_to_each_other_country_named(self):
        alerts = [self.apt("China-linked APT41 targets Taiwan telecoms"),
                  self.apt("Russia-linked hackers hit US and German ministries"),
                  self.apt("Chinese hackers breach Taiwan semiconductor firm")]
        arcs = {(a.source, a.target): a.count for a in worldmap.gather_arcs(alerts, NOW)}
        self.assertEqual(arcs, {("CN", "TW"): 2, ("RU", "US"): 1, ("RU", "DE"): 1})

    def test_nothing_is_drawn_without_a_named_target_or_attribution_or_in_time(self):
        alerts = [self.apt("Lazarus group steals crypto"),                       # No target named
                  alert("China hits Taiwan", severity="info"),       # Not an APT story
                  self.apt("China-linked group hits Taiwan", hours=24 * 9),     # Too old
                  self.apt("Iran-linked group attacks Iran water plants")]      # The only country named is its own
        self.assertEqual(worldmap.gather_arcs(alerts, NOW), [])

    def test_us_the_pronoun_is_not_the_united_states(self):
        self.assertEqual(worldmap.gather_arcs([self.apt("Chinese hackers target us all, researchers say")], NOW), [])
        self.assertEqual([a.target for a in worldmap.gather_arcs([self.apt("Chinese hackers target the US power grid")], NOW)], ["US"])

    def test_north_korea_is_not_south_korea_and_arcs_are_capped_busiest_first(self):
        arcs = worldmap.gather_arcs([self.apt("North Korean hackers target South Korean banks")] * 3, NOW)
        self.assertEqual([(a.source, a.target) for a in arcs], [("KP", "KR")])
        many = [self.apt(f"Chinese APT hits {name}") for name in ("Japan", "Taiwan", "India", "Canada", "France", "Spain", "Italy",
                                                                 "Poland", "Sweden", "Norway", "Brazil", "Mexico")]
        self.assertEqual(len(worldmap.gather_arcs(many, NOW)), 8)

    def test_arcs_only_use_open_water_and_leave_every_land_cell_exactly_as_it_was(self):
        arc = [worldmap.Arc("CN", "US", 2)]
        plain = worldmap.render(100, 20, [], 0, NEON, when=NOW)
        for step in range(0, 60, 7):
            drawn = worldmap.render(100, 20, [], step, NEON, when=NOW, arcs=arc)
            self.assertNotEqual(drawn.plain, plain.plain)  # Something is drawn over the Pacific
            for before, after in zip(plain.plain, drawn.plain):
                if before != " " and before != "\u2800":
                    self.assertEqual(before, after, "an arc changed a land cell")

    def test_an_arc_is_a_smooth_connected_bow_between_its_two_countries(self):
        dots = worldmap.arc_dots(worldmap.COUNTRIES["CN"], worldmap.COUNTRIES["US"], 100, 20)
        self.assertGreater(len(dots), 40)
        for (x0, y0), (x1, y1) in zip(dots, dots[1:]):
            self.assertLessEqual(max(abs(x1 - x0), abs(y1 - y0)), 2)   # No gaps: one smooth line
        start = worldmap.arc_dots(worldmap.COUNTRIES["CN"], worldmap.COUNTRIES["CN"], 100, 20)
        self.assertLess(len(start), 8)

    def test_an_arc_bows_above_both_of_its_ends(self):
        for source, target in (("CN", "US"), ("RU", "DE"), ("RU", "US"), ("CN", "GB")):
            dots = worldmap.arc_dots(worldmap.COUNTRIES[source], worldmap.COUNTRIES[target], 100, 20)
            self.assertLess(min(y for _x, y in dots), min(dots[0][1], dots[-1][1]), f"{source}->{target}")

    def test_a_bright_stretch_travels_along_the_arc(self):
        arc = [worldmap.Arc("CN", "US", 1)]
        def bright_cells(step):
            text = worldmap.render(100, 20, [], step, NEON, when=NOW, arcs=arc)
            full = _blend_hex(NEON.apt, NEON.bg, 1.0)
            offsets = {span.start for span in text.spans if str(span.style) == full}
            return frozenset(offsets)
        seen = {bright_cells(step) for step in range(0, 150, 3)}
        self.assertGreater(len(seen), 8)  # The bright part is in a different place each time

    def test_arcs_do_not_cover_markers(self):
        us = Spot(*worldmap.COUNTRIES["US"], "victim", "US", 9)
        text = worldmap.render(100, 20, [us], 0, NEON, arcs=[worldmap.Arc("CN", "US", 1)]).plain
        self.assertTrue(any(glyph in text for glyph in worldmap.PULSE))

    def test_the_legend_names_the_busiest_pairs_and_stays_the_same_without_arcs(self):
        arcs = [worldmap.Arc("CN", "TW", 3), worldmap.Arc("RU", "UA", 2)]
        with_arcs = [line.plain for line in worldmap.legend([], NEON, width=100, arcs=arcs)]
        without = [line.plain for line in worldmap.legend([], NEON, width=100)]
        self.assertEqual(len(with_arcs), len(without) + 1)
        self.assertTrue(any("Attributed targets  5" in line and "China → Taiwan" in line for line in with_arcs))



if __name__ == "__main__":
    unittest.main()
