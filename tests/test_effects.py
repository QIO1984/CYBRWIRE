"""The atmosphere: the arrival flash and the effects switch"""

import os
import sqlite3
import sys
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import isolated  # noqa: E402,F401
from cybrwire import ai, history  # noqa: E402
from cybrwire import app as cybrwire_app  # noqa: E402
from cybrwire.config import Config  # noqa: E402
from cybrwire.evidence import CONFIRMED, Evidence  # noqa: E402
from cybrwire.theme import PALETTES  # noqa: E402

NEON = PALETTES["neon"]
NOW = datetime.now(timezone.utc)


def alert(title, severity="info", source="Feed", hours=1, **extra):
    return {"title": title, "summary": "", "source": source, "kind": "news", "severity": severity,
            "url": f"https://example.test/{abs(hash(title))}", "ts": NOW - timedelta(hours=hours), **extra}


def edge(app):
    """The style of the outline round the window: "" when there is none"""
    return app.screen.styles.outline[0][0]


class InTheApp(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        for patcher in (mock.patch.object(ai, "generate", side_effect=AssertionError("no AI in tests")),
                        mock.patch("cybrwire.links.webbrowser.open"),
                        mock.patch("httpx.AsyncClient.get", mock.AsyncMock(side_effect=OSError("no network in tests")))):
            patcher.start()
            self.addCleanup(patcher.stop)
        cybrwire_app.CONFIG = Config(sources=[], timezone="UTC")
        cybrwire_app.STATE.settings = {"filter_type_index": 0, "alerts_default": True}
        cybrwire_app.alert_queue[:] = [alert("CISA adds a flaw to KEV", "critical", "CISA KEV"), alert("Routine post")]
        cybrwire_app.HISTORY.record([])
        conn = sqlite3.connect(history.HISTORY_PATH)
        with conn:
            conn.execute("DELETE FROM alerts")
        conn.close()

    def make_app(self):
        app = cybrwire_app.CybrWireApp()

        async def fake_load():
            app.pop_screen()
            app.is_loading = False
            app.update_display()

        app.initial_load = fake_load
        return app

    async def settle(self, pilot):
        await pilot.pause()
        await pilot.pause()






    async def test_an_urgent_arrival_pulses_the_edge_once_and_clears_it(self):
        app = self.make_app()
        urgent = alert("CVE-2099-1 added to KEV", "critical", evidence=Evidence(CONFIRMED, 150, ["CISA KEV today"], recent=True))
        async with app.run_test(size=(120, 40)) as pilot:
            await self.settle(pilot)
            app.arrival_effect([alert("Nothing special")])
            await pilot.pause(0.1)
            self.assertEqual(edge(app), "")
            app.arrival_effect([urgent])
            await pilot.pause(0.1)
            self.assertEqual(edge(app), "heavy")
            await pilot.pause(1.6)
            self.assertEqual(edge(app), "")

    async def test_cold_war_adds_a_flash_banner_that_goes_away(self):
        app = self.make_app()
        urgent = alert("CVE-2099-2 added to KEV", "critical", evidence=Evidence(CONFIRMED, 150, ["CISA KEV today"], recent=True))
        async with app.run_test(size=(120, 40)) as pilot:
            await self.settle(pilot)
            app.arrival_effect([urgent])
            await pilot.pause(0.1)
            self.assertFalse(app.query_one("#flash-banner").display)  # Only in Cold War mode
            app.cold_war_mode = True
            await self.settle(pilot)
            app.arrival_effect([urgent])
            await pilot.pause(0.3)
            self.assertTrue(app.query_one("#flash-banner").display)
            await pilot.pause(2.3)
            self.assertFalse(app.query_one("#flash-banner").display)

    async def test_no_flash_with_effects_off(self):
        app = self.make_app()
        urgent = alert("CVE-2099-3 added to KEV", "critical", evidence=Evidence(CONFIRMED, 150, ["CISA KEV today"], recent=True))
        async with app.run_test(size=(120, 40)) as pilot:
            await self.settle(pilot)
            app.effects_on = False
            app.cold_war_mode = True
            app.arrival_effect([urgent])
            await pilot.pause(0.3)
            self.assertFalse(app.query_one("#flash-banner").display)
            self.assertEqual(edge(app), "")

    async def test_kiosk_mode_rotates_the_views_only_when_nobody_is_using_the_app(self):
        app = self.make_app()
        async with app.run_test(size=(120, 40)) as pilot:
            await self.settle(pilot)
            self.assertEqual(app.main_view_mode, "map")
            app.kiosk_tick()
            self.assertEqual(app.main_view_mode, "map")  # Off by default
            await pilot.press("k")
            await self.settle(pilot)
            self.assertTrue(app.kiosk_on)
            self.assertTrue(cybrwire_app.STATE.settings["kiosk"])
            self.assertIn("kiosk on", plain_text(app.hint_bar([("x", "y")])))
            app.kiosk_tick()
            self.assertEqual(app.main_view_mode, "map")  # You just pressed a key: it waits
            app.last_input -= 1000
            app.kiosk_last_move -= 1000
            app.kiosk_tick()
            self.assertEqual(app.main_view_mode, "alerts")
            app.kiosk_tick()
            self.assertEqual(app.main_view_mode, "alerts")  # Thirty seconds on each view
            for expected in ("incidents", "map", "alerts"):
                app.kiosk_last_move -= 1000
                app.kiosk_tick()
                self.assertEqual(app.main_view_mode, expected)

    async def test_kiosk_mode_leaves_tools_cards_and_typing_alone_and_any_input_pauses_it(self):
        app = self.make_app()
        async with app.run_test(size=(120, 40)) as pilot:
            await self.settle(pilot)
            app.kiosk_on = True
            app.last_input -= 1000
            app.kiosk_last_move -= 1000
            app.main_view_mode = "api_tools"
            app.kiosk_tick()
            self.assertEqual(app.main_view_mode, "api_tools")
            app.main_view_mode = "map"
            app.prompt = "search"
            app.kiosk_tick()
            self.assertEqual(app.main_view_mode, "map")
            app.prompt = None
            await pilot.press("h")  # The help screen is open
            await self.settle(pilot)
            app.last_input -= 1000
            app.kiosk_tick()
            self.assertEqual(app.main_view_mode, "map")
            await pilot.press("escape")
            await self.settle(pilot)
            app.last_input -= 1000
            app.kiosk_last_move -= 1000
            await pilot.press("space")  # Input pauses it again
            await self.settle(pilot)
            app.kiosk_tick()
            self.assertEqual(app.main_view_mode, "map")

    async def test_kiosk_mode_is_remembered_between_launches(self):
        cybrwire_app.STATE.settings = {"kiosk": True, "alerts_default": True}
        self.assertTrue(cybrwire_app.CybrWireApp().kiosk_on)
        cybrwire_app.STATE.settings = {"alerts_default": True}
        self.assertFalse(cybrwire_app.CybrWireApp().kiosk_on)

    async def test_urgent_new_alerts_type_themselves_into_the_feed(self):
        app = self.make_app()
        urgent = alert("CISA adds a long vulnerability title to KEV today", "critical", "CISA KEV",
                       evidence=Evidence(CONFIRMED, 150, ["CISA KEV today"], recent=True))
        cybrwire_app.alert_queue[:] = [urgent, alert("Routine post")]
        async with app.run_test(size=(140, 40)) as pilot:
            await self.settle(pilot)
            app.main_view_mode = "alerts"
            app.update_display()
            app.arrival_effect([urgent])
            await self.settle(pilot)
            self.assertIn(cybrwire_app.alert_key(urgent), app.typing)
            full = urgent["title"]
            first = app.feed_title_cell(urgent, False).plain.strip()  # The clock starts at the first draw
            self.assertTrue(first.endswith("▌") or first.endswith(full))
            key = cybrwire_app.alert_key(urgent)
            app.typing[key] = cybrwire_app.time.monotonic() - 0.2   # About nine characters in
            partial = app.feed_title_cell(urgent, False).plain
            self.assertIn("▌", partial)
            self.assertNotIn(full, partial)
            self.assertTrue(full.startswith(partial.replace("▌", "").strip().split("  ")[-1][:6]))
            app.typing[key] = cybrwire_app.time.monotonic() - 10     # Long finished
            self.assertIn(full, app.feed_title_cell(urgent, False).plain)
            app.typing_tick()
            self.assertNotIn(key, app.typing)  # Forgotten once it has finished typing

    async def test_a_typing_row_is_redrawn_in_place(self):
        app = self.make_app()
        urgent = alert("A fairly long urgent headline that takes a moment to type in", "critical", "CISA KEV",
                       evidence=Evidence(CONFIRMED, 150, ["CISA KEV today"], recent=True))
        cybrwire_app.alert_queue[:] = [urgent]
        async with app.run_test(size=(140, 40)) as pilot:
            await self.settle(pilot)
            app.main_view_mode = "alerts"
            app.update_display()
            await self.settle(pilot)
            app.typing[cybrwire_app.alert_key(urgent)] = cybrwire_app.time.monotonic() - 0.3
            app.typing_tick()
            table = app.query_one("#feed-table")
            shown = table.get_row_at(0)[3].plain
            self.assertIn("▌", shown)
            self.assertLess(len(shown.replace("▌", "").strip()), len(urgent["title"]))

    async def test_nothing_types_with_effects_off_or_for_ordinary_alerts(self):
        app = self.make_app()
        urgent = alert("CVE added to KEV", "critical", "CISA KEV", evidence=Evidence(CONFIRMED, 150, ["CISA KEV today"], recent=True))
        async with app.run_test(size=(140, 40)) as pilot:
            await self.settle(pilot)
            app.effects_on = False
            app.start_typing([urgent])
            self.assertEqual(app.typing, {})
            app.effects_on = True
            app.arrival_effect([alert("Routine")])
            self.assertEqual(app.typing, {})
            app.start_typing([alert(f"urgent {i}", "critical", evidence=Evidence(CONFIRMED, 1, [], recent=True)) for i in range(10)])
            self.assertEqual(len(app.typing), 3)  # At most three at a time

    async def test_the_title_bar_carries_a_heartbeat_out_both_sides_and_stays_plain_in_the_period_simulations(self):
        from cybrwire.chrome import StyledHeader
        app = self.make_app()
        async with app.run_test(size=(140, 40)) as pilot:
            await self.settle(pilot)
            app.set_theme_by_key("neon")
            header = app.query_one(StyledHeader)
            app.heartbeat_tick()
            line = header.line().plain
            title = app.title.strip()
            self.assertEqual(len(line), 140)                                   # Exactly as wide as the window
            left, _, rest = line.partition("  " + title + "  ")
            right = rest[:len(left)]
            self.assertTrue(left and all("\u2800" <= ch <= "\u28ff" for ch in left))
            self.assertTrue(all("\u2800" <= ch <= "\u28ff" for ch in right))
            self.assertEqual(len(left), len(right))                              # Symmetrical about the title
            self.assertRegex(line[-10:], r"^ \d\d:\d\d:\d\d $")                  # The clock is at the right end
            for _ in range(4):
                app.heartbeat_tick()
            self.assertNotEqual(header.line().plain, line)                       # It moves
            app.effects_on = False
            app.heartbeat_tick()
            plain = header.line().plain
            self.assertFalse(any("\u2800" <= ch <= "\u28ff" for ch in plain))
            self.assertIn(title, plain)
            app.effects_on = True
            for key in ("amber_crt",):
                app.set_theme_by_key(key)
                app.heartbeat_tick()
                self.assertFalse(any("\u2800" <= ch <= "\u28ff" for ch in header.line().plain), key)
            app.set_theme_by_key("neon")
            await pilot.press("c")
            await self.settle(pilot)
            app.heartbeat_tick()
            self.assertFalse(any("\u2800" <= ch <= "\u28ff" for ch in header.line().plain))  # Cold War keeps its banner plain

    def test_the_two_sides_are_mirror_images_and_the_beats_travel_outward(self):
        from cybrwire import effects
        def mirror(char):  # Swap the left and right dot columns of a braille cell
            bits = ord(char) - 0x2800
            out = 0
            for a, b in ((0x01, 0x08), (0x02, 0x10), (0x04, 0x20), (0x40, 0x80)):
                out |= (b if bits & a else 0) | (a if bits & b else 0)
            return chr(0x2800 + out)
        right = effects.ecg_side(7, 30, 20, "right")
        left = effects.ecg_side(7, 30, 20, "left")
        self.assertEqual([mirror(c) for c, _k in reversed(left)], [c for c, _k in right])
        later = effects.ecg_side(9, 30, 20, "right")  # Two dots on is one cell outward
        self.assertEqual([c for c, _k in later][1:], [c for c, _k in right][:-1])

    def test_the_trace_is_one_thin_unbroken_line_that_fades_toward_the_edge(self):
        from cybrwire import effects
        cells = effects.ecg_side(0, 30, 24, "right")
        self.assertEqual(len(cells), 24)
        self.assertTrue(all("\u2800" <= c <= "\u28ff" for c, _k in cells))
        for c, _k in cells:
            self.assertLess(bin(ord(c) - 0x2800).count("1"), 7)  # No filled blocks: a line, not bars
        for x in range(48):  # Every dot column has a dot: unbroken from the title to the edge
            bits = ord(cells[x // 2][0]) - 0x2800
            self.assertTrue(bits & (0x47 if x % 2 == 0 else 0xB8), f"gap at dot column {x}")
        brightness = [k for _c, k in cells]
        self.assertEqual(brightness, sorted(brightness, reverse=True))
        self.assertGreater(brightness[0], brightness[-1] + 0.4)

    def test_busier_feeds_have_closer_heartbeats(self):
        from cybrwire import effects
        periods = [effects.beat_period(rate) for rate in (0, 4, 10, 20, 40, 400)]
        self.assertEqual(periods, sorted(periods, reverse=True))
        self.assertGreater(periods[0], periods[-1])
        def spikes(period):  # Cells with a dot in the top row: one per spike
            return sum(1 for c, _k in effects.ecg_side(0, period, 80, "right") if ord(c) & 0x09)
        self.assertGreater(spikes(effects.beat_period(100)), spikes(effects.beat_period(0)))

    def test_the_trace_has_the_shape_of_a_heartbeat(self):
        from cybrwire import effects
        beat = effects.ECG_BEAT
        self.assertEqual(beat.index(min(beat)), beat.index(0))                 # One tall R spike
        self.assertGreater(beat[beat.index(0) - 1], effects.ECG_BASE)          # A dip (Q) just before it
        self.assertGreater(beat[beat.index(0) + 1], effects.ECG_BASE)          # ...and another (S) just after
        self.assertLess(min(beat[:3]), effects.ECG_BASE)                       # A small P bump first
        self.assertLess(min(beat[-3:]), effects.ECG_BASE)                      # A T bump after


def plain_text(text):
    return text.plain


if __name__ == "__main__":
    unittest.main()
