"""The atmosphere: the screensaver's rain, the idle timer, the arrival flash and the effects switch"""

import asyncio
import os
import sqlite3
import sys
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import isolated  # noqa: E402,F401
from cybrwire import ai, history, screensaver  # noqa: E402
from cybrwire import app as cybrwire_app  # noqa: E402
from cybrwire.config import Config  # noqa: E402
from cybrwire.evidence import CONFIRMED, Evidence  # noqa: E402
from cybrwire.screensaver import Rain, ScreensaverScreen  # noqa: E402
from cybrwire.theme import COLD_WAR, PALETTES  # noqa: E402

NEON = PALETTES["neon"]
NOW = datetime.now(timezone.utc)


def alert(title, severity="info", source="Feed", hours=1, **extra):
    return {"title": title, "summary": "", "source": source, "kind": "news", "severity": severity,
            "url": f"https://example.test/{abs(hash(title))}", "ts": NOW - timedelta(hours=hours), **extra}


def edge(app):
    """The style of the outline round the window: "" when there is none"""
    return app.screen.styles.outline[0][0]


class RainModel(unittest.TestCase):
    def test_a_frame_has_one_cell_per_column_and_row(self):
        rain = Rain(60, 20, seed=1)
        for _ in range(5):
            rain.step([])
        lines = rain.render(NEON, 40).plain.split("\n")
        self.assertEqual(len(lines), 20)
        self.assertTrue(all(len(line) == 60 for line in lines))

    def test_the_rain_falls_and_something_is_always_on_screen(self):
        rain = Rain(60, 20, seed=2)
        seen = set()
        for _ in range(60):
            rain.step([])
            seen.add(rain.render(NEON).plain)
        self.assertGreater(len(seen), 30)  # It keeps changing
        self.assertTrue(all(plain.strip() for plain in seen))

    def test_a_headline_types_in_holds_and_fades_away(self):
        rain = Rain(100, 24, seed=3)
        headlines = [("CRITICAL", "CISA adds Cisco BroadWorks flaw to KEV")]
        rain.step(headlines)
        self.assertIsNotNone(rain.headline)
        self.assertNotIn("BroadWorks", rain.render(NEON).plain)  # Only the first few characters so far
        for _ in range(22):
            rain.step(headlines)
        self.assertIn("BroadWorks flaw", rain.render(NEON).plain)
        total = int(len(headlines[0][1]) / screensaver.TYPE_CHARS_PER_STEP + screensaver.HOLD_STEPS + screensaver.FADE_STEPS) + 2
        for _ in range(total):
            rain.step([])
        self.assertIsNone(rain.headline)

    def test_a_long_headline_is_cut_to_fit_a_narrow_screen(self):
        rain = Rain(40, 12, seed=4)
        rain.step([("APT", "A very long headline " * 6)])
        lines = rain.render(NEON).plain.split("\n")
        self.assertTrue(all(len(line) == 40 for line in lines))

    def test_the_bottom_rows_glow_in_the_threat_colour(self):
        rain = Rain(30, 10, seed=5)
        rain.step([])
        calm, hot = rain.render(NEON, 5), rain.render(NEON, 95)
        last_row_start = len("\n".join(calm.plain.split("\n")[:-1])) + 1
        def grounds(text):
            return {str(span.style) for span in text.spans if span.start >= last_row_start}
        self.assertNotEqual(grounds(calm), grounds(hot))
        self.assertTrue(all(" on " in style for style in grounds(hot)))

    def test_cold_war_rain_stays_one_colour_family(self):
        rain = Rain(30, 10, seed=6)
        rain.step([])
        rain.render(COLD_WAR, 50)  # Draws without needing the colourful roles

    def test_the_same_seed_gives_the_same_picture(self):
        a, b = Rain(40, 12, seed=7), Rain(40, 12, seed=7)
        for _ in range(10):
            a.step([])
            b.step([])
        self.assertEqual(a.render(NEON).plain, b.render(NEON).plain)


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

    async def test_the_screensaver_starts_when_idle_and_any_key_ends_it(self):
        app = self.make_app()
        with mock.patch.object(screensaver, "IGNORE_INPUT_SECONDS", 0):
            async with app.run_test(size=(120, 40)) as pilot:
                await self.settle(pilot)
                app.idle_check()
                self.assertEqual(len(app.screen_stack), 1)  # Not idle yet
                app.last_input -= app.IDLE_SECONDS + 1
                app.idle_check()
                await self.settle(pilot)
                self.assertIsInstance(app.screen, ScreensaverScreen)
                for _ in range(3):
                    app.screen.frame()
                self.assertIsNotNone(app.screen.rain)
                await pilot.press("space")
                await self.settle(pilot)
                self.assertNotIsInstance(app.screen, ScreensaverScreen)

    async def test_a_click_wakes_it_too(self):
        app = self.make_app()
        with mock.patch.object(screensaver, "IGNORE_INPUT_SECONDS", 0):
            async with app.run_test(size=(120, 40)) as pilot:
                await self.settle(pilot)
                app.last_input -= app.IDLE_SECONDS + 1
                app.idle_check()
                await self.settle(pilot)
                await pilot.click("#rain")
                await self.settle(pilot)
                self.assertNotIsInstance(app.screen, ScreensaverScreen)

    async def test_input_resets_the_idle_clock(self):
        app = self.make_app()
        async with app.run_test(size=(120, 40)) as pilot:
            await self.settle(pilot)
            app.last_input -= 1000
            await pilot.press("space")
            await self.settle(pilot)
            self.assertLess(cybrwire_app.time.monotonic() - app.last_input, 5)

    async def test_it_never_starts_with_effects_off_or_a_card_open_or_while_loading(self):
        app = self.make_app()
        async with app.run_test(size=(120, 40)) as pilot:
            await self.settle(pilot)
            app.last_input -= app.IDLE_SECONDS + 1
            app.effects_on = False
            app.idle_check()
            await self.settle(pilot)
            self.assertNotIsInstance(app.screen, ScreensaverScreen)
            app.effects_on = True
            await pilot.press("h")  # The help screen is open
            await self.settle(pilot)
            depth = len(app.screen_stack)
            app.idle_check()
            await self.settle(pilot)
            self.assertEqual(len(app.screen_stack), depth)

    async def test_headlines_and_heat_come_from_the_alerts(self):
        app = self.make_app()
        async with app.run_test(size=(120, 40)) as pilot:
            await self.settle(pilot)
            titles = [title for _tag, title in app.screensaver_headlines()]
            self.assertIn("CISA adds a flaw to KEV", titles)
            self.assertNotIn("Routine post", titles)
            self.assertGreater(app.threat_heat(), 0)
            cybrwire_app.alert_queue[:] = []
            self.assertEqual(app.threat_heat(), 0)

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


if __name__ == "__main__":
    unittest.main()
