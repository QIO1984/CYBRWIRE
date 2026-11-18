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

    async def test_the_header_corner_shows_a_heartbeat_that_stops_in_the_period_simulations(self):
        from cybrwire.chrome import StyledHeader
        app = self.make_app()
        async with app.run_test(size=(140, 40)) as pilot:
            await self.settle(pilot)
            app.set_theme_by_key("neon")
            header = app.query_one(StyledHeader)
            app.heartbeat_tick()
            first = header.icon
            self.assertTrue(first.startswith("[") and any(ch in first for ch in "▁▂▆█▃"))
            for _ in range(6):
                app.heartbeat_tick()
            self.assertNotEqual(header.icon, first)  # The trace scrolls
            app.effects_on = False
            app.heartbeat_tick()
            self.assertEqual(header.icon, "◆")
            app.effects_on = True
            for key in ("amber_crt",):
                app.set_theme_by_key(key)
                app.heartbeat_tick()
                self.assertEqual(header.icon, "◆", key)
            app.set_theme_by_key("neon")
            await pilot.press("c")
            await self.settle(pilot)
            app.heartbeat_tick()
            self.assertEqual(header.icon, "◆")  # Cold War mode keeps its plain header

    def test_busier_feeds_have_closer_heartbeats(self):
        from cybrwire import effects
        periods = [effects.beat_period(rate) for rate in (0, 4, 10, 20, 40, 400)]
        self.assertEqual(periods, sorted(periods, reverse=True))
        self.assertGreater(periods[0], periods[-1])
        for period in periods:
            frame = effects.ecg_frame(3, period)
            self.assertEqual(len(frame), effects.ECG_WIDTH)
            self.assertTrue(set(frame) <= set("▁▂▆█▃"))
        beats = lambda p: sum(effects.ecg_frame(0, p).count("█") for _ in (0,))
        self.assertGreaterEqual(beats(5), beats(14))

    def test_the_trace_scrolls_one_cell_per_step_and_repeats(self):
        from cybrwire import effects
        a, b = effects.ecg_frame(0, 10), effects.ecg_frame(1, 10)
        self.assertEqual(a[1:], b[:-1])
        self.assertEqual(effects.ecg_frame(0, 10), effects.ecg_frame(10, 10))

    async def test_sounds_go_to_a_local_speaker_or_to_the_browser_page(self):
        from cybrwire import sound, web_sound
        app = self.make_app()
        async with app.run_test(size=(120, 40)) as pilot:
            await self.settle(pilot)
            with mock.patch.dict(os.environ, {"TEXTUAL_DRIVER": "textual.drivers.linux_driver:LinuxDriver"}), \
                    mock.patch.object(sound, "play") as play:
                app.play_sound("sonar")
                app.play_sound("off")
                app.play_sound("nonsense")
            play.assert_called_once_with("sonar", app.bell)
            driver = mock.Mock()
            with mock.patch.dict(os.environ, {"TEXTUAL_DRIVER": "textual.drivers.web_driver:WebDriver"}), \
                    mock.patch.object(app, "_driver", driver), mock.patch.object(sound, "play") as play:
                app.play_sound("teletype")
                app.play_sound("bell")
                app.play_sound("off")
            play.assert_not_called()
            self.assertEqual([c.args[0] for c in driver.write_meta.call_args_list],
                             [{"type": web_sound.MESSAGE, "name": "teletype"}, {"type": web_sound.MESSAGE, "name": "bell"}])

    async def test_the_ambient_hum_toggles_saves_and_explains_when_there_is_no_player(self):
        from cybrwire import sound, web_sound
        app = self.make_app()
        async with app.run_test(size=(120, 40)) as pilot:
            await self.settle(pilot)
            self.assertFalse(app.hum_on)
            with mock.patch.dict(os.environ, {"TEXTUAL_DRIVER": "textual.drivers.linux_driver:LinuxDriver"}):
                with mock.patch.object(sound.HUM, "start", return_value=False):
                    await pilot.press("B")
                    await self.settle(pilot)
                    self.assertFalse(app.hum_on)  # No player: it says so and stays off
                with mock.patch.object(sound.HUM, "start", return_value=True) as start, mock.patch.object(sound.HUM, "stop") as stop:
                    await pilot.press("B")
                    await self.settle(pilot)
                    self.assertTrue(app.hum_on)
                    self.assertTrue(cybrwire_app.STATE.settings["hum"])
                    start.assert_called_once()
                    await pilot.press("B")
                    await self.settle(pilot)
                    self.assertFalse(app.hum_on)
                    stop.assert_called_once()
            driver = mock.Mock()
            with mock.patch.dict(os.environ, {"TEXTUAL_DRIVER": "textual.drivers.web_driver:WebDriver"}), mock.patch.object(app, "_driver", driver):
                app.action_toggle_hum()
            self.assertTrue(app.hum_on)
            driver.write_meta.assert_called_with({"type": web_sound.MESSAGE, "hum": True})

    async def test_the_hum_choice_is_remembered(self):
        cybrwire_app.STATE.settings = {"hum": True, "alerts_default": True}
        self.assertTrue(cybrwire_app.CybrWireApp().hum_on)
        cybrwire_app.STATE.settings = {"alerts_default": True}
        self.assertFalse(cybrwire_app.CybrWireApp().hum_on)


def plain_text(text):
    return text.plain


if __name__ == "__main__":
    unittest.main()
