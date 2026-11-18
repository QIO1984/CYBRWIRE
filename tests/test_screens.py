"""Every screen and strip draws, with the real app in a headless terminal.

The pure-logic tests can't see a moved import or a missing name in a screen, so this one launches
the app and reads what each screen actually shows.
"""

import asyncio
import io
import os
import sqlite3
import sys
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

from rich.console import Console

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import isolated  # noqa: E402,F401
import cybrwire  # noqa: E402
from cybrwire import ai, history, screens, chrome  # noqa: E402
from cybrwire.map_card import MapCard  # noqa: E402
from cybrwire import app as cybrwire_app  # noqa: E402
from cybrwire.config import Config  # noqa: E402


NOW = datetime.now(timezone.utc)


def alert(title, source="Feed", kind="news", severity="info", hours=1, **extra):
    return {"title": title, "summary": "Details", "source": source, "kind": kind, "severity": severity,
            "url": f"https://example.test/{abs(hash((title, source)))}", "ts": NOW - timedelta(hours=hours), **extra}


PANEL_ALERTS = [
    alert("RANSOMWARE VICTIM: Beta Ltd (play) [DE]", "Ransomware.live", "ransomware", "ransomware"),
    alert("OUTAGE · Cloudflare: elevated errors", "Cloudflare Status", "outage"),
    alert("Ivanti flaw CVE-2099-0001 exploited", "Feed A", "advisory", "zeroday"),
    alert("CVE-2099-0001 in the wild", "Feed B", "news", "exploit"),
    alert("RANSOMWARE VICTIM: Acme Corp (lockbit) [US]", "Ransomware.live", "ransomware", "ransomware"),
    alert("198.51.100.7", "ThreatFox", "indicators", ioc="198.51.100.7", threat="Emotet"),
    alert("OpenSSL update ships"),
]


def drawn(renderable, width: int = 100) -> str:
    """A Rich renderable as the plain text it prints"""
    console = Console(file=io.StringIO(), width=width, force_terminal=False)
    console.print(renderable)
    return console.file.getvalue()


def text_of(widget) -> str:
    """What a Static is showing, as plain text"""
    content = widget.render()
    return getattr(content, "plain", str(content))


class ScreensDraw(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        for patcher in (mock.patch.object(ai, "generate", side_effect=AssertionError("no AI in tests")),
                        mock.patch("cybrwire.links.webbrowser.open"),
                        mock.patch("httpx.AsyncClient.get", mock.AsyncMock(side_effect=OSError("no network in tests")))):
            patcher.start()
            self.addCleanup(patcher.stop)
        cybrwire_app.CONFIG = Config(sources=[], timezone="UTC", clocks=["NYC: America/New_York"])
        cybrwire_app.STATE.settings = {"filter_type_index": 0, "alerts_default": True}
        cybrwire_app.alert_queue[:] = []
        cybrwire_app.HISTORY.record([])  # Creates the table on a fresh test folder
        conn = sqlite3.connect(history.HISTORY_PATH)
        with conn:
            conn.execute("DELETE FROM alerts")
        conn.close()

    async def settle(self, pilot):
        await pilot.pause()
        await pilot.pause()

    async def test_the_loading_screen_shows_the_banner_and_the_feed_being_checked(self):
        app = cybrwire_app.CybrWireApp()
        release = asyncio.Event()

        async def slow_load():
            cybrwire_app.currently_loading = "Example Feed"
            await release.wait()
            app.pop_screen()
            app.is_loading = False
            app.update_display()

        app.initial_load = slow_load
        async with app.run_test(size=(160, 45)) as pilot:
            await self.settle(pilot)
            screen = app.screen_stack[-1]
            self.assertIsInstance(screen, screens.LoadingScreen)
            for _ in range(40):  # The animation steps through its messages
                screen.update_loading()
                screen.loading_step = len(screen.messages) - 1
            screen.update_loading()
            shown = text_of(screen.query_one("#loading-content"))
            self.assertIn(cybrwire.__version__, shown)
            self.assertIn("Example Feed", shown)
            release.set()
            await self.settle(pilot)
        cybrwire_app.currently_loading = None

    async def test_the_main_window_has_its_header_clock_and_footer(self):
        app = cybrwire_app.CybrWireApp()

        async def fake_load():
            app.pop_screen()
            app.is_loading = False
            app.update_display()

        app.initial_load = fake_load
        async with app.run_test(size=(160, 45)) as pilot:
            await self.settle(pilot)
            self.assertIn(f"v{cybrwire.__version__}", app.title)
            clock = app.query_one(chrome.WorldClock)
            shown = text_of(clock)
            self.assertIn("LOC", shown)
            self.assertIn("NYC", shown)  # The city from the config passed in at startup
            footer = text_of(app.query_one(chrome.CybrWireFooter))
            self.assertIn("quit", footer.lower())
            await pilot.press("h")
            await self.settle(pilot)
            self.assertIsInstance(app.screen, screens.HelpScreen)
            self.assertIn(cybrwire.__version__, text_of(app.screen.query_one("#help-content")))

    async def test_every_panel_draws_in_both_looks(self):
        cybrwire_app.alert_queue[:] = PANEL_ALERTS
        app = cybrwire_app.CybrWireApp()

        async def fake_load():
            app.pop_screen()
            app.is_loading = False
            app.update_display()

        app.initial_load = fake_load
        async with app.run_test(size=(160, 45)) as pilot:
            await self.settle(pilot)
            for cold_war in (False, True):
                app.cold_war_mode = cold_war
                await self.settle(pilot)
                for name, panel in (("dashboard", app.make_dashboard()), ("feed status", app.make_feed_status_panel()),
                                    ("war room", app.make_war_room_panel()), ("API tools", app.make_api_tools_content()),
                                    ("preview", app.make_alert_preview(PANEL_ALERTS[0])),
                                    ("map view", app.map_view_content(100, 45))):
                    self.assertTrue(drawn(panel).strip(), f"{name} drew nothing (cold war: {cold_war})")
                self.assertIn("Acme", drawn(app.make_dashboard()) + drawn(app.make_alert_preview(PANEL_ALERTS[4])))
            for _ in range(3):  # Alerts -> incidents -> API tools -> back
                await pilot.press("v")
                await self.settle(pilot)
            await pilot.press("tab")
            await self.settle(pilot)
            self.assertEqual(app.screen_stack[-1].__class__.__name__, "Screen")  # Nothing crashed back to a bare screen

    async def test_the_map_is_the_default_main_view_and_has_a_full_window_card(self):
        cybrwire_app.alert_queue[:] = PANEL_ALERTS
        app = cybrwire_app.CybrWireApp()

        async def fake_load():
            app.pop_screen()
            app.is_loading = False
            app.update_display()

        app.initial_load = fake_load
        async with app.run_test(size=(160, 45)) as pilot:
            await self.settle(pilot)
            self.assertEqual(app.main_view_mode, "map")
            self.assertTrue(app.query_one("#map-panel").display)
            self.assertFalse(app.query_one("#alerts-view").display)
            shown = drawn(app.map_view_content(100, 40))
            for expected in ("Ransomware victims  2", "Active outages  1", "LATEST", "ALERTS / HOUR"):
                self.assertIn(expected, shown)
            wide = [line for line in drawn(app.map_view_content(190, 40), 190).split("\n") if any(0x2800 < ord(ch) <= 0x28FF for ch in line)]
            left = min(next(i for i, ch in enumerate(line) if 0x2800 < ord(ch) <= 0x28FF) for line in wide)
            right = 190 - max(max(i for i, ch in enumerate(line) if 0x2800 < ord(ch) <= 0x28FF) for line in wide) - 1
            self.assertLess(abs(left - right), 12)  # The land sits in the middle, not pushed to the left
            self.assertGreater(190 - left - right, 120)  # And it fills most of the width
            before = drawn(app.map_view_content(100, 40))
            for _ in range(3):
                app.map_tick()  # The timer doesn't run in the harness; the pulse moves markers and scope
            self.assertNotEqual(before, drawn(app.map_view_content(100, 40)))
            await pilot.press("v")  # map -> alerts -> incidents -> API tools -> map
            await self.settle(pilot)
            self.assertEqual(app.main_view_mode, "alerts")
            for _ in range(3):
                await pilot.press("v")
                await self.settle(pilot)
            self.assertEqual(app.main_view_mode, "map")
            await pilot.press("m")
            await self.settle(pilot)
            self.assertIsInstance(app.screen, MapCard)
            before = drawn(app.screen.shown)
            self.assertIn("Ransomware victims", before)
            app.screen.pulse()
            await self.settle(pilot)
            self.assertNotEqual(before, drawn(app.screen.shown))
            await pilot.press("m")
            await self.settle(pilot)
            self.assertNotIsInstance(app.screen, MapCard)
            await pilot.press("m")
            await self.settle(pilot)
            await pilot.click("#map-close")
            await self.settle(pilot)
            self.assertNotIsInstance(app.screen, MapCard)

    async def test_effects_can_be_switched_off_and_the_choice_is_remembered(self):
        app = cybrwire_app.CybrWireApp()

        async def fake_load():
            app.pop_screen()
            app.is_loading = False
            app.update_display()

        app.initial_load = fake_load
        async with app.run_test(size=(160, 45)) as pilot:
            await self.settle(pilot)
            self.assertTrue(app.effects_on)
            step = app.map_step
            await pilot.press("x")
            await self.settle(pilot)
            self.assertFalse(app.effects_on)
            app.map_tick()
            self.assertEqual(app.map_step, step)  # Nothing pulses with effects off
            self.assertFalse(cybrwire_app.STATE.settings["effects"])
            await pilot.press("x")
            await self.settle(pilot)
            self.assertTrue(app.effects_on)

    async def test_the_last_main_view_is_remembered(self):
        cybrwire_app.STATE.settings = {"main_view": "incidents", "alerts_default": True}
        app = cybrwire_app.CybrWireApp()
        self.assertEqual(app.main_view_mode, "incidents")
        cybrwire_app.STATE.settings = {"main_view": "api_tools"}
        self.assertEqual(cybrwire_app.CybrWireApp().main_view_mode, "map")  # API tools is never the opening view

    async def test_the_theme_picker_previews_live_and_the_cycle_visits_every_theme(self):
        from cybrwire.theme_card import ThemeCard
        from cybrwire.theme import PALETTES
        app = cybrwire_app.CybrWireApp()

        async def fake_load():
            app.pop_screen()
            app.is_loading = False
            app.update_display()

        app.initial_load = fake_load
        async with app.run_test(size=(160, 45)) as pilot:
            await self.settle(pilot)
            start = app.theme_mode
            seen = {start}
            for _ in range(len(PALETTES)):
                await pilot.press("t")
                seen.add(app.theme_mode)
            self.assertEqual(seen, set(PALETTES))
            self.assertEqual(app.theme_mode, start)  # A full lap comes back to where it began
            await pilot.press("T")
            await self.settle(pilot)
            self.assertIsInstance(app.screen, ThemeCard)
            self.assertEqual(app.theme_mode, start)
            await pilot.press("down")
            await self.settle(pilot)
            moved = app.theme_mode
            self.assertNotEqual(moved, start)
            self.assertEqual(app.theme, f"cybrwire-{moved}")  # The window changed under the card
            self.assertEqual(cybrwire_app.STATE.settings["theme"], moved)
            await pilot.press("escape")
            await self.settle(pilot)
            self.assertNotIsInstance(app.screen, ThemeCard)
            self.assertEqual(app.theme_mode, moved)  # Esc keeps what was previewed

    async def test_picking_a_theme_leaves_cold_war_mode(self):
        app = cybrwire_app.CybrWireApp()

        async def fake_load():
            app.pop_screen()
            app.is_loading = False
            app.update_display()

        app.initial_load = fake_load
        async with app.run_test(size=(160, 45)) as pilot:
            await self.settle(pilot)
            await pilot.press("c")
            await self.settle(pilot)
            self.assertTrue(app.cold_war_mode)
            app.set_theme_by_key("tron")
            self.assertFalse(app.cold_war_mode)
            self.assertEqual(app.palette.key, "tron")

    def test_themed_boot_screens_keep_the_api_step_third_and_have_seven_steps(self):
        from cybrwire.theme import PALETTES
        for key in ("blade_runner", "matrix", "newsroom"):
            screen = screens.LoadingScreen(PALETTES[key])
            self.assertEqual(len(screen.messages), 7)
            self.assertEqual(screen.messages[2], "CHECKING APIS...")
            self.assertEqual(screen.messages[1], PALETTES[key].boot[0])
        plain = screens.LoadingScreen(PALETTES["neon"])
        self.assertEqual(plain.messages[1], "TAPPING WIRES...")


if __name__ == "__main__":
    unittest.main()
