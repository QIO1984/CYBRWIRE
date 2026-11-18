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
from cybrwire import app as cybrwire_app  # noqa: E402
from cybrwire.config import Config  # noqa: E402


NOW = datetime.now(timezone.utc)


def alert(title, source="Feed", kind="news", severity="info", hours=1, **extra):
    return {"title": title, "summary": "Details", "source": source, "kind": kind, "severity": severity,
            "url": f"https://example.test/{abs(hash((title, source)))}", "ts": NOW - timedelta(hours=hours), **extra}


PANEL_ALERTS = [
    alert("Ivanti flaw CVE-2099-0001 exploited", "Feed A", "advisory", "zeroday"),
    alert("CVE-2099-0001 in the wild", "Feed B", "news", "exploit"),
    alert("RANSOMWARE VICTIM: Acme Corp (lockbit) [US]", "Ransomware.live", "ransomware", "ransomware"),
    alert("198.51.100.7", "ThreatFox", "indicators", ioc="198.51.100.7", threat="Emotet"),
    alert("OpenSSL update ships"),
]


def drawn(renderable) -> str:
    """A Rich renderable as the plain text it prints"""
    console = Console(file=io.StringIO(), width=100, force_terminal=False)
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
                                    ("preview", app.make_alert_preview(PANEL_ALERTS[0]))):
                    self.assertTrue(drawn(panel).strip(), f"{name} drew nothing (cold war: {cold_war})")
                self.assertIn("Acme", drawn(app.make_dashboard()) + drawn(app.make_alert_preview(PANEL_ALERTS[2])))
            for _ in range(3):  # Alerts -> incidents -> API tools -> back
                await pilot.press("v")
                await self.settle(pilot)
            await pilot.press("tab")
            await self.settle(pilot)
            self.assertEqual(app.screen_stack[-1].__class__.__name__, "Screen")  # Nothing crashed back to a bare screen


if __name__ == "__main__":
    unittest.main()
