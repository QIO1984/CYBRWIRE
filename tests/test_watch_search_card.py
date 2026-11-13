"""
Watchlist, search and CVE card tests. Run from the repo root:

    venv/bin/python -m unittest discover -s tests

No network, no AI calls, and the real state file is never touched.
"""

import asyncio
import io
import os
import sqlite3
import sys
import time
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

from rich.console import Console
from textual import events

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import isolated  # noqa: E402,F401
from cybrwire import history  # noqa: E402
from cybrwire import state  # noqa: E402

from cybrwire import ai  # noqa: E402
from cybrwire import cve_card  # noqa: E402
from cybrwire import links  # noqa: E402
from cybrwire import cve_intel  # noqa: E402
from cybrwire import app as cybrwire  # noqa: E402
from cybrwire import feeds  # noqa: E402
from cybrwire.config import Config  # noqa: E402
from cybrwire.cve_card import CveCard, exploit_status  # noqa: E402
from cybrwire.livewire import Shown, WireItem  # noqa: E402
from cybrwire import evidence  # noqa: E402
from cybrwire.watch_card import WatchCard  # noqa: E402
from cybrwire.watchlist import Watchlist, matches_search  # noqa: E402

NOW = datetime.now(timezone.utc)


def alert(title, summary="", source="Feed", kind="news", severity="info", hours=1, **extra):
    return {"title": title, "summary": summary, "source": source, "kind": kind, "severity": severity,
            "url": f"https://example.test/{abs(hash(title))}", "ts": NOW - timedelta(hours=hours), **extra}


SAMPLE = [
    alert("Ivanti EPMM flaw CVE-2099-0001 exploited", "and also CVE-2099-0002", severity="zeroday", kind="advisory"),
    alert("OpenSSL update ships", "Routine release"),
    alert("CitrixBleed returns", "Sessions hijacked", severity="exploit"),
    alert("Old Fortinet story", "From last week", hours=100),
    alert("198.51.100.7", "C2 server", source="ThreatFox", kind="indicators", ioc="198.51.100.7", threat="Emotet"),
]

NVD_RECORD = {
    "descriptions": [{"lang": "es", "value": "no"}, {"lang": "en", "value": "Auth bypass in EPMM."}],
    "metrics": {"cvssMetricV31": [
        {"type": "Secondary", "cvssData": {"baseScore": 5.0, "baseSeverity": "MEDIUM", "vectorString": "wrong"}},
        {"type": "Primary", "cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL", "vectorString": "CVSS:3.1/AV:N"}},
    ]},
    "weaknesses": [{"description": [{"value": "CWE-287"}, {"value": "NVD-CWE-noinfo"}]}],
    "configurations": [{"nodes": [{"cpeMatch": [
        {"vulnerable": True, "criteria": "cpe:2.3:a:ivanti:endpoint_manager_mobile:*:*"},
        {"vulnerable": False, "criteria": "cpe:2.3:o:linux:linux_kernel:*:*"},
    ]}]}],
    "references": [{"url": "https://vendor.test/a", "tags": ["Vendor Advisory"]},
                   {"url": "https://poc.test/b", "tags": ["Exploit"]}],
    "published": "2099-01-02T00:00:00.000", "vulnStatus": "Analyzed",
}


class WatchlistMatching(unittest.TestCase):
    def test_whole_word_and_case(self):
        w = Watchlist(["ssl"])
        self.assertEqual(w.hits(alert("OpenSSL update")), [])
        self.assertEqual(w.hits(alert("SSL certificate flaw")), ["ssl"])

    def test_prefix_wildcard(self):
        self.assertEqual(Watchlist(["citrix*"]).hits(alert("CitrixBleed returns")), ["citrix*"])
        self.assertEqual(Watchlist(["citrix"]).hits(alert("CitrixBleed returns")), [])

    def test_special_characters_and_cve_terms(self):
        self.assertTrue(Watchlist(["CVE-2099-0001"]).hits(SAMPLE[0]))
        self.assertTrue(Watchlist(["c++"]).hits(alert("A c++ library flaw")))
        self.assertEqual(Watchlist(["(unbalanced"]).hits(alert("nothing")), [])

    def test_only_title_and_description_count(self):
        self.assertTrue(Watchlist(["sessions"]).hits(alert("Flaw", "Sessions hijacked")))
        self.assertEqual(Watchlist(["cisco"]).hits(alert("Patch", source="Cisco PSIRT")), [])
        self.assertEqual(Watchlist(["emotet"]).hits(SAMPLE[4]), [])

    def test_toggle(self):
        w = Watchlist(["Fortinet"], ["Ivanti"])
        self.assertEqual(w.toggle("citrix"), "added")
        self.assertEqual(w.toggle("CITRIX"), "removed")
        self.assertEqual(w.toggle("fortinet"), "configured")
        self.assertEqual(w.terms, ["Fortinet", "Ivanti"])

    def test_edit_invalidates_remembered_answers(self):
        w = Watchlist()
        a = alert("Ivanti flaw")
        self.assertEqual(w.hits(a), [])
        w.toggle("ivanti")
        self.assertEqual(w.hits(a), ["ivanti"])
        w.toggle("ivanti")
        self.assertEqual(w.hits(a), [])

    def test_duplicates_collapse_and_yaml_wins(self):
        self.assertEqual(Watchlist(["A", "a", " ", None], ["A"]).terms, ["A"])


class SearchMatching(unittest.TestCase):
    def test_all_words_any_order_substring(self):
        a = alert("Ivanti EPMM flaw", "Exploited in the wild", source="CISA")
        self.assertTrue(matches_search(a, "wild ivan"))
        self.assertTrue(matches_search(a, "cisa"))
        self.assertFalse(matches_search(a, "ivanti fortinet"))


class NvdParsing(unittest.TestCase):
    def test_parse(self):
        d = cve_intel.parse_nvd(NVD_RECORD)
        self.assertEqual((d["score"], d["severity"], d["vector"]), (9.8, "CRITICAL", "CVSS:3.1/AV:N"))
        self.assertEqual(d["description"], "Auth bypass in EPMM.")
        self.assertEqual(d["cwes"], ["CWE-287"])
        self.assertEqual(d["affected"], ["ivanti endpoint manager mobile"])
        self.assertEqual(d["references"][0]["url"], "https://poc.test/b")
        self.assertEqual(d["exploit_refs"], 1)

    def test_empty_record_is_cached_as_known_missing(self):
        d = cve_intel.parse_nvd({})
        self.assertIsNone(d["score"])
        self.assertIn("description", d)

    def test_exploit_wording(self):
        self.assertIn("KNOWN EXPLOITED", exploit_status({"dateAdded": "2099-01-01"}, {})[1])
        self.assertIn("PUBLIC EXPLOIT", exploit_status({}, {"exploit_refs": 2})[1])
        self.assertTrue(exploit_status({}, {})[1].startswith("No known"))


class NvdClientUpgrades(unittest.IsolatedAsyncioTestCase):

    async def test_old_cache_entry_refetched_only_for_detail(self):
        cache = {"CVE-1": {"score": 9.0, "severity": "CRITICAL", "checked": NOW.isoformat()}}
        nvd = cve_intel.NvdClient(cache)
        nvd._last = -1e9
        response = mock.Mock(raise_for_status=lambda: None, json=lambda: {"vulnerabilities": [{"cve": NVD_RECORD}]})
        with mock.patch("httpx.AsyncClient.get", mock.AsyncMock(return_value=response)) as get:
            self.assertEqual((await nvd.fetch("CVE-1"))["score"], 9.0)
            get.assert_not_called()
            self.assertEqual((await nvd.fetch("CVE-1", detail=True))["description"], "Auth bypass in EPMM.")
            get.assert_called_once()
            await nvd.fetch("CVE-1", detail=True)
            get.assert_called_once()

    async def test_detail_waits_for_a_lookup_already_running(self):
        nvd = cve_intel.NvdClient({})
        nvd._last = -1e9
        response = mock.Mock(raise_for_status=lambda: None, json=lambda: {"vulnerabilities": [{"cve": NVD_RECORD}]})

        async def slow_get(*args, **kwargs):
            await asyncio.sleep(0.3)
            return response

        with mock.patch("httpx.AsyncClient.get", slow_get):
            preview = asyncio.create_task(nvd.fetch("CVE-1"))
            await asyncio.sleep(0)
            entry = await nvd.fetch("CVE-1", detail=True)
            await preview
        self.assertEqual(entry["score"], 9.8)

    async def test_failure_keeps_old_entry_and_is_reported(self):
        old = {"score": 9.0, "checked": NOW.isoformat()}
        nvd = cve_intel.NvdClient({"CVE-1": old})
        nvd._last = -1e9
        with mock.patch("httpx.AsyncClient.get", mock.AsyncMock(side_effect=OSError("down"))):
            self.assertEqual(await nvd.fetch("CVE-1", detail=True), old)
        self.assertIn("CVE-1", nvd.failed)


class AppBehavior(unittest.IsolatedAsyncioTestCase):
    """Drives the real app with keypresses, skipping the feed fetch and loading screen"""

    def setUp(self):
        self.ai_guard = mock.patch.object(ai, "generate", side_effect=AssertionError("tests must not call AI"))
        self.ai_guard.start()
        self.addCleanup(self.ai_guard.stop)
        # Nothing in here may reach the network or open a browser
        for target in ("cybrwire.links.webbrowser.open",):
            patcher = mock.patch(target)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.http = mock.patch("httpx.AsyncClient.get", mock.AsyncMock(side_effect=OSError("network blocked in tests")))
        self.http_get = self.http.start()
        self.addCleanup(self.http.stop)
        interval = mock.patch.object(cve_intel, "NVD_INTERVAL", 0)
        interval.start()
        self.addCleanup(interval.stop)
        cybrwire.STATE.cvss.clear()
        cybrwire.CONFIG = Config(sources=[], watchlist=["Fortinet"])
        cybrwire.STATE.settings = {"filter_type_index": 0, "alerts_default": True}  # Most tests are about everything loaded
        cybrwire.STATE.watchlist = []
        cybrwire.STATE.notified = {}
        cybrwire.alert_queue[:] = SAMPLE
        cybrwire.HISTORY.record([])
        conn = sqlite3.connect(history.HISTORY_PATH)
        with conn:
            conn.execute("DELETE FROM alerts")
        conn.close()
        feeds.KEV_DETAILS.clear()
        cve_intel.EPSS.clear()

    def make_app(self):
        app = cybrwire.CybrWireApp()

        async def fake_load():
            app.pop_screen()
            app.is_loading = False
            app.update_display()

        app.initial_load = fake_load
        return app

    async def settle(self, pilot):
        await pilot.pause()
        await pilot.pause()

    def titles(self, app):
        return [a["title"] for a in app.filtered_alerts()]

    async def test_search_filters_as_typed_and_commands_stay_off(self):
        app = self.make_app()
        with mock.patch.object(app, "action_refresh") as refresh, mock.patch.object(app, "action_quit") as quit_:
            async with app.run_test(size=(160, 45)) as pilot:
                await self.settle(pilot)
                await pilot.press("slash", "q", "r")
                self.assertEqual(app.query_one("#search-box").value, "qr")
                self.assertEqual(self.titles(app), [])
                refresh.assert_not_called()
                quit_.assert_not_called()
                await pilot.press("backspace", "backspace", *"citrix")
                self.assertEqual(self.titles(app), ["CitrixBleed returns"])
                await pilot.press("enter")
                self.assertIsNone(app.prompt)
                self.assertEqual(app.search_query, "citrix")
                self.assertEqual(app.query_one("#feed-table").cursor_row, 0)
                await pilot.press("escape")
                self.assertEqual(app.search_query, "")
                self.assertNotIn("Old Fortinet story", self.titles(app))

    async def test_search_reaches_older_items_and_indicators(self):
        app = self.make_app()
        async with app.run_test(size=(160, 45)) as pilot:
            await self.settle(pilot)
            await pilot.press("slash", *"fortinet")
            self.assertEqual(self.titles(app), ["Old Fortinet story"])
            await pilot.press("escape", "slash", *"emotet")
            self.assertEqual(self.titles(app), ["198.51.100.7"])
            # An explicit content type still narrows it
            await pilot.press("enter", "4")
            self.assertEqual(app.active_kind, "advisory")
            self.assertEqual(self.titles(app), [])

    async def test_digit_and_v_are_text_while_typing(self):
        app = self.make_app()
        async with app.run_test(size=(160, 45)) as pilot:
            await self.settle(pilot)
            await pilot.press("slash", "4", "v", "w", "i", "tab", "a")
            self.assertEqual(app.query_one("#search-box").value, "4vwia")
            self.assertEqual(app.kind_index, 0)
            self.assertEqual(app.main_view_mode, "alerts")
            self.assertFalse(app.watch_only)

    async def test_arrows_move_from_typing_to_results(self):
        app = self.make_app()
        async with app.run_test(size=(160, 45)) as pilot:
            await self.settle(pilot)
            await pilot.press("slash", *"ivanti", "down")
            self.assertIsNone(app.prompt)
            self.assertEqual(app.query_one("#feed-table").cursor_row, 0)
            self.assertEqual(app.selected_alert()["title"], SAMPLE[0]["title"])

    async def test_watch_only_and_editing_persist(self):
        app = self.make_app()
        async with app.run_test(size=(160, 45)) as pilot:
            await self.settle(pilot)
            await pilot.press("W", *"citrix*", "enter", *"ivanti", "enter", "escape")
            self.assertIsNone(app.prompt)
            self.assertEqual(cybrwire.STATE.watchlist, ["citrix*", "ivanti"])
            await pilot.press("w")
            self.assertTrue(app.watch_only)
            self.assertCountEqual(self.titles(app), ["CitrixBleed returns", SAMPLE[0]["title"]])
            await pilot.press("W", *"ivanti", "enter", "escape")
            self.assertEqual(self.titles(app), ["CitrixBleed returns"])
            await pilot.press("W", *"fortinet", "enter", "escape")
            self.assertIn("Fortinet", app.watchlist.terms)  # From YAML, so not removable here
        app.save_settings()
        reloaded = state.AppState()
        self.assertEqual(reloaded.watchlist, ["citrix*"])
        self.assertTrue(reloaded.settings["watch_only"])

    async def test_w_with_empty_watchlist_asks_for_a_term(self):
        cybrwire.CONFIG = Config(sources=[])
        app = self.make_app()
        async with app.run_test(size=(160, 45)) as pilot:
            await self.settle(pilot)
            await pilot.press("w")
            self.assertIsInstance(app.screen, WatchCard)
            self.assertTrue(app.watch_only)

    async def test_watch_card_lists_all_terms_and_takes_keys_as_text(self):
        app = self.make_app()
        with mock.patch.object(app, "action_quit") as quit_, mock.patch.object(app, "action_refresh") as refresh:
            async with app.run_test(size=(160, 45)) as pilot:
                await self.settle(pilot)
                await pilot.press("W", *"qr", "backspace", "backspace", *"ivanti", "enter", *"citrix*", "enter")
                table = app.screen.query_one("#watch-table")
                rows = [" ".join(c.plain for c in table.get_row_at(i)) for i in range(table.row_count)]
                card = " ".join(rows) + str(app.screen.query_one("#watch-title").render())
                for expected in ("3 terms", "Fortinet", "from YAML", "ivanti", "citrix*"):
                    self.assertIn(expected, card)
                self.assertRegex(card, r"ivanti\s+1 loaded")
                quit_.assert_not_called()
                refresh.assert_not_called()
                await pilot.press("down", "delete")  # Removes the selected app-added term
                self.assertEqual(app.watchlist.terms, ["Fortinet", "citrix*"])
                await pilot.press("up", "delete")    # YAML terms stay
                self.assertIn("Fortinet", app.watchlist.terms)
                await pilot.press("escape")
                self.assertNotIsInstance(app.screen, WatchCard)
            self.assertEqual(cybrwire.STATE.watchlist, ["citrix*"])

    async def test_click_selects_correct_row_with_search_bar(self):
        app = self.make_app()
        async with app.run_test(size=(160, 45)) as pilot:
            await self.settle(pilot)
            await pilot.press("slash", *"e", "enter")
            await self.settle(pilot)
            second = app.feed_rows[1]
            with mock.patch.object(links.webbrowser, "open") as browser:
                await pilot.click("#feed-table", offset=(10, 1))
                await self.settle(pilot)
                self.assertIs(app.selected_alert(), second)
                browser.assert_not_called()
                await pilot.click("#feed-table", offset=(40, 1))  # Same row, another column
                await self.settle(pilot)
                browser.assert_called_once_with(second["url"])

    async def test_feed_keeps_selection_when_new_alerts_arrive(self):
        app = self.make_app()
        async with app.run_test(size=(160, 45)) as pilot:
            await self.settle(pilot)
            await pilot.press("down", "down")
            chosen = app.selected_alert()
            cybrwire.alert_queue.insert(0, alert("Brand new story"))
            app.update_display()
            await self.settle(pilot)
            self.assertIs(app.selected_alert(), chosen)
            self.assertEqual(app.query_one("#feed-table").cursor_row, app.feed_rows.index(chosen))

    async def test_feed_scrolls_through_everything_without_pages(self):
        cybrwire.alert_queue[:] = [alert(f"Story number {i}", hours=1 + i / 100) for i in range(300)]
        app = self.make_app()
        async with app.run_test(size=(160, 45)) as pilot:
            await self.settle(pilot)
            table = app.query_one("#feed-table")
            self.assertEqual(table.row_count, 300)
            await pilot.press("right")
            await self.settle(pilot)
            self.assertGreater(table.cursor_row, 10)
            self.assertEqual(app.selected_alert(), app.feed_rows[table.cursor_row])
            await pilot.press("left")
            await self.settle(pilot)
            self.assertEqual(table.cursor_row, 0)

    async def test_cursor_stays_on_screen_past_the_bottom(self):
        cybrwire.alert_queue[:] = [alert(f"Story number {i}", hours=1 + i / 100) for i in range(300)]
        app = self.make_app()
        async with app.run_test(size=(160, 45)) as pilot:
            await self.settle(pilot)
            table = app.query_one("#feed-table")
            for _ in range(table.size.height + 5):
                await pilot.press("down")
                app.update_display()  # A redraw mid-scroll must not pull the view back
            await pilot.pause(0.5)
            self.assertGreaterEqual(table.cursor_row, table.scroll_y)
            self.assertLess(table.cursor_row, table.scroll_y + table.size.height)

    async def test_unchanged_feed_is_not_rebuilt(self):
        app = self.make_app()
        async with app.run_test(size=(160, 45)) as pilot:
            await self.settle(pilot)
            with mock.patch.object(app.query_one("#feed-table"), "clear") as clear:
                app.update_display()
                clear.assert_not_called()

    async def test_columns_follow_a_resize(self):
        app = self.make_app()
        async with app.run_test(size=(160, 45)) as pilot:
            await self.settle(pilot)
            table = app.query_one("#feed-table")
            wide = table.ordered_columns[-1].width
            await pilot.resize_terminal(110, 45)
            await self.settle(pilot)
            await self.settle(pilot)
            self.assertLess(table.ordered_columns[-1].width, wide)

    async def test_empty_feed_explains_itself_and_selects_nothing(self):
        app = self.make_app()
        async with app.run_test(size=(160, 45)) as pilot:
            await self.settle(pilot)
            await pilot.press("slash", *"zzzznothing", "enter")
            await self.settle(pilot)
            table = app.query_one("#feed-table")
            self.assertIsNone(app.selected_alert())
            self.assertFalse(table.show_cursor)
            self.assertIn("NO ALERTS", table.get_row_at(0)[2].plain)
            with mock.patch.object(links.webbrowser, "open") as browser:
                await pilot.press("enter")
                browser.assert_not_called()

    async def test_indicator_columns_and_back(self):
        app = self.make_app()
        async with app.run_test(size=(160, 45)) as pilot:
            await self.settle(pilot)
            while app.active_kind != "indicators":
                await pilot.press("4")
            await self.settle(pilot)
            table = app.query_one("#feed-table")
            self.assertEqual([str(c.label) for c in table.ordered_columns][2:4], ["TYPE", "INDICATOR"])
            self.assertTrue(table.show_header)
            while app.active_kind != "all":
                await pilot.press("4")
            await self.settle(pilot)
            self.assertFalse(table.show_header)
            self.assertEqual(len(table.ordered_columns), 4)

    async def test_search_box_takes_paste_and_cursor_keys(self):
        app = self.make_app()
        async with app.run_test(size=(160, 45)) as pilot:
            await self.settle(pilot)
            await pilot.press("slash")
            box = app.query_one("#search-box")
            box.post_message(events.Paste("citrix"))
            await self.settle(pilot)
            self.assertEqual(box.value, "citrix")
            self.assertEqual(self.titles(app), ["CitrixBleed returns"])
            await pilot.press("home", "x")
            self.assertEqual(box.value, "xcitrix")

    async def test_clicking_away_from_search_turns_commands_back_on(self):
        app = self.make_app()
        async with app.run_test(size=(160, 45)) as pilot:
            await self.settle(pilot)
            await pilot.press("slash", "e")
            self.assertEqual(app.prompt, "search")
            app.set_focus(None)
            await self.settle(pilot)
            self.assertIsNone(app.prompt)

    async def api_app(self, pilot, app):
        await self.settle(pilot)
        cybrwire.enrichment_engine.providers["abusech"] = mock.Mock()
        self.addCleanup(cybrwire.enrichment_engine.providers.pop, "abusech", None)
        await pilot.press("v", "v")
        await self.settle(pilot)
        self.assertEqual(app.main_view_mode, "api_tools")

    async def test_api_tools_typing_goes_to_its_box_and_commands_stay_off(self):
        app = self.make_app()
        with mock.patch.object(app, "action_refresh") as refresh, mock.patch.object(app, "action_quit") as quit_:
            async with app.run_test(size=(160, 45)) as pilot:
                await self.api_app(pilot, app)
                await pilot.press("slash", "r", "w", "i", "q")
                self.assertEqual(app.query_one("#indicator-box").value, "/rwiq")
                self.assertEqual(app.prompt, "indicator")
                self.assertFalse(app.watch_only)
                refresh.assert_not_called()
                quit_.assert_not_called()
                # Esc clears the box and gives the single-key commands back
                await pilot.press("escape")
                await self.settle(pilot)
                self.assertEqual(app.query_one("#indicator-box").value, "")
                self.assertIsNone(app.prompt)
                await pilot.press("r")
                refresh.assert_called_once()

    async def test_api_tools_v_leaves_only_when_the_box_is_empty(self):
        app = self.make_app()
        async with app.run_test(size=(160, 45)) as pilot:
            await self.api_app(pilot, app)
            await pilot.press("a", "v")
            self.assertEqual(app.query_one("#indicator-box").value, "av")
            await pilot.press("escape", "slash")
            await self.settle(pilot)
            await pilot.press("v")
            await self.settle(pilot)
            self.assertEqual(app.main_view_mode, "alerts")
            self.assertIsNone(app.prompt)

    async def test_api_tools_enter_runs_the_lookup_and_paste_works(self):
        app = self.make_app()
        with mock.patch.object(cybrwire.enrichment_engine, "enrich", mock.AsyncMock(return_value={})) as enrich:
            async with app.run_test(size=(160, 45)) as pilot:
                await self.api_app(pilot, app)
                app.query_one("#indicator-box").post_message(events.Paste("198.51.100.7"))
                await self.settle(pilot)
                await pilot.press("enter")
                await self.settle(pilot)
                enrich.assert_awaited_once_with("198.51.100.7")
                self.assertEqual(app.api_tools_last_query, "198.51.100.7")
                self.assertIn("NO RESULTS", str(app.query_one("#api-content").render()))

    async def test_incidents_select_by_keyboard_and_mouse(self):
        cybrwire.alert_queue[:] = [
            alert("CVE-2099-1111 story", source="A"), alert("CVE-2099-1111 again", source="B"),
            alert("CVE-2099-2222 story", source="A", hours=2), alert("CVE-2099-2222 again", source="B", hours=2)]
        app = self.make_app()
        with mock.patch.object(links.webbrowser, "open") as browser:
            async with app.run_test(size=(160, 45)) as pilot:
                await self.settle(pilot)
                await pilot.press("v")
                await self.settle(pilot)
                table = app.query_one("#incident-table")
                self.assertEqual(table.row_count, 2)
                first, second = app.incident_list
                self.assertGreater(table.rows[table.ordered_rows[0].key].height, 3)  # Rows are as tall as their text
                self.assertIn("▶", table.get_row_at(0)[0].plain)
                await pilot.press("down")
                await self.settle(pilot)
                self.assertIs(app.selected_incident(), second)
                self.assertIn("▶", table.get_row_at(1)[0].plain)
                self.assertNotIn("▶", table.get_row_at(0)[0].plain)
                await pilot.click("#incident-table", offset=(10, 2))  # Inside the first, taller row
                await self.settle(pilot)
                self.assertIs(app.selected_incident(), first)
                browser.assert_not_called()
                await pilot.click("#incident-table", offset=(10, 2))
                await self.settle(pilot)
                browser.assert_called_once()

    async def test_footer_commands_are_clickable(self):
        app = self.make_app()
        async with app.run_test(size=(160, 45)) as pilot:
            await self.settle(pilot)
            footer = app.query_one(cybrwire.CybrWireFooter)
            first, _, _ = next(r for r in footer.regions if r[2] == "toggle_view")
            await pilot.click(cybrwire.CybrWireFooter, offset=(first + 1, 0))
            await self.settle(pilot)
            self.assertEqual(app.main_view_mode, "incidents")

    async def test_right_click_acts_like_v_in_that_panel_and_never_opens_a_row(self):
        app = self.make_app()
        with mock.patch.object(links.webbrowser, "open") as browser:
            async with app.run_test(size=(160, 45)) as pilot:
                await self.settle(pilot)
                await pilot.click("#feed-table", offset=(10, 0), button=3)  # On the selected row
                await self.settle(pilot)
                self.assertEqual(app.main_view_mode, "incidents")
                browser.assert_not_called()
                self.assertEqual(app.dashboard_panel_index, 0)
                await pilot.click("#dashboard", offset=(5, 5), button=3)
                await self.settle(pilot)
                self.assertEqual(app.panel_focus, "dashboard")
                self.assertEqual(app.dashboard_panel_index, 1)
                self.assertEqual(app.main_view_mode, "incidents")

    async def test_right_click_leaves_the_search_box(self):
        app = self.make_app()
        async with app.run_test(size=(160, 45)) as pilot:
            await self.settle(pilot)
            await pilot.press("slash", "x")
            await pilot.click("#dashboard", offset=(5, 5), button=3)
            await self.settle(pilot)
            self.assertIsNone(app.prompt)
            self.assertEqual(app.dashboard_panel_index, 1)

    async def test_left_click_selects_a_panel_without_changing_view(self):
        app = self.make_app()
        async with app.run_test(size=(160, 45)) as pilot:
            await self.settle(pilot)
            await pilot.click("#dashboard", offset=(5, 5))
            await self.settle(pilot)
            self.assertEqual((app.panel_focus, app.dashboard_panel_index), ("dashboard", 0))
            await pilot.click("#feed-table", offset=(10, 2))
            await self.settle(pilot)
            self.assertEqual(app.panel_focus, "main")

    async def test_pager_and_wheel_turn_war_room_pages(self):
        app = self.make_app()
        app.threat_summary = "LOCAL KEYWORD ANALYSIS"
        app.threat_summary_full = "\n".join(f"line {i}" for i in range(200))
        async with app.run_test(size=(160, 45)) as pilot:
            await self.settle(pilot)
            await pilot.click("#dashboard", offset=(5, 5), button=3)
            await self.settle(pilot)
            pager = app.query_one("#dashboard-pager")
            self.assertTrue(pager.display)
            page, total = app.dashboard_pages()
            self.assertEqual(page, 0)
            self.assertGreater(total, 1)
            next_start = pager.regions[0][0]  # On page 1, Next is the first thing that can be clicked
            await pilot.click("#dashboard-pager", offset=(next_start, 0))
            await self.settle(pilot)
            self.assertEqual(app.dashboard_pages()[0], 1)
            prev_start = pager.regions[0][0]
            await pilot.click("#dashboard-pager", offset=(prev_start, 0))
            await self.settle(pilot)
            self.assertEqual(app.dashboard_pages()[0], 0)
            panel = app.query_one("#dashboard")
            panel.last_turn = 0
            panel.turn(1)
            panel.turn(1)  # A second event from the same wheel notch
            await self.settle(pilot)
            self.assertEqual(app.dashboard_pages()[0], 1)

    async def test_new_briefing_is_clickable_and_pager_hides_where_nothing_pages(self):
        app = self.make_app()
        with mock.patch.object(app, "action_ai_refresh") as refresh:
            async with app.run_test(size=(160, 45)) as pilot:
                await self.settle(pilot)
                self.assertFalse(app.query_one("#dashboard-pager").display)
                await pilot.click("#dashboard", offset=(5, 5), button=3)
                await self.settle(pilot)
                pager = app.query_one("#dashboard-pager")
                self.assertTrue(pager.display)
                await pilot.click("#dashboard-pager", offset=(pager.regions[-1][0], 0))
                await self.settle(pilot)
                refresh.assert_called_once()

    async def test_view_buttons_match_the_keys(self):
        app = self.make_app()
        async with app.run_test(size=(160, 45)) as pilot:
            await self.settle(pilot)
            with mock.patch.object(links.webbrowser, "open") as browser:
                await pilot.click("#act-open")
                await self.settle(pilot)
                browser.assert_called_once_with(app.selected_alert()["url"])
            await pilot.click("#act-cve")
            await self.settle(pilot)
            self.assertIsInstance(app.screen, CveCard)
            await app.workers.wait_for_complete()
            await self.settle(pilot)
            await pilot.click("#cve-close")
            await self.settle(pilot)
            self.assertNotIsInstance(app.screen, CveCard)

    async def test_selected_row_keeps_its_cell_colors(self):
        app = self.make_app()
        async with app.run_test(size=(160, 45)) as pilot:
            await self.settle(pilot)
            self.assertEqual(app.query_one("#feed-table").cursor_foreground_priority, "renderable")

    async def test_pager_labels_fit_a_narrow_panel(self):
        app = self.make_app()
        async with app.run_test(size=(120, 45)) as pilot:
            await self.settle(pilot)
            app.threat_summary = "LOCAL KEYWORD ANALYSIS"
            app.threat_summary_full = "\n".join(f"line {i}" for i in range(200))
            await pilot.click("#dashboard", offset=(5, 5), button=3)
            await self.settle(pilot)
            pager = app.query_one("#dashboard-pager")
            self.assertLessEqual(pager.render().cell_length, pager.size.width)

    async def test_help_closes_by_mouse(self):
        app = self.make_app()
        async with app.run_test(size=(160, 45)) as pilot:
            await self.settle(pilot)
            await pilot.press("h")
            await self.settle(pilot)
            await pilot.click("#help-close")
            await self.settle(pilot)
            self.assertEqual(app.screen_stack[-1].__class__.__name__, "Screen")

    async def test_watchlist_card_opens_from_the_footer_and_it_all_fits_at_120_columns(self):
        cybrwire.alert_queue[:] = [alert(f"Story {i}") for i in range(2500)]
        app = self.make_app()
        async with app.run_test(size=(120, 45)) as pilot:
            await self.settle(pilot)
            footer = app.query_one(cybrwire.CybrWireFooter)
            self.assertLess(footer.regions[-1][1], 120)  # The last command is still on screen
            first = next(r[0] for r in footer.regions if r[2] == "edit_watchlist")
            await pilot.click(cybrwire.CybrWireFooter, offset=(first + 1, 0))
            await self.settle(pilot)
            self.assertIsInstance(app.screen, WatchCard)

    async def test_live_wire_click_jumps_and_clears_a_hiding_filter(self):
        app = self.make_app()
        async with app.run_test(size=(160, 45)) as pilot:
            await self.settle(pilot)
            await pilot.press("slash", *"openssl", "enter")
            await self.settle(pilot)
            target = next(a for a in SAMPLE if a["title"].startswith("CitrixBleed"))
            app.wire.shown = Shown(WireItem("REPORTED", target["title"], "", target), False, time.monotonic())
            app.wire_tick()
            await pilot.click("#ticker", offset=(30, 1))
            await self.settle(pilot)
            self.assertEqual(app.search_query, "")
            self.assertIs(app.selected_alert(), target)

    async def test_live_wire_shows_arrivals_and_badges_them_in_the_feed(self):
        app = self.make_app()
        async with app.run_test(size=(160, 45)) as pilot:
            await self.settle(pilot)
            wire = app.wire
            wire.end_sweep([], app.watchlist, {}, 0.0)  # The first check only sets the baseline
            fresh = alert("Vendor fixes zero-day flaw", severity="zeroday")
            evidence.apply_evidence([fresh])
            cybrwire.alert_queue.insert(0, fresh)
            clock = time.monotonic()
            wire.end_sweep([fresh], app.watchlist, {}, clock)
            app.wire_tick()
            app.update_display()
            await self.settle(pilot)
            panel = app.query_one("#ticker")
            self.assertIn("JUST IN", panel.drawn[3])
            self.assertIn("Vendor fixes zero-day flaw", panel.drawn[3])
            self.assertIn("REPORTED", panel.drawn[3])
            self.assertIn("1 new this session", panel.drawn[2])
            table = app.query_one("#feed-table")
            self.assertIn("LIVE", table.get_row_at(app.feed_rows.index(fresh))[3].plain)

    async def test_a_stale_arrival_is_new_but_not_just_in(self):
        app = self.make_app()
        async with app.run_test(size=(160, 45)) as pilot:
            await self.settle(pilot)
            wire = app.wire
            wire.end_sweep([], app.watchlist, {}, 0.0)
            late = alert("Vendor fixes zero-day flaw", severity="zeroday", hours=23)
            late["ts"] = datetime.now(timezone.utc) - timedelta(hours=23)
            evidence.apply_evidence([late])
            cybrwire.alert_queue.insert(0, late)
            wire.end_sweep([late], app.watchlist, {}, time.monotonic())
            app.wire_tick()
            await self.settle(pilot)
            body = app.query_one("#ticker").drawn[3]
            self.assertNotIn("JUST IN", body)
            self.assertIn(" NEW ", body)

    async def test_blocklists_do_not_read_as_exploitation_on_the_dashboard(self):
        app = self.make_app()
        async with app.run_test(size=(160, 45)) as pilot:
            await self.settle(pilot)
            now = datetime.now(timezone.utc)
            listed = [alert(f"TOP MALICIOUS IP: 198.51.100.{i}", source="Blocklist", kind="indicators", severity="exploit")
                      for i in range(50)]
            story = alert("LockBit claims another hospital", severity="ransomware")
            for a in [*listed, story]:
                a["ts"] = now - timedelta(minutes=5)
            cybrwire.alert_queue[:] = [*listed, story]
            console = Console(width=60, record=True, file=io.StringIO())
            console.print(app.make_dashboard())
            drawn = " ".join(console.export_text().split())
            self.assertIn("Items Seen 51", drawn)
            self.assertIn("IOCs Listed 50", drawn)
            self.assertIn("Exploits 0", drawn)
            self.assertIn("Ransomware wave", drawn)
            self.assertNotIn("Exploitation wave", drawn)

    async def test_live_wire_title_follows_a_real_check(self):
        app = self.make_app()
        async with app.run_test(size=(160, 45)) as pilot:
            await self.settle(pilot)
            app.wire.begin_sweep(61)
            app.wire.feed_started("CISA KEV")
            for _ in range(42):
                app.wire.feed_done()
            app.wire_tick()
            self.assertIn("checking 42/61 · CISA KEV", app.query_one("#ticker").drawn[1])
            app.wire.end_sweep([], app.watchlist, {}, time.monotonic())
            app.wire_tick()
            self.assertIn("last check 0s ago", app.query_one("#ticker").drawn[1])

    async def test_fetch_reports_progress_and_arrivals_through_the_wire(self):
        cybrwire.CONFIG = Config(sources=[{"name": "Fake", "url": "https://x.test/f", "type": "rss", "source_file": "curated"}])
        app = self.make_app()
        rss = "<rss><channel><item><title>Fetched story</title><link>https://x.test/1</link></item></channel></rss>"
        self.http_get.side_effect = None
        self.http_get.return_value = mock.Mock(raise_for_status=lambda: None, text=rss)
        async with app.run_test(size=(160, 45)) as pilot:
            await self.settle(pilot)
            await app.fetch_feeds()
            self.assertEqual((app.wire.total, app.wire.checked, app.wire.sweeping), (1, 1, False))
            self.assertEqual(app.last_arrivals, [])  # The session's first check is the baseline

    async def test_clicking_the_sound_setting_changes_it_and_not_the_view(self):
        app = self.make_app()
        with mock.patch.object(cybrwire.sound, "play"):
            async with app.run_test(size=(160, 45)) as pilot:
                await self.settle(pilot)
                app.wire_tick()
                await pilot.click("#ticker", offset=(150, 2))
                await self.settle(pilot)
                self.assertEqual(app.sound, "pc")

    async def test_world_clock_shows_and_z_hides_it_and_remembers(self):
        app = self.make_app()
        async with app.run_test(size=(80, 30)) as pilot:
            await self.settle(pilot)
            clock = app.query_one(cybrwire.WorldClock)
            self.assertTrue(clock.display)
            self.assertIn("LOC ", clock.shown[0])
            self.assertIn("TYO ", clock.shown[0])
            self.assertLessEqual(len(clock.shown[0]), clock.size.width)  # Squeezed to fit, not cut off
            await pilot.press("z")
            self.assertFalse(clock.display)
            self.assertFalse(cybrwire.STATE.settings["world_clock"])
            await pilot.press("z")
            self.assertTrue(clock.display)
            self.assertTrue(cybrwire.STATE.settings["world_clock"])

    async def test_world_clock_is_centered(self):
        app = self.make_app()
        async with app.run_test(size=(160, 30)) as pilot:
            await self.settle(pilot)
            line = app.query_one(cybrwire.WorldClock).render_line(0).text
            left, right = len(line) - len(line.lstrip()), len(line) - len(line.rstrip())
            self.assertGreater(left, 10)  # Not hugging the left edge
            self.assertLessEqual(abs(left - right), 1)

    async def test_sound_cycles_saves_and_stays_off_by_default(self):
        app = self.make_app()
        with mock.patch.object(cybrwire.sound, "play") as play:
            async with app.run_test(size=(160, 45)) as pilot:
                await self.settle(pilot)
                self.assertEqual(app.sound, "off")
                urgent = alert("Vendor fixes zero-day flaw")
                evidence.apply_evidence([urgent])
                app.announce_arrivals([urgent])
                play.assert_not_called()
                await pilot.press("b")
                self.assertEqual(app.sound, "pc")
                play.assert_called_once()  # A preview of the choice
                self.assertEqual(cybrwire.STATE.settings["sound"], "pc")
                play.reset_mock()
                app.announce_arrivals([alert("routine")])
                play.assert_not_called()
                app.announce_arrivals([urgent, urgent])
                play.assert_called_once()  # Once per check, however many arrived

    async def test_clicking_outside_a_card_closes_it_and_buttons_work(self):
        app = self.make_app()
        async with app.run_test(size=(160, 45)) as pilot:
            await self.settle(pilot)
            await pilot.press("W", *"ivanti", "enter", "down")
            await pilot.click("#watch-remove")
            await self.settle(pilot)
            self.assertNotIn("ivanti", app.watchlist.terms)
            await pilot.click(offset=(1, 1))
            await self.settle(pilot)
            self.assertNotIsInstance(app.screen, WatchCard)

    async def test_click_on_the_table_leaves_the_search_box(self):
        app = self.make_app()
        async with app.run_test(size=(160, 45)) as pilot:
            await self.settle(pilot)
            await pilot.press("slash")
            self.assertEqual(app.prompt, "search")
            await pilot.click("#feed-table", offset=(10, 0))
            await self.settle(pilot)
            self.assertIsNone(app.prompt)

    async def test_cve_card(self):
        app = self.make_app()
        feeds.KEV_DETAILS["CVE-2099-0001"] = {"dateAdded": "2099-01-05", "requiredAction": "Patch it.",
                                              "knownRansomwareCampaignUse": "Known", "dueDate": "2099-02-01"}
        cve_intel.EPSS["CVE-2099-0001"] = (0.42, 0.97)
        self.http_get.side_effect = None
        self.http_get.return_value = mock.Mock(raise_for_status=lambda: None,
                                               json=lambda: {"vulnerabilities": [{"cve": NVD_RECORD}], "data": []})

        browser = links.webbrowser.open
        async with app.run_test(size=(160, 45)) as pilot:
            await self.settle(pilot)
            await pilot.press("i")
            self.assertIsInstance(app.screen, CveCard)
            await app.workers.wait_for_complete()
            await self.settle(pilot)
            card = app.screen.render_card().plain
            for expected in ("CVSS 9.8", "CRITICAL", "EPSS 42.0%", "KNOWN EXPLOITED", "ransomware",
                             "Patch it.", "Auth bypass", "CWE-287", "ivanti endpoint", "EXPLOIT https://poc.test/b",
                             "IN YOUR FEEDS (1)", "1 of 2"):
                self.assertIn(expected, card)
            # Arrows go to the card, not the feed underneath
            row = app.query_one("#feed-table").cursor_row
            await pilot.press("right")
            self.assertEqual(app.screen.cve, "CVE-2099-0002")
            self.assertEqual(app.query_one("#feed-table").cursor_row, row)
            await pilot.press("x")
            browser.assert_called_with("https://poc.test/b")
            await pilot.press("enter")
            browser.assert_called_with("https://nvd.nist.gov/vuln/detail/CVE-2099-0002")
            self.assertEqual(app.main_view_mode, "alerts")
            await pilot.press("v")
            self.assertEqual(app.main_view_mode, "alerts")  # App commands don't leak through
            await pilot.press("escape")
            self.assertNotIsInstance(app.screen, CveCard)

    async def test_card_says_when_lookup_failed(self):
        app = self.make_app()
        async with app.run_test(size=(160, 45)) as pilot:
            await self.settle(pilot)
            app.push_screen(CveCard(["CVE-2099-0003"]))
            await self.settle(pilot)
            await app.workers.wait_for_complete()
            await self.settle(pilot)
            self.assertIn("lookup failed", app.screen.render_card().plain)

    async def test_config_tolerates_odd_watchlist_values(self):
        self.assertEqual(Watchlist(["A", None, 5]).terms, ["A", "5"])

    async def test_search_includes_saved_history_once(self):
        gone = alert("Vintage Sonicwall story", hours=2000)
        cybrwire.HISTORY.record([gone, SAMPLE[2]])
        app = self.make_app()
        async with app.run_test(size=(160, 45)) as pilot:
            await self.settle(pilot)
            await pilot.press("slash", *"sonicwall", "enter")
            rows = app.filtered_alerts()
            self.assertEqual([a["title"] for a in rows], ["Vintage Sonicwall story"])
            self.assertTrue(rows[0]["archived"])
            self.assertIn("from history", app.make_alert_preview(rows[0]).plain)
            await pilot.press("escape", "slash", *"citrixbleed")
            self.assertEqual(self.titles(app), ["CitrixBleed returns"])  # Loaded copy only

    async def test_duplicates_collapse_toggle_and_survive_filters(self):
        lead = alert("Ivanti patches critical EPMM authentication bypass flaw", source="A", severity="zeroday")
        other = alert("Ivanti patches critical EPMM authentication bypass bug", source="B")
        cybrwire.alert_queue[:] = [other, lead]
        app = self.make_app()
        async with app.run_test(size=(160, 45)) as pilot:
            await self.settle(pilot)
            self.assertEqual(app.filtered_alerts(), [lead])
            self.assertIn("Also reported by B", app.make_alert_preview(lead).plain)
            await pilot.press("f", "f")  # Posts only: the lead is filtered out, so the other report shows
            self.assertEqual(app.filtered_alerts(), [other])
            await pilot.press("f", "u")
            self.assertCountEqual(app.filtered_alerts(), [lead, other])
            self.assertFalse(cybrwire.STATE.settings["group_dupes"])

    async def test_notifications_skip_backlog_then_send_once(self):
        cybrwire.CONFIG = Config(sources=[], watchlist=["ivanti"], notifications={"ntfy_url": "https://n.test/t"})
        app = self.make_app()
        send = mock.AsyncMock(return_value={"ntfy": None})
        with mock.patch("cybrwire.notify.send", send):
            await app.send_notifications()
            send.assert_not_called()
            new = alert("Fresh Ivanti flaw")
            cybrwire.alert_queue.insert(0, new)
            await app.send_notifications()
            send.assert_called_once()
            self.assertIn("Fresh Ivanti flaw", send.call_args.args[2])
            await app.send_notifications()
            send.assert_called_once()

    async def test_failed_notification_is_retried(self):
        cybrwire.CONFIG = Config(sources=[], watchlist=["ivanti"], notifications={"ntfy_url": "https://n.test/t"})
        cybrwire.STATE.settings = {"notifications_started": True}
        app = self.make_app()
        app.notify = mock.Mock()
        send = mock.AsyncMock(return_value={"ntfy": "HTTP 500"})
        with mock.patch("cybrwire.notify.send", send):
            await app.send_notifications()
            await app.send_notifications()
        self.assertEqual(send.call_count, 2)

    async def test_no_cve_in_alert(self):
        app = self.make_app()
        async with app.run_test(size=(160, 45)) as pilot:
            await self.settle(pilot)
            await pilot.press("slash", *"openssl", "enter", "i")
            self.assertNotIsInstance(app.screen, CveCard)


if __name__ == "__main__":
    unittest.main()
