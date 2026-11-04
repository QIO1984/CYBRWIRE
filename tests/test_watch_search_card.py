"""
Watchlist, search and CVE card tests. Run from the repo root:

    venv/bin/python -m unittest discover -s tests

No network, no AI calls, and the real state file is never touched.
"""

import asyncio
import os
import sqlite3
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Must happen before cybrwire is imported: it loads the state at import time
import state  # noqa: E402

_tmp = tempfile.TemporaryDirectory()
state.STATE_PATH = os.path.join(_tmp.name, "state.json")
import history  # noqa: E402

history.HISTORY_PATH = os.path.join(_tmp.name, "history.db")

import ai  # noqa: E402
import cve_card  # noqa: E402
import cve_intel  # noqa: E402
import cybrwire  # noqa: E402
import feeds  # noqa: E402
from config import Config  # noqa: E402
from cve_card import CveCard, exploit_status  # noqa: E402
from watch_card import WatchCard  # noqa: E402
from watchlist import Watchlist, matches_search  # noqa: E402

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
        for target in ("cybrwire.webbrowser.open", "cve_card.webbrowser.open"):
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
        cybrwire.STATE.settings = {}
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
                self.assertEqual(app.prompt_buffer, "qr")
                self.assertEqual(self.titles(app), [])
                refresh.assert_not_called()
                quit_.assert_not_called()
                await pilot.press("backspace", "backspace", *"citrix")
                self.assertEqual(self.titles(app), ["CitrixBleed returns"])
                await pilot.press("enter")
                self.assertIsNone(app.prompt)
                self.assertEqual(app.search_query, "citrix")
                self.assertEqual(app.hover_row, 0)
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
            self.assertEqual(app.prompt_buffer, "4vwia")
            self.assertEqual(app.kind_index, 0)
            self.assertEqual(app.main_view_mode, "alerts")
            self.assertFalse(app.watch_only)

    async def test_arrows_move_from_typing_to_results(self):
        app = self.make_app()
        async with app.run_test(size=(160, 45)) as pilot:
            await self.settle(pilot)
            await pilot.press("slash", *"ivanti", "down")
            self.assertIsNone(app.prompt)
            self.assertEqual(app.hover_row, 0)
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
                card = app.screen.render_card().plain
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
            second = app.page_alerts[1]
            await pilot.click("#feeds", offset=(10, 4))  # Border, padding, search bar, first row
            self.assertIs(app.selected_alert(), second)

    async def test_api_tools_typing_still_goes_to_its_input(self):
        app = self.make_app()
        with mock.patch.object(app, "action_refresh") as refresh, mock.patch.object(app, "action_quit") as quit_:
            async with app.run_test(size=(160, 45)) as pilot:
                await self.settle(pilot)
                app.main_view_mode = "api_tools"
                app.api_tools_input_mode = True
                await pilot.press("slash", "r", "w", "i", "q")
                self.assertEqual(app.api_tools_input_buffer, "/rwiq")
                self.assertIsNone(app.prompt)
                self.assertFalse(app.watch_only)
                self.assertEqual(app.screen_stack[-1].__class__.__name__, "Screen")
                refresh.assert_not_called()
                quit_.assert_not_called()

    async def test_cve_card(self):
        app = self.make_app()
        feeds.KEV_DETAILS["CVE-2099-0001"] = {"dateAdded": "2099-01-05", "requiredAction": "Patch it.",
                                              "knownRansomwareCampaignUse": "Known", "dueDate": "2099-02-01"}
        cve_intel.EPSS["CVE-2099-0001"] = (0.42, 0.97)
        self.http_get.side_effect = None
        self.http_get.return_value = mock.Mock(raise_for_status=lambda: None,
                                               json=lambda: {"vulnerabilities": [{"cve": NVD_RECORD}], "data": []})

        browser = cve_card.webbrowser.open
        async with app.run_test(size=(160, 45)) as pilot:
            await self.settle(pilot)
            await pilot.press("i")  # Nothing selected yet
            self.assertNotIsInstance(app.screen, CveCard)
            await pilot.press("down", "i")
            self.assertIsInstance(app.screen, CveCard)
            await app.workers.wait_for_complete()
            await self.settle(pilot)
            card = app.screen.render_card().plain
            for expected in ("CVSS 9.8", "CRITICAL", "EPSS 42.0%", "KNOWN EXPLOITED", "ransomware",
                             "Patch it.", "Auth bypass", "CWE-287", "ivanti endpoint", "EXPLOIT https://poc.test/b",
                             "IN YOUR FEEDS (1)", "1 of 2"):
                self.assertIn(expected, card)
            # Arrows go to the card, not the feed underneath
            offset = app.feed_page_offset
            await pilot.press("right")
            self.assertEqual(app.screen.cve, "CVE-2099-0002")
            self.assertEqual(app.feed_page_offset, offset)
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
        with mock.patch("notify.send", send):
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
        with mock.patch("notify.send", send):
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
