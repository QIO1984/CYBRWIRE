"""The IOC lookup page: what the box understands, what it suggests, and how answers read"""

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
from cybrwire import ai, history, ioc  # noqa: E402
from cybrwire import app as cybrwire_app  # noqa: E402
from cybrwire.config import Config  # noqa: E402
from cybrwire.enrichment import EnrichmentData, ThreatLevel, enrichment_engine  # noqa: E402
from cybrwire.theme import PALETTES  # noqa: E402

NEON = PALETTES["neon"]
NOW = datetime.now(timezone.utc)


def plain(renderable, width=100):
    console = Console(file=io.StringIO(), width=width, force_terminal=False)
    console.print(renderable)
    return console.file.getvalue()


def result(provider, level, score, malicious, **details):
    return EnrichmentData("198.51.100.7", "ip", provider, level, score, malicious, details, datetime.now())


def alert(title, kind="news", hours=1, **extra):
    return {"title": title, "summary": "", "source": extra.pop("source", "Feed"), "kind": kind, "severity": "info",
            "url": f"https://example.test/{abs(hash(title))}", "ts": NOW - timedelta(hours=hours), **extra}


class Understanding(unittest.TestCase):
    def test_defanged_indicators_are_cleaned_up(self):
        for typed, clean in (("hxxps://evil[.]com/a", "https://evil.com/a"), ("1[.]2[.]3[.]4", "1.2.3.4"),
                             ("evil(.)example(.)org", "evil.example.org"), ("  \"8.8.8.8\"  ", "8.8.8.8"),
                             ("hxxp[:]//bad[.]site", "http://bad.site"), ("user[@]evil.com", "user@evil.com"),
                             ("198.51.100.7", "198.51.100.7")):
            self.assertEqual(ioc.refang(typed), clean, typed)

    def test_the_type_is_named_precisely(self):
        sha256, md5 = "a" * 64, "b" * 32
        for value, label, kind in (("198.51.100.7", "IPv4", "ip"), ("2001:db8::1", "IPv6", "ip"), (md5, "MD5", "hash"),
                                   ("c" * 40, "SHA-1", "hash"), (sha256, "SHA-256", "hash"), ("d" * 128, "SHA-512", "hash"),
                                   ("evil.example.org", "Domain", "domain"), ("https://evil.example.org/x", "URL", "url"),
                                   ("", "", "")):
            self.assertEqual(ioc.describe(value), (label, kind), value)

    def test_the_chip_reads_the_cleaned_up_value_and_is_blank_when_empty(self):
        self.assertEqual(ioc.kind_chip("", NEON).plain, "")
        self.assertEqual(ioc.kind_chip("hxxps://evil[.]com", NEON).plain.strip(), "URL")
        self.assertEqual(ioc.kind_chip("1.2.3.4", NEON).plain.strip(), "IPv4")


class Suggestions(unittest.TestCase):
    def test_recent_lookups_come_first_then_fresh_feed_indicators_without_repeats(self):
        alerts = [alert("a", "indicators", 5, ioc="203.0.113.9", threat="Emotet", source="ThreatFox"),
                  alert("b", "indicators", 1, ioc="198.51.100.7", source="URLhaus"),
                  alert("c", "indicators", 2, ioc="192.0.2.0/24", ioc_type="cidr", source="Spamhaus"),
                  alert("not an indicator", "news", 1, ioc="10.0.0.1")]
        rows = ioc.suggestions(["198.51.100.7", "evil.example.org"], alerts)
        self.assertEqual([(r.origin, r.value) for r in rows],
                         [("recent", "198.51.100.7"), ("recent", "evil.example.org"), ("feed", "192.0.2.0"), ("feed", "203.0.113.9")])
        self.assertIn("Emotet", rows[-1].note)
        self.assertIn("ThreatFox", rows[-1].note)

    def test_the_lists_are_capped(self):
        alerts = [alert(f"i{n}", "indicators", n, ioc=f"203.0.113.{n}") for n in range(40)]
        rows = ioc.suggestions([f"10.0.0.{n}" for n in range(20)], alerts)
        self.assertEqual(sum(r.origin == "recent" for r in rows), ioc.MAX_RECENT)
        self.assertEqual(sum(r.origin == "feed" for r in rows), ioc.MAX_FEED)

    def test_nothing_to_suggest_is_an_empty_list(self):
        self.assertEqual(ioc.suggestions([], []), [])


class Reading(unittest.TestCase):
    def test_the_verdict_is_the_worst_level_and_counts_who_flagged_it(self):
        results = {"abuseipdb": result("abuseipdb", ThreatLevel.HIGH, 85, True), "virustotal": result("virustotal", ThreatLevel.LOW, 8, False),
                   "pulsedive": None}
        worst, flagged, answered = ioc.verdict(results)
        self.assertEqual((worst, flagged, answered), (ThreatLevel.HIGH, 1, 2))
        self.assertEqual(ioc.verdict({}), (None, 0, 0))

    def test_facts_follow_a_fixed_order_and_skip_empties(self):
        details = {"report_count": 12, "country": "US", "isp": "", "malicious_vendors": 7, "is_whitelisted": False,
                   "threat": None, "domain": ["a.example", "b.example", "c.example", "d.example"]}
        self.assertEqual(ioc.facts(details),
                         [("Country", "US"), ("Domain", "a.example, b.example, c.example (+1)"), ("Reports", "12"),
                          ("Malicious", "7"), ("Whitelisted", "no")])
        self.assertEqual(len(ioc.facts({k: "x" for k, _label in ioc.FACTS})), ioc.MAX_FACTS)

    def test_the_provider_line_shows_what_is_on_and_what_cannot_answer(self):
        line = ioc.providers_line(["abuseipdb", "virustotal"], "hash", NEON).plain
        self.assertIn("● VirusTotal", line)
        self.assertIn("AbuseIPDB (not for hashes)", line)
        self.assertIn("○ Pulsedive (no key)", line)

    def test_an_answer_has_one_verdict_and_a_row_per_provider(self):
        results = {"abuseipdb": result("abuseipdb", ThreatLevel.CRITICAL, 92, True, country="US", isp="Example ISP", report_count=40),
                   "virustotal": result("virustotal", ThreatLevel.CLEAN, 0, False, malicious_vendors=0)}
        text = plain(ioc.render_results("198.51.100.7", results, NEON))
        for expected in ("198.51.100.7", "IPv4", "CRITICAL", "1 of 2 providers flag it", "AbuseIPDB", "92/100",
                         "VirusTotal", "Country US", "ISP Example ISP", "Reports 40", "not that it is safe"):
            self.assertIn(expected, text)

    def test_a_defanged_entry_says_how_it_was_typed(self):
        text = plain(ioc.render_results("https://evil.com", {"virustotal": result("virustotal", ThreatLevel.LOW, 10, False)}, NEON,
                                        shown_as="hxxps://evil[.]com"))
        self.assertIn("typed as hxxps://evil[.]com", text)

    def test_no_results_says_so_and_does_not_claim_safety(self):
        text = plain(ioc.render_results("198.51.100.7", {}, NEON))
        self.assertIn("NO RESULTS", text)
        self.assertIn("does not mean it is safe", text)

    def test_the_empty_states_read_properly(self):
        self.assertIn("Shift+K", plain(ioc.render_no_providers(NEON)))
        self.assertIn("Looking up 1.2.3.4 across 2 providers", plain(ioc.render_loading("1.2.3.4", 2, NEON)))


class InTheApp(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        for patcher in (mock.patch.object(ai, "generate", side_effect=AssertionError("no AI in tests")),
                        mock.patch("cybrwire.links.webbrowser.open"),
                        mock.patch("httpx.AsyncClient.get", mock.AsyncMock(side_effect=OSError("no network in tests")))):
            patcher.start()
            self.addCleanup(patcher.stop)
        enrichment_engine.providers["abuseipdb"] = mock.Mock()
        self.addCleanup(enrichment_engine.providers.pop, "abuseipdb", None)
        cybrwire_app.CONFIG = Config(sources=[], timezone="UTC")
        cybrwire_app.STATE.settings = {"filter_type_index": 0, "alerts_default": True}
        cybrwire_app.alert_queue[:] = [alert("198.51.100.7", "indicators", 2, ioc="198.51.100.7", threat="Emotet", source="ThreatFox"),
                                       alert("203.0.113.9", "indicators", 3, ioc="203.0.113.9", source="URLhaus")]
        cybrwire_app.HISTORY.record([])
        conn = sqlite3.connect(history.HISTORY_PATH)
        with conn:
            conn.execute("DELETE FROM alerts")
        conn.close()

    async def open_page(self, pilot, app):
        await self.settle(pilot)
        for _ in range(3):  # map -> alerts -> incidents -> API tools
            await pilot.press("v")
        await self.settle(pilot)
        self.assertEqual(app.main_view_mode, "api_tools")

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

    async def test_the_page_opens_on_suggestions_from_the_feeds(self):
        app = self.make_app()
        async with app.run_test(size=(150, 45)) as pilot:
            await self.open_page(pilot, app)
            self.assertTrue(app.query_one("#ioc-table").display)
            self.assertFalse(app.query_one("#api-results").display)
            self.assertEqual([r.value for r in app.ioc_rows], ["198.51.100.7", "203.0.113.9"])
            self.assertEqual(app.query_one("#ioc-table").row_count, 2)

    async def test_arrows_pick_a_suggestion_and_enter_looks_it_up(self):
        app = self.make_app()
        found = {"abuseipdb": result("abuseipdb", ThreatLevel.HIGH, 85, True, country="US")}
        with mock.patch.object(enrichment_engine, "enrich", mock.AsyncMock(return_value=found)) as enrich:
            async with app.run_test(size=(150, 45)) as pilot:
                await self.open_page(pilot, app)
                await pilot.press("down")
                await self.settle(pilot)
                self.assertEqual(app.selected_ioc().value, "203.0.113.9")
                await pilot.press("enter")
                await self.settle(pilot)
                enrich.assert_awaited_once_with("203.0.113.9")
                self.assertFalse(app.query_one("#ioc-table").display)
                shown = plain(app.make_api_tools_content())
                self.assertIn("HIGH", shown)
                self.assertIn("1 of 1 provider flag it", shown)
                self.assertEqual(app.api_tools_recent, ["203.0.113.9"])

    async def test_escape_goes_back_to_the_suggestions_and_the_lookup_is_now_recent(self):
        app = self.make_app()
        with mock.patch.object(enrichment_engine, "enrich", mock.AsyncMock(return_value={})):
            async with app.run_test(size=(150, 45)) as pilot:
                await self.open_page(pilot, app)
                await pilot.press("enter")  # The highlighted suggestion
                await self.settle(pilot)
                self.assertFalse(app.idle_api())
                await pilot.press("escape")
                await self.settle(pilot)
                self.assertTrue(app.idle_api())
                self.assertTrue(app.query_one("#ioc-table").display)
                self.assertEqual(app.ioc_rows[0].origin, "recent")
                self.assertEqual(app.ioc_rows[0].value, "198.51.100.7")
                self.assertEqual(app.query_one("#indicator-box").value, "")

    async def test_a_defanged_paste_is_cleaned_before_the_lookup(self):
        app = self.make_app()
        with mock.patch.object(enrichment_engine, "enrich", mock.AsyncMock(return_value={})) as enrich:
            async with app.run_test(size=(150, 45)) as pilot:
                await self.open_page(pilot, app)
                await pilot.press("slash")
                app.query_one("#indicator-box").value = "hxxps://evil[.]example[.]com/x"
                await self.settle(pilot)
                await pilot.press("enter")
                await self.settle(pilot)
                enrich.assert_awaited_once_with("https://evil.example.com/x")
                self.assertEqual(app.query_one("#indicator-box").value, "https://evil.example.com/x")
                self.assertIn("typed as hxxps://evil[.]example[.]com/x", plain(app.make_api_tools_content()))

    async def test_the_type_label_follows_what_is_typed(self):
        app = self.make_app()
        async with app.run_test(size=(150, 45)) as pilot:
            await self.open_page(pilot, app)
            await pilot.press("slash")
            app.query_one("#indicator-box").value = "203.0.113.9"
            await self.settle(pilot)
            self.assertEqual(plain(app.query_one("#indicator-kind").render()).strip(), "IPv4")
            self.assertIn("AbuseIPDB", plain(app.query_one("#api-providers").render()))
            app.query_one("#indicator-box").value = ""
            await self.settle(pilot)
            self.assertEqual(plain(app.query_one("#indicator-kind").render()).strip(), "")

    async def test_clicking_the_selected_suggestion_looks_it_up(self):
        app = self.make_app()
        with mock.patch.object(enrichment_engine, "enrich", mock.AsyncMock(return_value={})) as enrich:
            async with app.run_test(size=(150, 45)) as pilot:
                await self.open_page(pilot, app)
                await pilot.click("#ioc-table", offset=(12, 0))
                await self.settle(pilot)
                enrich.assert_awaited_once_with("198.51.100.7")

    async def test_without_providers_the_page_explains_how_to_start(self):
        enrichment_engine.providers.pop("abuseipdb", None)
        app = self.make_app()
        async with app.run_test(size=(150, 45)) as pilot:
            await self.open_page(pilot, app)
            self.assertFalse(app.idle_api())
            self.assertFalse(app.query_one("#ioc-table").display)
            self.assertIn("NO PROVIDERS YET", plain(app.make_api_tools_content()))

    async def test_new_lookup_button_and_add_keys_button_exist(self):
        app = self.make_app()
        with mock.patch.object(enrichment_engine, "enrich", mock.AsyncMock(return_value={})):
            async with app.run_test(size=(150, 45)) as pilot:
                await self.open_page(pilot, app)
                self.assertFalse(app.query_one("#act-clear").display)  # Nothing to start over from yet
                await pilot.press("enter")
                await self.settle(pilot)
                self.assertTrue(app.query_one("#act-clear").display)
                await pilot.click("#act-clear")
                await self.settle(pilot)
                self.assertTrue(app.idle_api())


if __name__ == "__main__":
    unittest.main()
