"""
Duplicate grouping, history, notifications, digest and secret handling tests.
No network, no AI calls, and the real state and history files are never touched.
"""

import logging
import os
import stat
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock
from urllib.parse import parse_qs

import httpx

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ["CYBRWIRE_KEYCHAIN"] = "off"  # Tests must never touch the real keychain

import config  # noqa: E402
import digest  # noqa: E402
import feeds  # noqa: E402
import notify  # noqa: E402
from dedupe import group_duplicates  # noqa: E402
from history import History  # noqa: E402
from state import alert_key  # noqa: E402
from watchlist import Watchlist  # noqa: E402

NOW = datetime.now(timezone.utc)


def alert(title, source="A", severity="info", hours=1, kind="news", summary=""):
    return {"title": title, "summary": summary, "source": source, "severity": severity, "kind": kind,
            "source_file": "curated", "url": f"https://example.test/{source}/{abs(hash(title))}",
            "ts": NOW - timedelta(hours=hours)}


class Grouping(unittest.TestCase):
    def group(self, *alerts):
        return group_duplicates(list(alerts))

    def test_same_story_different_sources_merges_under_most_severe(self):
        a = alert("Ivanti patches critical EPMM authentication bypass flaw", "A")
        b = alert("Ivanti patches critical EPMM authentication bypass bug", "B", severity="zeroday", hours=5)
        g = self.group(a, b)
        self.assertEqual(g.leader_of, {alert_key(a): alert_key(b)})
        self.assertEqual(g.others[alert_key(b)], [a])

    def test_same_source_is_not_a_duplicate(self):
        # CISA posts the same headline for different additions
        self.assertEqual(self.group(alert("CISA Adds One Known Exploited Vulnerability to Catalog", "CISA", hours=1),
                                    alert("CISA Adds One Known Exploited Vulnerability to Catalog", "CISA", hours=30)).leader_of, {})

    def test_different_cves_stay_apart(self):
        self.assertEqual(self.group(alert("Chromium CVE-2099-0001: Use after free in the browser", "A"),
                                    alert("Chromium CVE-2099-0002: Use after free in the browser", "B")).leader_of, {})

    def test_too_far_apart_in_time(self):
        self.assertEqual(self.group(alert("Ivanti patches critical EPMM authentication bypass flaw", "A", hours=1),
                                    alert("Ivanti patches critical EPMM authentication bypass flaw", "B", hours=100)).leader_of, {})

    def test_short_titles_and_different_stories_and_indicators_stay_apart(self):
        self.assertEqual(self.group(alert("Patch Tuesday", "A"), alert("Patch Tuesday", "B")).leader_of, {})
        self.assertEqual(self.group(alert("Ivanti patches critical EPMM authentication flaw", "A"),
                                    alert("Fortinet warns about exploited FortiWeb authentication flaw", "B")).leader_of, {})
        self.assertEqual(self.group(alert("MALWARE URL http://x.test/a payload emotet today", "A", kind="indicators"),
                                    alert("MALWARE URL http://x.test/a payload emotet today", "B", kind="indicators")).leader_of, {})


class HistoryStore(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, "h.db")
        self.history = History(self.path)

    def test_round_trip_and_first_copy_wins(self):
        a = alert("Ivanti flaw", summary="Exploited")
        self.history.record([a])
        self.history.record([{**a, "title": "Changed"}])
        rows = self.history.search("exploited ivanti")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["title"], "Ivanti flaw")
        self.assertEqual(rows[0]["ts"], a["ts"])
        self.assertTrue(rows[0]["archived"])
        self.assertEqual(alert_key(rows[0]), alert_key(a))

    def test_wildcards_are_literal_and_injection_is_inert(self):
        self.history.record([alert("plain title"), alert("100% sure")])
        self.assertEqual([r["title"] for r in self.history.search("100%")], ["100% sure"])
        self.assertEqual(self.history.search("%"), [r for r in self.history.search("%") if "%" in r["title"]])
        self.assertEqual(self.history.search("'; DROP TABLE alerts; --"), [])
        self.assertEqual(len(self.history.search("title")), 1)

    def test_old_rows_expire(self):
        self.history.record([alert("ancient item", hours=24 * 400), alert("recent item")])
        self.assertEqual(self.history.search("ancient"), [])
        self.assertEqual(len(self.history.search("recent")), 1)

    def test_file_is_private(self):
        self.history.record([alert("x")])
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o600)

    def test_broken_database_does_not_raise(self):
        with open(self.path, "w") as f:
            f.write("not a database")
        self.history.record([alert("x")])
        self.assertEqual(self.history.search("x"), [])


class Notifications(unittest.IsolatedAsyncioTestCase):
    def test_selection(self):
        w = Watchlist(["ivanti"])
        hit = alert("Ivanti flaw")
        chosen = notify.select_new(
            [hit, alert("Unrelated"), alert("Ivanti old", hours=100), alert("Ivanti ioc", kind="indicators"),
             alert("Ivanti seen"), alert("Ivanti dup"), alert("KEV ACTIVE → CVE-1", severity="critical"),
             alert("Zero", severity="zeroday")],
            {alert_key(alert("Ivanti seen")): "x"}, w, ["watchlist"], {alert_key(alert("Ivanti dup")): "leader"})
        self.assertEqual([a["title"] for a, _ in chosen], ["Ivanti flaw"])
        both = notify.select_new([alert("KEV ACTIVE → CVE-1"), alert("Zero", severity="zeroday")], {}, w, ["kev", "zeroday"], {})
        self.assertEqual([r for _, r in both], ["KEV", "ZERO-DAY"])

    def test_message_caps_length(self):
        title, body = notify.build_message([(alert(f"Item {i}"), "KEV") for i in range(12)])
        self.assertIn("12 new alerts", title)
        self.assertIn("...and 4 more", body)

    async def test_payloads_block_pings_and_report_without_secret_urls(self):
        calls = {}

        async def fake_post(self, url, **kwargs):
            calls[url] = kwargs
            if "discord" in url:
                request = notify.httpx.Request("POST", url)
                raise notify.httpx.HTTPStatusError(f"failed for {url}", request=request,
                                                   response=notify.httpx.Response(404, request=request))
            return mock.Mock(raise_for_status=lambda: None)

        settings = {"ntfy_url": "https://ntfy.sh/secret-topic", "ntfy_token": "tok",
                    "discord_webhook": "https://discord.test/hook/secret", "slack_webhook": "https://slack.test/secret"}
        with mock.patch("httpx.AsyncClient.post", fake_post):
            results = await notify.send(settings, "T", "<!channel> @everyone héllo")
        self.assertEqual(calls["https://ntfy.sh/"]["json"]["topic"], "secret-topic")
        self.assertEqual(calls["https://ntfy.sh/"]["headers"]["Authorization"], "Bearer tok")
        self.assertEqual(calls["https://discord.test/hook/secret"]["json"]["allowed_mentions"], {"parse": []})
        self.assertIn("&lt;!channel&gt;", calls["https://slack.test/secret"]["json"]["text"])
        self.assertEqual(results["discord"], "HTTP 404")
        self.assertNotIn("secret", str(results))


class Digest(unittest.TestCase):
    def test_sections_merge_and_window(self):
        alerts = [
            alert("Ivanti patches critical EPMM authentication bypass flaw", "A", severity="zeroday"),
            alert("Ivanti patches critical EPMM authentication bypass bug", "B"),
            alert("KEV ACTIVE → CVE-2099-0001", "CISA KEV", severity="critical", kind="advisory"),
            alert("Too old to include in this window", "C", hours=50),
            alert("MALWARE URL thing", "D", kind="indicators"),
        ]
        text = digest.build_digest(alerts, 24, Watchlist(["ivanti"]), {}, {"Dead Feed": ("e", 1)})
        self.assertIn("last 24h", text)
        self.assertIn("1 duplicate reports merged", text)
        self.assertIn("WATCHLIST HITS (1)", text)
        self.assertIn("NEW IN CISA KEV (1)", text)
        self.assertIn("ZERO-DAYS (1)", text)
        self.assertIn("Dead Feed", text)
        self.assertNotIn("Too old", text)
        self.assertNotIn("MALWARE URL", text)

    def test_empty(self):
        self.assertIn("0 stories", digest.build_digest([], 24, Watchlist(), {}, {}))


class FeedParsing(unittest.TestCase):
    def test_urlhaus(self):
        data = {"urls": [{"url": "http://bad.test/x", "threat": "malware_download", "url_status": "online",
                          "date_added": "2099-01-02 03:04:05 UTC", "urlhaus_reference": "https://urlhaus.abuse.ch/url/1/"}]}
        item = feeds.parse_urlhaus(data, "URLhaus", "curated")[0]
        self.assertEqual(item["ioc"], "http://bad.test/x")
        self.assertEqual(item["url"], "https://urlhaus.abuse.ch/url/1/")  # Never the malware URL
        self.assertEqual(item["threat"], "malware download")
        self.assertEqual(item["ts"].year, 2099)
        self.assertEqual(feeds.parse_urlhaus({}, "URLhaus", "curated"), [])


class Secrets(unittest.TestCase):
    def setUp(self):
        saved = set(config.SECRETS)
        self.addCleanup(lambda: (config.SECRETS.clear(), config.SECRETS.update(saved)))
        config.SECRETS.clear()

    def test_redacts_loaded_secrets_and_url_params(self):
        config.SECRETS.add("supersecretvalue")
        self.assertEqual(config.redact("token supersecretvalue here"), "token *** here")
        self.assertEqual(config.redact("GET https://x.test/api?indicator=1.2.3.4&key=abc123 failed"),
                         "GET https://x.test/api?indicator=1.2.3.4&key=*** failed")

    def test_log_lines_and_tracebacks_are_masked(self):
        config.SECRETS.add("supersecretvalue")
        formatter = config.RedactingFormatter("%(message)s")
        try:
            raise ValueError("bad supersecretvalue")
        except ValueError:
            record = logging.LogRecord("x", logging.ERROR, "f", 1, "see %s", ("supersecretvalue",), sys.exc_info())
        self.assertNotIn("supersecretvalue", formatter.format(record))

    def test_secure_file(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "f")
            open(path, "w").close()
            os.chmod(path, 0o664)
            config.secure_file(path)
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
            config.secure_file(os.path.join(d, "missing"))  # Doesn't raise

    def test_notification_urls_count_as_secrets(self):
        cfg = config.Config(notifications={"discord_webhook": "https://discord.test/secret-hook"},
                            ai={"api_key": "aikey-value"}, enrichment={"x": {"api_key": "enrich-value"}},
                            sources=[{"headers": {"X-Key": "header-value"}}])
        config._remember_secrets(cfg)
        self.assertEqual(config.SECRETS, {"https://discord.test/secret-hook", "aikey-value", "enrich-value", "header-value"})


class PushoverTests(unittest.IsolatedAsyncioTestCase):
    async def test_sends_form_fields_within_its_limits(self):
        sent = []

        def handler(request):
            sent.append(request)
            return httpx.Response(200, json={"status": 1})
        real = httpx.AsyncClient
        with mock.patch.object(notify.httpx, "AsyncClient", lambda **kw: real(transport=httpx.MockTransport(handler), **kw)):
            results = await notify.send({"pushover_token": "app-token", "pushover_user": "user-key"}, "T" * 400, "B" * 2000)
        self.assertEqual(results, {"pushover": None})
        self.assertEqual(str(sent[0].url), notify.PUSHOVER_URL)
        form = parse_qs(sent[0].content.decode())
        self.assertEqual((form["token"], form["user"]), (["app-token"], ["user-key"]))
        self.assertEqual(len(form["title"][0]), notify.PUSHOVER_MAX_TITLE)
        self.assertEqual(len(form["message"][0]), notify.PUSHOVER_MAX_MESSAGE)

    def test_needs_both_parts(self):
        self.assertFalse(notify.is_configured({"pushover_token": "a"}))
        self.assertFalse(notify.is_configured({"pushover_user": "b"}))
        self.assertTrue(notify.is_configured({"pushover_token": "a", "pushover_user": "b"}))


if __name__ == "__main__":
    unittest.main()
