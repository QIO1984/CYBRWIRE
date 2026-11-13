"""Evidence tiers, the Alerts filter and the new signal parsers. No network."""

import os
import sys
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import isolated  # noqa: E402,F401

from cybrwire import cve_intel  # noqa: E402
from cybrwire import digest  # noqa: E402
from cybrwire import evidence  # noqa: E402
from cybrwire import feeds  # noqa: E402
from cybrwire import notify  # noqa: E402
from cybrwire.evidence import CONFIRMED, LIKELY, REPORTED, apply_evidence, assess, assess_cve  # noqa: E402
from cybrwire.watchlist import Watchlist  # noqa: E402

NOW = datetime(2026, 11, 5, 12, tzinfo=timezone.utc)


def alert(title, source="Feed", kind="news", summary="", hours=1, severity="info"):
    return {"title": title, "summary": summary, "source": source, "kind": kind, "severity": severity,
            "url": f"https://x.test/{title}", "ts": NOW - timedelta(hours=hours)}


def kev(cve, added, **extra):
    return {cve: {"cveID": cve, "dateAdded": added, "vendorProject": "Acme", "product": "Router",
                  "requiredAction": "Apply the update.", "dueDate": "2026-11-20", **extra}}


class Base(unittest.TestCase):
    def setUp(self):
        for store in (feeds.KEV_DETAILS, feeds.EUVD_EXPLOITED, cve_intel.EPSS):
            patcher = mock.patch.dict(store, clear=True)
            patcher.start()
            self.addCleanup(patcher.stop)
        for name in ("CIRCL_EXPLOITED", "CIRCL_POC"):
            patcher = mock.patch.object(feeds, name, set())
            patcher.start()
            self.addCleanup(patcher.stop)


class TierTests(Base):
    def test_recent_kev_is_confirmed_with_what_to_do(self):
        feeds.KEV_DETAILS.update(kev("CVE-2026-1001", "2026-11-03"))
        ev = assess(alert("KEV ACTIVE → CVE-2026-1001", "CISA KEV", "advisory"), NOW)
        self.assertEqual((ev.tier, ev.recent, ev.name), (CONFIRMED, True, "Acme Router"))
        self.assertIn("CISA KEV 2d ago", ev.reasons)
        self.assertEqual(ev.action, "Apply the update.")
        self.assertEqual(evidence.due_text(ev, NOW), "CISA deadline 20 Nov")

    def test_enisa_alone_also_confirms(self):
        feeds.EUVD_EXPLOITED["CVE-2026-1001"] = NOW - timedelta(days=1)
        ev = assess(alert("CVE-2026-1001 story"), NOW)
        self.assertEqual((ev.tier, ev.recent), (CONFIRMED, True))
        self.assertIn("ENISA exploited list", ev.reasons)

    def test_high_epss_is_likely_and_public_exploit_needs_a_raised_score(self):
        cve_intel.EPSS["CVE-2026-1001"] = (0.83, 0.99)
        self.assertEqual(assess(alert("CVE-2026-1001"), NOW).tier, LIKELY)
        feeds.CIRCL_POC.add("CVE-2026-1002")
        self.assertIsNone(assess(alert("CVE-2026-1002"), NOW))
        cve_intel.EPSS["CVE-2026-1002"] = (0.2, 0.9)
        self.assertEqual(assess(alert("CVE-2026-1002"), NOW).tier, LIKELY)

    def test_circl_sighting_is_only_reported(self):
        feeds.CIRCL_EXPLOITED.add("CVE-2026-1001")
        self.assertEqual(assess(alert("CVE-2026-1001"), NOW).tier, REPORTED)

    def test_news_headlines_can_report_exploitation(self):
        for title in ("Zyxel fixes zero-day exploited to hack nearly 1,000 network switches",
                      "CISA flags WordPress RCE flaw as actively exploited in attacks",
                      "Attackers Exploit Critical Siemens IoT2050 Flaw"):
            self.assertEqual(assess(alert(title), NOW).tier, REPORTED, title)

    def test_wording_that_does_not_claim_exploitation_does_not_count(self):
        for title in ("Flaw could be exploited to take over routers", "No evidence the bug was exploited in attacks",
                      "The Race Against the 3-Day Clock: Compliance Made Easy", "Patch Tuesday roundup"):
            self.assertIsNone(assess(alert(title), NOW), title)

    def test_advisories_and_summaries_cannot_claim_it_by_wording(self):
        self.assertIsNone(assess(alert("ZDI-26-874: (0Day) Cobalt Use-After-Free RCE", "ZDI Published", "advisory"), NOW))
        self.assertIsNone(assess(alert("How we help", "Rapid7 Research", summary="zero-day actively exploited"), NOW))

    def test_an_old_exploited_cve_mentioned_in_passing_is_not_the_story(self):
        feeds.KEV_DETAILS.update(kev("CVE-2021-1001", "2021-11-03"))
        self.assertIsNone(assess(alert("New Linux backdoor", summary="also uses CVE-2021-1001"), NOW))
        ev = assess(alert("CVE-2021-1001 still being hit"), NOW)
        self.assertEqual((ev.tier, ev.recent), (CONFIRMED, False))

    def test_a_zero_day_reported_today_outranks_an_older_listing(self):
        feeds.KEV_DETAILS.update(kev("CVE-2026-1001", "2026-10-16"))
        listed = assess(alert("CVE-2026-1001"), NOW)
        fresh = assess(alert("Zyxel fixes zero-day exploited to hack switches"), NOW)
        self.assertGreater(fresh.score, listed.score)
        self.assertTrue(fresh.zero_day)

    def test_fresh_official_listing_outranks_older_likely_items(self):
        feeds.KEV_DETAILS.update(kev("CVE-2026-1001", "2026-11-11"))
        cve_intel.EPSS["CVE-2026-2002"] = (0.97, 0.99)
        feeds.CIRCL_POC.add("CVE-2026-2002")
        fresh, likely = assess_cve("CVE-2026-1001", NOW), assess_cve("CVE-2026-2002", NOW)
        self.assertEqual(likely.tier, "LIKELY")
        self.assertGreater(fresh.score - 3, likely.score)

    def test_news_adds_to_official_evidence(self):
        feeds.KEV_DETAILS.update(kev("CVE-2026-1001", "2026-11-03"))
        plain = assess(alert("CVE-2026-1001 story"), NOW)
        reported = assess(alert("Hackers exploit CVE-2026-1001 in attacks"), NOW)
        self.assertGreater(reported.score, plain.score)
        self.assertIn("in the news", reported.reasons)


class SeverityTests(Base):
    def run_one(self, a):
        return apply_evidence([a], NOW)[0]["severity"]

    def test_keywords_no_longer_make_a_zero_day(self):
        self.assertEqual(self.run_one(alert("ZDI-26-874: (0Day) Cobalt Use-After-Free RCE", "ZDI Published", "advisory", severity="zeroday")), "info")
        self.assertEqual(self.run_one(alert("ZDI-CAN-36787: Autodesk", "ZDI Upcoming", "advisory", severity="zeroday")), "info")

    def test_summaries_no_longer_set_the_label(self):
        self.assertEqual(self.run_one(alert("Smashing Security podcast #491", summary="ransomware", severity="ransomware")), "info")

    def test_evidence_sets_the_label(self):
        feeds.KEV_DETAILS.update(kev("CVE-2026-1001", "2026-11-03"))
        self.assertEqual(self.run_one(alert("CVE-2026-1001")), "critical")
        self.assertEqual(self.run_one(alert("Vendor patches zero-day")), "zeroday")
        self.assertEqual(self.run_one(alert("Hackers exploit router bug")), "exploit")

    def test_headlines_still_name_ransomware_and_actors(self):
        self.assertEqual(self.run_one(alert("LockBit returns")), "ransomware")
        self.assertEqual(self.run_one(alert("Russian hackers target banks")), "apt")

    def test_a_country_needs_hacking_wording_to_be_apt(self):
        for title in ("Russian police arrest three over fraud", "Drone strikes hit Iran border town",
                      "China unveils new chip plan"):
            self.assertEqual(self.run_one(alert(title)), "info", title)
        for title in ("Iranian hackers breach water utility", "China-linked espionage campaign", "Lazarus steals crypto",
                      "Volt Typhoon hides in routers"):
            self.assertEqual(self.run_one(alert(title)), "apt", title)

    def test_exploit_label_needs_real_exploit_code(self):
        self.assertEqual(self.run_one(alert("[webapps] pizzafy-1.0 SQLi", "Exploit-DB", "advisory")), "exploit")
        self.assertEqual(self.run_one(alert("Remote code execution in Foo", "VulDB", "advisory")), "info")

    def test_a_product_named_after_its_vendor_does_not_repeat_it(self):
        self.assertEqual(feeds.product_name("WordPress", "WordPress Core"), "WordPress Core")
        self.assertEqual(feeds.product_name("Apple", "Multiple Products"), "Apple Multiple Products")
        self.assertEqual(feeds.product_name(None, "Router"), "Router")

    def test_indicators_are_left_alone(self):
        self.assertEqual(self.run_one(alert("1.2.3.4", "List", "indicators", severity="exploit")), "exploit")

    def test_agreeing_sources_add_weight_and_rows_are_not_duplicated(self):
        feeds.KEV_DETAILS.update(kev("CVE-2026-1001", "2026-11-03"))
        enisa = alert("Exploited (ENISA) → CVE-2026-1001", "ENISA Exploited", "advisory")
        enisa["signal_cve"] = "CVE-2026-1001"
        kept = apply_evidence([enisa, alert("CVE-2026-1001 in A", "A"), alert("CVE-2026-1001 in B", "B")], NOW)
        self.assertEqual([a["source"] for a in kept], ["A", "B"])
        self.assertIn("2 sources", kept[0]["evidence"].reasons)


class AlertFilterTests(Base):
    def test_what_counts(self):
        feeds.KEV_DETAILS.update(kev("CVE-2026-1001", "2026-11-03"))
        rows = [alert("CVE-2026-1001"), alert("Russian hackers target banks"), alert("LockBit returns"),
                alert("Harvard - 850,537 breached accounts", "Have I Been Pwned Latest Breaches")]
        apply_evidence(rows, NOW)
        for row in rows:
            self.assertTrue(evidence.is_alert(row, []), row["title"])

    def test_what_is_noise(self):
        rows = [alert("Nintendo chip supplier news"), alert("RANSOMWARE VICTIM: x (gang)", "Ransomware.live", "ransomware"),
                alert("[webapps] pizzafy SQLi", "Exploit-DB", "advisory")]
        apply_evidence(rows, NOW)
        for row in rows:
            self.assertFalse(evidence.is_alert(row, []), row["title"])
        self.assertTrue(evidence.is_alert(rows[0], ["nintendo"]))  # A watchlist hit always counts


class ParserTests(Base):
    def test_circl_is_signals_only(self):
        rows = feeds.parse_circl({"data": [
            {"type": "exploited", "vulnerability": "cve-2026-1001", "source": "https://t.me/badchannel/1"},
            {"type": "published-proof-of-concept", "vulnerability": "CVE-2026-1002", "source": "https://t.me/x"},
            {"type": "seen", "vulnerability": "CVE-2026-1003", "source": "https://bsky.app/x"},
            {"type": "exploited", "vulnerability": "GHSA-xxxx", "source": "https://x.test"},
        ]}, "CIRCL Exploited", "curated")
        self.assertEqual(rows, [])
        self.assertEqual(feeds.CIRCL_EXPLOITED, {"CVE-2026-1001"})
        self.assertEqual(feeds.CIRCL_POC, {"CVE-2026-1002"})

    def test_euvd(self):
        rows = feeds.parse_euvd([{"id": "EUVD-1", "aliases": "GHSA-x\nCVE-2024-27834\n", "description": "Bug <b>here</b>",
                                  "exploitedSince": "Nov 4, 2026, 12:00:00 AM"}, {"id": "EUVD-2", "aliases": "GHSA-y\n"}], "ENISA Exploited", "curated")
        self.assertEqual([r["title"] for r in rows], ["Exploited (ENISA) → CVE-2024-27834"])
        self.assertEqual(rows[0]["summary"], "Bug here")
        self.assertEqual(rows[0]["ts"], datetime(2026, 11, 4, tzinfo=timezone.utc))
        self.assertIn("CVE-2024-27834", feeds.EUVD_EXPLOITED)

    def test_kev_titles_name_the_product(self):
        rows = feeds.parse_cisa({"vulnerabilities": list(kev("CVE-2026-1001", "2026-11-03").values())}, "CISA KEV", "curated")
        self.assertEqual(rows[0]["title"], "KEV ACTIVE → CVE-2026-1001: Acme Router")


class OutputTests(Base):
    def setUp(self):
        super().setUp()
        feeds.KEV_DETAILS.update(kev("CVE-2026-1001", "2026-11-03"))
        self.row = alert("KEV ACTIVE → CVE-2026-1001: Acme Router", "CISA KEV", "advisory")
        apply_evidence([self.row], NOW)

    def test_notifications_trigger_on_new_confirmed_and_say_what_to_do(self):
        self.assertEqual(notify.triggered_by(self.row, [], notify.DEFAULT_TRIGGERS), "CONFIRMED Acme Router")
        _, body = notify.build_message([(self.row, "CONFIRMED Acme Router")])
        self.assertIn("Action: Apply the update.", body)

    def test_old_confirmed_does_not_notify(self):
        feeds.KEV_DETAILS.update(kev("CVE-2021-1001", "2021-11-03"))
        row = alert("CVE-2021-1001 still being hit")
        apply_evidence([row], NOW)
        self.assertIsNone(notify.triggered_by(row, [], ["confirmed"]))

    def test_digest_leads_with_evidence_and_action(self):
        rows = [self.row, alert("Plain story"), alert("RANSOMWARE VICTIM: x (gang)", "Ransomware.live", "ransomware")]
        text = digest.build_digest(rows, 24, Watchlist(), {}, {}, NOW)
        self.assertIn("EXPLOITATION EVIDENCE (1)", text)
        self.assertIn("[CONFIRMED ]", text)
        self.assertIn("Action: Apply the update.", text)
        self.assertIn("RANSOMWARE CLAIMS: 1", text)


if __name__ == "__main__":
    unittest.main()
