"""Outage feeds: every status page parses the same way, and each service can be placed on the map"""

import os
import sys
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import isolated  # noqa: E402,F401
import yaml  # noqa: E402
from cybrwire import feeds, worldmap  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NOW = datetime.now(timezone.utc)


def rss(*items):
    body = "".join(f"<item><title>{t}</title><link>https://status.example/{i}</link><pubDate>{d}</pubDate>{extra}"
                   f"<description>{desc}</description></item>" for i, (t, d, extra, desc) in enumerate(items))
    return f'<?xml version="1.0"?><rss version="2.0" xmlns:status="https://status.example/"><channel><title>x</title>{body}</channel></rss>'


def stamp(minutes_ago):
    return (NOW - timedelta(minutes=minutes_ago)).strftime("%a, %d %b %Y %H:%M:%S GMT")


class StatusStates(unittest.TestCase):
    def test_an_available_status_line_is_not_an_incident(self):
        text = rss(("Microsoft Admin Center", stamp(5), "<status>Available</status>", "Updated when admins cannot reach Service health"))
        self.assertEqual(feeds.parse_status(text, "Microsoft 365 Status", "curated"), [])

    def test_a_degraded_status_line_is_an_active_outage_with_its_state_in_the_title(self):
        text = rss(("Microsoft Admin Center", stamp(5), "<status>Degraded</status>", "Updated when admins cannot reach Service health"))
        [row] = feeds.parse_status(text, "Microsoft 365 Status", "curated")
        self.assertFalse(row["resolved"])
        self.assertEqual(row["title"], "OUTAGE · Microsoft 365: Microsoft Admin Center (Degraded)")
        self.assertEqual(row["kind"], "outage")

    def test_an_event_with_a_state_field_resolves_by_it(self):
        text = rss(("Availability degradation of Packaging", stamp(30), "<status:state>Resolved</status:state>", "Brief detail"),
                   ("Pipelines delayed", stamp(20), "<status:state>Investigating</status:state>", "Brief detail"))
        rows = {r["title"].split(": ", 1)[1]: r for r in feeds.parse_status(text, "Azure DevOps Status", "curated")}
        self.assertTrue(rows["Availability degradation of Packaging"]["resolved"])
        self.assertFalse(rows["Pipelines delayed (Investigating)"]["resolved"])

    def test_statuspage_style_feeds_still_work_without_state_fields(self):
        text = rss(("Delayed traces", stamp(40), "", "<b>Resolved</b> - Fixed."), ("Elevated errors", stamp(10), "", "<b>Investigating</b> - Looking."),
                   ("Planned maintenance window", stamp(10), "", "Scheduled"), ("Upcoming", (NOW + timedelta(days=2)).strftime("%a, %d %b %Y %H:%M:%S GMT"), "", "later"))
        rows = {r["title"]: r for r in feeds.parse_status(text, "Datadog Status", "curated")}
        self.assertEqual(set(rows), {"RESOLVED · Datadog: Delayed traces", "OUTAGE · Datadog: Elevated errors"})


class ShippedFeeds(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(os.path.join(ROOT, "cybrwire", "data", "cybrwire.yaml")) as f:
            data = yaml.safe_load(f)
        cls.outages = [s for v in data.values() if isinstance(v, list) for s in v if isinstance(s, dict) and s.get("kind") == "outage"]

    def test_there_are_many_services_and_each_is_a_status_feed_named_like_the_rest(self):
        self.assertGreaterEqual(len(self.outages), 30)
        for src in self.outages:
            self.assertEqual(src["type"], "status", src["name"])
            self.assertTrue(src["name"].endswith(" Status"), src["name"])
            self.assertTrue(src["url"].startswith("https://"), src["name"])

    def test_no_service_or_address_is_listed_twice(self):
        names = [s["name"] for s in self.outages]
        urls = [s["url"] for s in self.outages]
        self.assertEqual(len(set(names)), len(names))
        self.assertEqual(len(set(urls)), len(urls))

    def test_every_service_has_a_home_on_the_map(self):
        for src in self.outages:
            service = src["name"].removesuffix(" Status").lower()
            self.assertIn(service, worldmap.SERVICE_HOMES, f"{src['name']} would not show on the map")


if __name__ == "__main__":
    unittest.main()
