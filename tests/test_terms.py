"""Conditions the data providers set, kept true by tests so a later edit can't quietly break them"""

import asyncio
import os
import sys
import unittest
from unittest import mock

import yaml

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import isolated  # noqa: E402,F401

from cybrwire import app, paths  # noqa: E402


def feed(name):
    with open(os.path.join(paths.DATA_DIR, "cybrwire.yaml")) as f:
        return next(s for s in yaml.safe_load(f)["curated"] if s["name"] == name)


class Terms(unittest.TestCase):
    def test_spamhaus_is_fetched_at_most_hourly_as_it_asks(self):
        self.assertGreaterEqual(feed("Spamhaus Drop")["interval_minutes"], 60)

    def test_slow_changing_lists_are_not_polled_every_five_minutes(self):
        for name in ("DShield Attackers", "DShield Block", "Emerging Threats IPs"):
            self.assertGreaterEqual(feed(name)["interval_minutes"], 60, name)

    def test_have_i_been_pwned_is_asked_once_an_hour(self):
        calls = []

        class Resp:
            def json(self):
                return [{"Name": "A", "AddedDate": "2026-01-01"}]

        async def fake_get(self, url, **kw):
            calls.append(url)
            return Resp()

        app._breaches_checked = None
        with mock.patch("httpx.AsyncClient.get", fake_get):
            asyncio.run(app.fetch_breaches())
            asyncio.run(app.fetch_breaches())
        self.assertEqual(len(calls), 1)


if __name__ == "__main__":
    unittest.main()
