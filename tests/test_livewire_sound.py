"""Live Wire logic and alert sounds. Nothing here plays through the speakers."""

import os
import sys
import tempfile
import unittest
import wave
from datetime import datetime, timedelta, timezone
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import isolated  # noqa: E402,F401

from cybrwire import evidence  # noqa: E402
from cybrwire import livewire  # noqa: E402
from cybrwire import sound  # noqa: E402
from cybrwire.livewire import LiveWire, wire_items  # noqa: E402
from cybrwire.watchlist import Watchlist  # noqa: E402

NOW = datetime.now(timezone.utc)
NO_TERMS = Watchlist()


def alert(title, severity="info", source=None, hours=1, kind="news", **extra):
    return {"title": title, "summary": "", "source": source or title, "severity": severity, "kind": kind,
            "url": f"https://x.test/{title}", "ts": NOW - timedelta(hours=hours), **extra}


def with_evidence(title, tier=evidence.CONFIRMED, score=100, recent=True, **extra):
    a = alert(title, **extra)
    a["evidence"] = evidence.Evidence(tier, score, ["because"], cve=extra.get("cve"), recent=recent)
    return a


class ArrivalTests(unittest.TestCase):
    def wire(self):
        wire = LiveWire()
        wire.end_sweep([], NO_TERMS, {}, 0.0)
        return wire

    def test_first_check_of_a_session_announces_nothing(self):
        wire = LiveWire()
        self.assertEqual(wire.end_sweep([with_evidence("a")], NO_TERMS, {}, 0.0), [])
        self.assertEqual(wire.session_count, 0)
        self.assertEqual(wire.queue, [])

    def test_only_evidence_or_a_watchlist_hit_is_announced(self):
        terms = Watchlist(["vendor"])
        wire = self.wire()
        routine, watched, proven = alert("routine"), alert("vendor news"), with_evidence("proven")
        arrivals = wire.end_sweep([routine, watched, proven], terms, {}, 1.0)
        self.assertEqual(arrivals, [proven, watched])
        self.assertEqual([i.label for i in wire.queue], [evidence.CONFIRMED, "WATCHLIST"])
        self.assertEqual(wire.session_count, 2)
        self.assertTrue(wire.is_fresh(routine))  # Still marked LIVE in the feed

    def test_an_old_exploited_cve_in_a_new_story_is_not_news(self):
        wire = self.wire()
        self.assertEqual(wire.end_sweep([with_evidence("old", recent=False)], NO_TERMS, {}, 1.0), [])

    def test_strongest_first_and_a_burst_is_capped_and_counted(self):
        wire = self.wire()
        wire.end_sweep([with_evidence(f"s{i}", score=i) for i in range(26)], NO_TERMS, {}, 1.0)
        self.assertEqual(wire.session_count, 26)
        self.assertEqual(wire.queue[0].headline, "s25")
        self.assertEqual(len(wire.queue), livewire.MAX_ARRIVALS_SHOWN)
        for _ in range(livewire.MAX_ARRIVALS_SHOWN):
            wire.shown = None
            wire.tick(2.0, lambda: [])
        self.assertEqual(wire.shown.more, 21)  # Told once, on the last of the burst
        self.assertEqual(wire.more, 0)

    def test_noise_is_not_news(self):
        wire = self.wire()
        leader = with_evidence("second report")
        old = with_evidence("backlog from a newly added feed", hours=24 * 30)
        arrivals = wire.end_sweep([leader, old, with_evidence("ioc", kind="indicators"), with_evidence("undated", undated=True)],
                                  NO_TERMS, {livewire.alert_key(leader): "someone"}, 1.0)
        self.assertEqual(arrivals, [])

    def test_fresh_badges_expire(self):
        wire = self.wire()
        a = alert("a")
        wire.end_sweep([a], NO_TERMS, {}, 100.0)
        self.assertTrue(wire.is_fresh(a))
        self.assertFalse(wire.expire_fresh(100.0 + livewire.FRESH_SECONDS - 1))
        self.assertTrue(wire.expire_fresh(100.0 + livewire.FRESH_SECONDS))
        self.assertFalse(wire.is_fresh(a))


def item(name):
    return livewire.WireItem("REPORTED", name, "", alert(name))


class RotationTests(unittest.TestCase):
    def test_items_take_turns_at_their_pace(self):
        wire = LiveWire()
        items = [item("a"), item("b")]
        wire.tick(0.0, lambda: items)
        self.assertEqual(wire.shown.item.headline, "a")
        wire.tick(livewire.QUIET_SECONDS - 1, lambda: items)
        self.assertEqual(wire.shown.item.headline, "a")
        wire.tick(livewire.QUIET_SECONDS, lambda: items)
        self.assertEqual(wire.shown.item.headline, "b")
        wire.tick(livewire.QUIET_SECONDS * 2, lambda: items)
        self.assertEqual(wire.shown.item.headline, "a")

    def test_an_arrival_interrupts_a_quiet_item_but_not_another_arrival(self):
        wire = LiveWire()
        wire.baseline_done = True
        wire.tick(0.0, lambda: [item("quiet")])
        wire.end_sweep([with_evidence("one", score=9), with_evidence("two", score=1)], NO_TERMS, {}, 1.0)
        wire.tick(1.0, lambda: [])
        self.assertTrue(wire.shown.arrival)
        self.assertEqual(wire.shown.item.headline, "one")
        wire.tick(2.0, lambda: [])
        self.assertEqual(wire.shown.item.headline, "one")
        wire.tick(1.0 + livewire.ARRIVAL_SECONDS, lambda: [])
        self.assertEqual(wire.shown.item.headline, "two")

    def test_nothing_to_show_is_said_plainly(self):
        wire = LiveWire()
        wire.tick(0.0, lambda: [])
        self.assertIsNone(wire.shown)


class WireItemTests(unittest.TestCase):
    def test_strongest_evidence_leads_and_says_why(self):
        strong = with_evidence("strong", score=150)
        weak = with_evidence("weak", evidence.REPORTED, score=60)
        items = wire_items([weak, strong, alert("no evidence at all")], NO_TERMS, {}, NOW)
        self.assertEqual([i.headline for i in items], ["strong", "weak"])
        self.assertEqual(items[0].label, evidence.CONFIRMED)
        self.assertIn("because", items[0].detail)

    def test_one_line_per_cve_named_by_product(self):
        a = with_evidence("story one", cve="CVE-1", source="A")
        b = with_evidence("story two", cve="CVE-1", source="B", score=120)
        b["evidence"].name = "Acme Router"
        items = wire_items([a, b], NO_TERMS, {}, NOW)
        self.assertEqual([i.headline for i in items], ["Acme Router CVE-1"])

    def test_watchlist_outranks_slightly_stronger_evidence(self):
        items = wire_items([with_evidence("plain", score=110), with_evidence("vendor bug", score=100)], Watchlist(["vendor"]), {}, NOW)
        self.assertEqual(items[0].headline, "vendor bug")

    def test_old_exploited_cves_and_week_old_stories_drop_out(self):
        items = wire_items([with_evidence("old cve", recent=False), with_evidence("stale", hours=24 * 8)], NO_TERMS, {}, NOW)
        self.assertEqual(items, [])

    def test_ransomware_claims_become_one_campaign_line(self):
        claims = [alert(f"RANSOMWARE VICTIM: v{i} (medusalocker) [US]", "ransomware", source="Ransomware.live") for i in range(17)]
        claims += [alert("RANSOMWARE VICTIM: lonely (tinygang)", "ransomware", source="Ransomware.live")]
        items = wire_items(claims, NO_TERMS, {}, NOW)
        self.assertEqual([i.headline for i in items], ["medusalocker claimed 17 victims in 48h"])
        self.assertEqual(items[0].label, "CAMPAIGN")
        self.assertEqual(items[0].search, "medusalocker")

    def test_breaches_follow_the_evidence(self):
        items = wire_items([alert("Harvard - 850,537 breached accounts", source="Have I Been Pwned Latest Breaches"),
                            with_evidence("proven")], NO_TERMS, {}, NOW)
        self.assertEqual([i.label for i in items], [evidence.CONFIRMED, "BREACH"])

    def test_indicators_undated_and_duplicates_stay_out(self):
        dup = with_evidence("dup")
        items = wire_items([dup, with_evidence("ioc", kind="indicators"), with_evidence("undated", undated=True)], NO_TERMS,
                           {livewire.alert_key(dup): "x"}, NOW)
        self.assertEqual(items, [])


class SoundTests(unittest.TestCase):
    def test_every_tone_is_a_valid_short_wav(self):
        for name, (_, make) in sound.TONES.items():
            if not make:
                continue
            with tempfile.TemporaryDirectory() as d:
                path = os.path.join(d, "t.wav")
                sound.write_wav(path, make())
                with wave.open(path) as f:
                    seconds = f.getnframes() / f.getframerate()
                    self.assertEqual((f.getnchannels(), f.getsampwidth()), (1, 2))
                    frames = f.readframes(f.getnframes())
                self.assertTrue(0.1 < seconds < 1.0, name)
                self.assertLess(abs(int.from_bytes(frames[:2], "little", signed=True)), 100)  # Fades in, so no click

    def test_cycle_starts_and_ends_at_off(self):
        seen, current = [], "off"
        for _ in sound.TONES:
            current = sound.next_tone(current)
            seen.append(current)
        self.assertEqual(seen[-1], "off")
        self.assertEqual(sound.next_tone("not-a-tone"), "off")

    def test_off_is_silent_and_no_player_falls_back_to_the_bell(self):
        bell = mock.Mock()
        with mock.patch.object(sound, "find_player", return_value=None):
            sound.play("off", bell)
            bell.assert_not_called()
            sound.play("pc", bell)
            bell.assert_called_once()
        bell.reset_mock()
        sound.play("bell", bell)
        bell.assert_called_once()

    def test_a_player_is_started_without_blocking(self):
        with mock.patch.object(sound, "find_player", return_value="fake-player"), \
                mock.patch.object(sound.subprocess, "run") as run:
            sound.play("pc", mock.Mock())
            for thread in sound.threading.enumerate():
                if thread is not sound.threading.main_thread():
                    thread.join(1)
        self.assertEqual(run.call_args.args[0][0], "fake-player")

    def test_a_broken_player_is_only_logged(self):
        with mock.patch.object(sound.subprocess, "run", side_effect=OSError):
            sound._run_player("fake-player", "x.wav")


if __name__ == "__main__":
    unittest.main()
