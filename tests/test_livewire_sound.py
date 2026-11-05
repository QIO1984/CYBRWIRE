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

import livewire  # noqa: E402
import sound  # noqa: E402
from livewire import LiveWire, quiet_items  # noqa: E402
from watchlist import Watchlist  # noqa: E402

NOW = datetime.now(timezone.utc)
NO_TERMS = Watchlist()


def alert(title, severity="info", source=None, hours=1, kind="news", **extra):
    return {"title": title, "summary": "", "source": source or title, "severity": severity, "kind": kind,
            "url": f"https://x.test/{title}", "ts": NOW - timedelta(hours=hours), **extra}


class ArrivalTests(unittest.TestCase):
    def wire(self):
        wire = LiveWire()
        wire.end_sweep([], NO_TERMS, {}, 0.0)
        return wire

    def test_first_check_of_a_session_announces_nothing(self):
        wire = LiveWire()
        self.assertEqual(wire.end_sweep([alert("a")], NO_TERMS, {}, 0.0), [])
        self.assertEqual(wire.session_count, 0)
        self.assertEqual(wire.queue, [])

    def test_most_severe_comes_first_and_watchlist_breaks_ties(self):
        terms = Watchlist(["vendor"])
        wire = self.wire()
        wire.end_sweep([alert("plain"), alert("vendor flaw"), alert("big", "zeroday"), alert("other", "exploit")], terms, {}, 1.0)
        self.assertEqual([a["title"] for a in wire.queue], ["big", "other", "vendor flaw", "plain"])

    def test_a_burst_is_capped_and_counted(self):
        wire = self.wire()
        wire.end_sweep([alert(f"s{i}") for i in range(26)], NO_TERMS, {}, 1.0)
        self.assertEqual(wire.session_count, 26)
        self.assertEqual(len(wire.queue), livewire.MAX_ARRIVALS_SHOWN)
        for _ in range(livewire.MAX_ARRIVALS_SHOWN):
            wire.shown = None
            wire.tick(2.0, lambda: [])
        self.assertEqual(wire.shown.more, 21)  # Told once, on the last of the burst
        self.assertEqual(wire.more, 0)

    def test_noise_is_not_news(self):
        wire = self.wire()
        leader = alert("second report")
        old = alert("backlog from a newly added feed", hours=24 * 30)
        arrivals = wire.end_sweep([leader, old, alert("ioc", kind="indicators"), alert("undated", undated=True)],
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


class RotationTests(unittest.TestCase):
    def test_quiet_items_take_turns_at_their_pace(self):
        wire = LiveWire()
        items = [alert("a"), alert("b")]
        wire.tick(0.0, lambda: items)
        self.assertEqual(wire.shown.alert["title"], "a")
        wire.tick(livewire.QUIET_SECONDS - 1, lambda: items)
        self.assertEqual(wire.shown.alert["title"], "a")
        wire.tick(livewire.QUIET_SECONDS, lambda: items)
        self.assertEqual(wire.shown.alert["title"], "b")
        wire.tick(livewire.QUIET_SECONDS * 2, lambda: items)
        self.assertEqual(wire.shown.alert["title"], "a")

    def test_an_arrival_interrupts_a_quiet_item_but_not_another_arrival(self):
        wire = LiveWire()
        wire.baseline_done = True
        wire.tick(0.0, lambda: [alert("quiet")])
        wire.end_sweep([alert("one", "zeroday"), alert("two")], NO_TERMS, {}, 1.0)
        wire.tick(1.0, lambda: [])
        self.assertTrue(wire.shown.arrival)
        self.assertEqual(wire.shown.alert["title"], "one")
        wire.tick(2.0, lambda: [])
        self.assertEqual(wire.shown.alert["title"], "one")
        wire.tick(1.0 + livewire.ARRIVAL_SECONDS, lambda: [])
        self.assertEqual(wire.shown.alert["title"], "two")

    def test_nothing_to_show_is_said_plainly(self):
        wire = LiveWire()
        wire.tick(0.0, lambda: [])
        self.assertIsNone(wire.shown)


class QuietItemTests(unittest.TestCase):
    def test_most_severe_first_within_the_window(self):
        items = quiet_items([alert("info"), alert("exploit", "exploit"), alert("zero", "zeroday"), alert("kev", "critical"),
                             alert("too old", "zeroday", hours=100)], NO_TERMS, {}, 24)
        self.assertEqual([a["title"] for a in items], ["kev", "zero", "exploit", "info"])

    def test_watchlist_hits_lead_their_severity(self):
        items = quiet_items([alert("plain", "exploit"), alert("vendor bug", "exploit", hours=5)], Watchlist(["vendor"]), {}, 24)
        self.assertEqual(items[0]["title"], "vendor bug")

    def test_one_source_cannot_take_over(self):
        victims = [alert(f"victim {i}", "ransomware", source="Ransomware.live") for i in range(20)]
        items = quiet_items(victims + [alert("news")], NO_TERMS, {}, 24)
        self.assertEqual(sum(a["source"] == "Ransomware.live" for a in items), livewire.MAX_QUIET_PER_SOURCE)
        self.assertIn("news", [a["title"] for a in items])

    def test_indicators_undated_and_duplicates_stay_out(self):
        dup = alert("dup")
        items = quiet_items([dup, alert("ioc", kind="indicators"), alert("undated", undated=True)], NO_TERMS,
                            {livewire.alert_key(dup): "x"}, 24)
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
