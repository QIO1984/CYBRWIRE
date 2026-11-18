"""Heat mood lighting: borders tint toward amber and red as threats rise, but never in the period simulations"""

import os
import sys
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import isolated  # noqa: E402,F401
from cybrwire import effects  # noqa: E402
from cybrwire.theme import COLD_WAR, PALETTES  # noqa: E402
from cybrwire.worldmap import _blend  # noqa: E402

NOW = datetime.now(timezone.utc)


def channels(color):
    return [int(color[i:i + 2], 16) for i in (1, 3, 5)]


def distance(a, b):
    return sum(abs(x - y) for x, y in zip(channels(a), channels(b)))


class Fake(effects.EffectsMixin):
    """The mixin on its own: just what it reads from the app"""

    def __init__(self, palette="neon", heat=0.0, effects_on=True, alerts=()):
        self.palette = COLD_WAR if palette == "cold_war" else PALETTES[palette]
        self.effects_on = effects_on
        self.mood_heat = heat
        self.recency_hours = 24
        self.all_alerts = list(alerts)
        self.dirty_marks = 0

    def mark_dirty(self):
        self.dirty_marks += 1


def alert(severity, kind="news", hours=1):
    return {"severity": severity, "kind": kind, "ts": NOW - timedelta(hours=hours)}


class Tint(unittest.TestCase):
    def test_a_calm_screen_is_not_tinted(self):
        app = Fake(heat=effects.CALM_BELOW)
        self.assertEqual(app.mood(app.palette.focus), app.palette.focus)
        self.assertEqual(Fake(heat=0).mood("#123456"), "#123456")

    def test_a_hot_screen_moves_toward_red_and_a_warm_one_toward_amber(self):
        p = PALETTES["neon"]
        hot, warm = Fake(heat=100), Fake(heat=effects.CALM_BELOW + 5)
        self.assertLess(distance(hot.mood(p.border, 0.9), p.bad), distance(p.border, p.bad))
        self.assertLess(distance(warm.mood(p.border, 0.9), p.warn), distance(p.border, p.warn))
        self.assertLess(distance(hot.mood(p.focus), p.bad), distance(p.focus, p.bad))

    def test_the_tint_grows_with_the_heat(self):
        p = PALETTES["neon"]
        shifts = [distance(Fake(heat=h).mood(p.border, 0.9), p.border) for h in (35, 50, 70, 100)]
        self.assertEqual(shifts, sorted(shifts))
        self.assertGreater(shifts[-1], shifts[0])

    def test_the_period_simulations_never_get_the_mood_light(self):
        for name in ("amber_crt", "cold_war"):
            app = Fake(palette=name, heat=100)
            self.assertFalse(app.mood_active())
            self.assertEqual(app.mood(app.palette.focus), app.palette.focus, name)
            self.assertEqual(app.mood(app.palette.border, 0.9), app.palette.border, name)

    def test_the_other_themes_do_get_it(self):
        for name in ("neon", "retro_warm", "synthwave", "blade_runner", "newsroom"):
            self.assertTrue(Fake(palette=name, heat=100).mood_active(), name)

    def test_effects_off_means_no_tint(self):
        app = Fake(heat=100, effects_on=False)
        self.assertEqual(app.mood(app.palette.focus), app.palette.focus)


class Easing(unittest.TestCase):
    def test_the_shown_level_glides_toward_the_real_one(self):
        app = Fake(alerts=[alert("ransomware")] * 9 + [alert("info")])  # 90 percent of stories are threats
        steps = []
        for _ in range(4):
            app.mood_tick()
            steps.append(app.mood_heat)
        self.assertEqual(steps, sorted(steps))
        self.assertLess(steps[0], 90 * 0.5)   # The first tick is a small step, not a jump
        for _ in range(60):
            app.mood_tick()
        self.assertEqual(app.mood_heat, 90.0)

    def test_it_asks_for_a_redraw_only_when_a_whole_step_changes(self):
        app = Fake(alerts=[alert("ransomware")] * 9 + [alert("info")])
        for _ in range(80):
            app.mood_tick()
        self.assertLessEqual(app.dirty_marks, effects.MOOD_STEPS)
        before = app.dirty_marks
        app.mood_tick()  # Settled: nothing more to draw
        self.assertEqual(app.dirty_marks, before)

    def test_it_fades_back_to_calm_and_stays_off_in_a_pure_mode(self):
        app = Fake(heat=80, alerts=[alert("info")] * 10)
        for _ in range(60):
            app.mood_tick()
        self.assertEqual(app.mood_heat, 0.0)
        crt = Fake(palette="amber_crt", heat=80, alerts=[alert("ransomware")] * 10)
        for _ in range(60):
            crt.mood_tick()
        self.assertEqual(crt.mood_heat, 0.0)


class Heat(unittest.TestCase):
    def test_heat_is_the_share_of_stories_that_are_threats(self):
        app = Fake(alerts=[alert("critical"), alert("exploit"), alert("info"), alert("info"),
                           alert("ransomware", "indicators"), alert("critical", hours=100)])
        self.assertEqual(app.threat_heat(), 50.0)  # Indicators and anything outside the window do not count

    def test_no_stories_is_zero_not_an_error(self):
        self.assertEqual(Fake().threat_heat(), 0.0)


if __name__ == "__main__":
    unittest.main()
