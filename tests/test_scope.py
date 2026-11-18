"""The alerts-per-hour scope under the map"""

import os
import sys
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import isolated  # noqa: E402,F401
from cybrwire import scope  # noqa: E402
from cybrwire.theme import PALETTES  # noqa: E402

NOW = datetime.now(timezone.utc)
NEON = PALETTES["neon"]


class Counts(unittest.TestCase):
    def test_alerts_are_bucketed_by_hour_oldest_first(self):
        alerts = [{"ts": NOW - timedelta(minutes=10)}, {"ts": NOW - timedelta(minutes=50)},
                  {"ts": NOW - timedelta(hours=3, minutes=5)}, {"ts": NOW - timedelta(hours=30)}]
        counts = scope.hourly_counts(alerts, NOW)
        self.assertEqual(len(counts), 24)
        self.assertEqual(counts[-1], 2)      # The last hour
        self.assertEqual(counts[-4], 1)      # Three hours back
        self.assertEqual(sum(counts), 3)     # The 30-hour-old one is outside the window

    def test_no_alerts_is_a_flat_line_not_an_error(self):
        counts = scope.hourly_counts([], NOW)
        self.assertEqual(counts, [0] * 24)
        lines = scope.render(counts, 40, 2, 0, NEON)
        self.assertEqual(len(lines), 3)


class Drawing(unittest.TestCase):
    COUNTS = [0, 1, 2, 5, 9, 14, 18, 12, 6, 3, 2, 1] * 2

    def test_the_trace_is_as_wide_and_tall_as_asked(self):
        lines = scope.render(self.COUNTS, 60, 2, 0, NEON)
        self.assertEqual(len(lines), 3)  # A heading and two rows
        self.assertTrue(all(len(line.plain) == 60 for line in lines[1:]))
        self.assertIn("peak 18", lines[0].plain)

    def test_busier_hours_are_drawn_higher(self):
        heights = scope.trace(self.COUNTS, 48, 2)
        self.assertEqual(len(heights), 96)
        peak_at = self.COUNTS.index(18) / (len(self.COUNTS) - 1) * 95
        self.assertLess(heights[round(peak_at)], heights[0])  # Smaller number is higher on screen
        self.assertTrue(all(0 <= h <= 7 for h in heights))

    def test_the_sweep_point_moves_and_wraps(self):
        def point_column(step):
            line = scope.render(self.COUNTS, 50, 2, step, NEON)
            for text in line[1:]:
                if "●" in text.plain:
                    return text.plain.index("●")
            return None
        found = {point_column(step) for step in range(0, 50, 5)}
        self.assertGreater(len({c for c in found if c is not None}), 3)
        self.assertEqual(point_column(7), point_column(7 + 50))  # One lap is the width

    def test_a_tiny_width_still_draws(self):
        self.assertEqual(len(scope.render(self.COUNTS, 3, 2, 0, NEON)), 3)


if __name__ == "__main__":
    unittest.main()
