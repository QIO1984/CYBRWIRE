"""The default theme: near-black with neon, and every colour readable on its backgrounds"""

import unittest

from cybrwire.theme import COLD_WAR, DEFAULT_PALETTE, PALETTES


def luminance(color: str) -> float:
    parts = [int(color[i:i + 2], 16) / 255 for i in (1, 3, 5)]
    r, g, b = [x / 12.92 if x <= 0.03928 else ((x + 0.055) / 1.055) ** 2.4 for x in parts]
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def contrast(a: str, b: str) -> float:
    hi, lo = sorted((luminance(a), luminance(b)), reverse=True)
    return (hi + 0.05) / (lo + 0.05)


class NeonTheme(unittest.TestCase):
    def test_it_is_the_default_and_first_in_the_cycle(self):
        self.assertEqual(DEFAULT_PALETTE, "neon")
        self.assertEqual(next(iter(PALETTES)), "neon")

    def test_the_older_themes_are_still_there_for_saved_choices(self):
        for key in ("synthwave", "retro_warm", "amber_crt"):
            self.assertIn(key, PALETTES)

    def test_the_background_is_near_black(self):
        self.assertLess(luminance(PALETTES["neon"].bg), 0.01)

    def test_every_text_and_severity_colour_is_readable_on_the_background_and_on_selected_rows(self):
        p = PALETTES["neon"]
        roles = "text muted accent focus critical zeroday ransomware apt exploit info good warn bad".split()
        for role in roles:
            for ground in (p.bg, p.surface):
                self.assertGreaterEqual(contrast(getattr(p, role), ground), 4.5, f"{role} on {ground}")

    def test_the_borders_stay_quiet_but_visible(self):
        p = PALETTES["neon"]
        self.assertGreater(contrast(p.border, p.bg), 1.5)
        self.assertLess(contrast(p.border, p.bg), 3)

    def test_cold_war_is_not_a_cycle_theme(self):
        self.assertNotIn(COLD_WAR.key, PALETTES)


if __name__ == "__main__":
    unittest.main()
