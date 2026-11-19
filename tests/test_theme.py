"""The themes: near-black grounds with their own neon, every colour readable, and period simulations kept pure"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import isolated  # noqa: E402,F401
from cybrwire.theme import COLD_WAR, DEFAULT_PALETTE, PALETTES  # noqa: E402

NEW = ["neon", "blade_runner", "tron", "ghost_shell", "vaporwave", "arctic", "ember", "matrix", "newsroom"]
OLDER = ["synthwave", "retro_warm", "amber_crt"]
READABLE = "text muted accent focus critical zeroday ransomware apt exploit info good warn bad".split()
SEVERITY = "critical zeroday ransomware apt exploit info".split()


def luminance(color: str) -> float:
    parts = [int(color[i:i + 2], 16) / 255 for i in (1, 3, 5)]
    r, g, b = [x / 12.92 if x <= 0.03928 else ((x + 0.055) / 1.055) ** 2.4 for x in parts]
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def contrast(a: str, b: str) -> float:
    hi, lo = sorted((luminance(a), luminance(b)), reverse=True)
    return (hi + 0.05) / (lo + 0.05)


class Themes(unittest.TestCase):
    def test_there_are_twelve_themes_in_a_stable_order_with_neon_first(self):
        self.assertEqual(list(PALETTES), NEW + OLDER)
        self.assertEqual(DEFAULT_PALETTE, "neon")

    def test_keys_and_names_are_unique(self):
        self.assertEqual(len({p.name for p in PALETTES.values()}), len(PALETTES))
        for key, palette in PALETTES.items():
            self.assertEqual(key, palette.key)

    def test_cold_war_is_not_a_cycle_theme(self):
        self.assertNotIn(COLD_WAR.key, PALETTES)

    def test_the_older_themes_are_still_there_for_saved_choices(self):
        for key in OLDER:
            self.assertIn(key, PALETTES)

    def test_only_the_period_simulations_are_pure(self):
        self.assertEqual({k for k, p in PALETTES.items() if p.pure}, {"amber_crt"})
        self.assertTrue(COLD_WAR.pure)


class Readability(unittest.TestCase):
    def test_the_new_themes_have_near_black_grounds(self):
        for key in NEW:
            self.assertLess(luminance(PALETTES[key].bg), 0.01, key)

    def test_every_text_and_severity_colour_is_readable_on_the_background_and_on_selected_rows(self):
        for key in NEW:
            p = PALETTES[key]
            for role in READABLE:
                for ground in (p.bg, p.surface):
                    self.assertGreaterEqual(contrast(getattr(p, role), ground), 4.5, f"{key}: {role} on {ground}")

    def test_borders_stay_quiet_but_visible(self):
        for key in NEW:
            p = PALETTES[key]
            self.assertGreater(contrast(p.border, p.bg), 1.4, key)
            self.assertLess(contrast(p.border, p.bg), 3.2, key)

    def test_severity_levels_can_be_told_apart_in_every_new_theme(self):
        for key in NEW:
            p = PALETTES[key]
            colours = [getattr(p, role) for role in SEVERITY if role not in ("exploit",)]
            self.assertGreaterEqual(len(set(colours)), 4, key)
            self.assertNotEqual(p.critical, p.zeroday, key)


class Blurbs(unittest.TestCase):
    def test_every_theme_has_a_short_description_for_the_picker(self):
        for key, palette in PALETTES.items():
            self.assertTrue(palette.blurb, f"{key} has no description")
            self.assertLessEqual(len(palette.blurb), 46, key)  # The picker's description column is 46 wide
        self.assertEqual(len({p.blurb for p in PALETTES.values()}), len(PALETTES))

    def test_the_picker_shows_a_description_on_every_row_and_never_scrolls_sideways(self):
        import asyncio
        from textual.app import App
        from cybrwire.theme_card import ThemeCard

        class Host(App):
            def on_mount(self):
                self.theme_mode, self.cold_war_mode = "neon", False
                self.push_screen(ThemeCard())

        async def run():
            app = Host()
            async with app.run_test(size=(120, 40)) as pilot:
                await pilot.pause()
                await pilot.pause()
                table = app.screen.query_one("#theme-table")
                rows = [[cell.plain for cell in table.get_row_at(i)] for i in range(table.row_count)]
                self.assertEqual([r[2] for r in rows], [p.blurb for p in PALETTES.values()])
                self.assertFalse(table.show_horizontal_scrollbar)  # The columns fit inside the card
        asyncio.run(run())


class Boot(unittest.TestCase):
    def test_every_new_theme_but_neon_has_its_own_boot_lines(self):
        for key in NEW[1:]:
            self.assertGreaterEqual(len(PALETTES[key].boot), 4, key)
            self.assertTrue(all(line == line.upper() or key == "vaporwave" for line in PALETTES[key].boot), key)


if __name__ == "__main__":
    unittest.main()
