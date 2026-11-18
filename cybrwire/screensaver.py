"""The idle screensaver: digital rain with live headlines typing in and fading out, and a glow along
the bottom that follows the current threat level. Any key or click brings the dashboard back."""

import hashlib
import random
from dataclasses import dataclass
from typing import Callable, List, Optional, Tuple

from rich.text import Text
from textual import events
from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import Static

from .worldmap import _blend

GLYPHS = "ｱｲｳｴｵｶｷｸｹｺｻｼｽｾｿﾀﾁﾂﾃﾄ0123456789ABCDEF<>/\\=+*"
FRAME_SECONDS = 0.14
TYPE_CHARS_PER_STEP = 2
HOLD_STEPS = 34       # About five seconds fully shown
FADE_STEPS = 10
NEXT_HEADLINE_STEPS = 36
IGNORE_INPUT_SECONDS = 1.0  # Events right after it starts (a mouse already resting on the window) don't wake it


@dataclass
class Headline:
    tag: str
    title: str
    row: int
    col: int
    born: int


class Rain:
    """The animation as plain data, so it can be tested without a screen"""

    def __init__(self, cols: int, rows: int, seed: Optional[int] = None):
        self.cols, self.rows = max(8, cols), max(6, rows)
        self.rng = random.Random(seed)
        self.t = 0
        self.drops = [self._new_drop(initial=True) for _ in range(self.cols)]
        self.headline: Optional[Headline] = None
        self.headline_index = 0

    def _new_drop(self, initial: bool = False) -> dict:
        return {"y": self.rng.uniform(-self.rows, self.rows if initial else 0),
                "speed": self.rng.uniform(0.25, 0.7), "length": self.rng.randint(8, max(9, self.rows // 2))}

    def glyph(self, col: int, row: int) -> str:
        key = f"{col}:{row}:{self.t // 3}".encode()
        return GLYPHS[hashlib.md5(key).digest()[0] % len(GLYPHS)]

    def step(self, headlines: List[Tuple[str, str]]) -> None:
        self.t += 1
        for i, drop in enumerate(self.drops):
            drop["y"] += drop["speed"]
            if drop["y"] - drop["length"] > self.rows:
                self.drops[i] = self._new_drop()
        h = self.headline
        if h and self.t - h.born > len(h.title) / TYPE_CHARS_PER_STEP + HOLD_STEPS + FADE_STEPS:
            self.headline = h = None
        if not h and headlines and self.t % NEXT_HEADLINE_STEPS == 1:
            tag, title = headlines[self.headline_index % len(headlines)]
            self.headline_index += 1
            title = title[: max(10, self.cols - len(tag) - 8)]
            width = len(tag) + len(title) + 6
            self.headline = Headline(tag, title, self.rng.randint(2, max(2, self.rows - 5)),
                                     self.rng.randint(1, max(1, self.cols - width - 1)), self.t)

    def render(self, palette, heat_pct: float = 0.0) -> Text:
        rows, cols = self.rows, self.cols
        grid: List[List[Optional[Tuple[str, str]]]] = [[None] * cols for _ in range(rows)]
        accent_every = 9
        for c, drop in enumerate(self.drops):
            base = palette.focus if c % accent_every == 0 and not palette.monochrome else palette.good
            for i in range(drop["length"]):
                r = int(drop["y"]) - i
                if 0 <= r < rows:
                    strength = (1 - i / drop["length"]) ** 1.6
                    color = palette.text if i == 0 else _blend(base, palette.bg, strength)
                    grid[r][c] = (self.glyph(c, r), color)
        h = self.headline
        if h:
            shown = min(len(h.title), (self.t - h.born) * TYPE_CHARS_PER_STEP)
            fade = 1.0 if shown < len(h.title) or self.t - h.born <= len(h.title) / TYPE_CHARS_PER_STEP + HOLD_STEPS else \
                max(0.0, 1 - (self.t - h.born - len(h.title) / TYPE_CHARS_PER_STEP - HOLD_STEPS) / FADE_STEPS)
            line = f" {h.tag}  {h.title[:shown]}{'▌' if shown < len(h.title) else ' '}"
            for i, ch in enumerate(line.ljust(len(h.tag) + len(h.title) + 5)):
                col = h.col + i
                if 0 <= col < cols:
                    color = palette.accent if 0 < i <= len(h.tag) else palette.text
                    grid[h.row][col] = (ch, _blend(color, palette.bg, fade) if fade < 1 else color)
        glow = _blend(palette.level(heat_pct), palette.bg, 0.22)
        glow_dim = _blend(palette.level(heat_pct), palette.bg, 0.1)
        out = Text(no_wrap=True)
        for r in range(rows):
            ground = glow if r == rows - 1 else glow_dim if r == rows - 2 else None
            for cell in grid[r]:
                char, color = cell if cell else (" ", palette.bg)
                out.append(char, style=f"{color} on {ground}" if ground else color)
            if r < rows - 1:
                out.append("\n")
        return out


class ScreensaverScreen(Screen):
    DEFAULT_CSS = """
    ScreensaverScreen { background: $background; }
    #rain { width: 100%; height: 100%; }
    """

    def __init__(self, headlines: Callable[[], List[Tuple[str, str]]], heat: Callable[[], float]):
        super().__init__()
        self.headlines, self.heat = headlines, heat
        self.rain: Optional[Rain] = None
        self.started = 0.0

    def compose(self) -> ComposeResult:
        yield Static(id="rain")

    def on_mount(self) -> None:
        import time
        self.started = time.monotonic()
        self.set_interval(FRAME_SECONDS, self.frame)

    def frame(self) -> None:
        size = self.size
        if size.width < 8 or size.height < 6:
            return
        if not self.rain or (self.rain.cols, self.rain.rows) != (size.width, size.height):
            self.rain = Rain(size.width, size.height)
        self.rain.step(self.headlines())
        self.query_one("#rain", Static).update(self.rain.render(self.app.palette, self.heat()))

    def wake(self) -> None:
        import time
        if time.monotonic() - self.started > IGNORE_INPUT_SECONDS:
            self.app.pop_screen()

    def on_key(self, event: events.Key) -> None:
        event.stop()
        self.wake()

    def on_click(self, event: events.Click) -> None:
        event.stop()
        self.wake()

    def on_mouse_move(self, event: events.MouseMove) -> None:
        self.wake()
