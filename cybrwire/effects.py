"""Atmosphere that reacts to what is happening: the flash when something urgent arrives.
It obeys the Effects switch (x)."""

from .worldmap import _blend

EDGE_FADE = (1.0, 0.75, 0.45, 0.2)   # How much of the edge colour is left at each step
EDGE_STEP_SECONDS = 0.3
BANNER_BLINKS = 8


class EffectsMixin:
    def arrival_effect(self, arrivals) -> None:
        """When something urgent arrives, the window edge pulses once; in Cold War mode FLASH flickers too"""
        if not self.effects_on or self.is_loading or len(self.screen_stack) > 1:
            return
        urgent = [a for a in arrivals if a.get("evidence") and a["evidence"].urgent]
        if not urgent:
            return
        self.flash_edge()
        if self.cold_war_mode:
            self.flash_banner(urgent[0])

    def flash_edge(self) -> None:
        p = self.palette
        self.set_outline(_blend(p.focus, p.bg, EDGE_FADE[0]))
        for i, keep in enumerate(EDGE_FADE[1:], start=1):
            self.set_timer(i * EDGE_STEP_SECONDS, lambda keep=keep: self.set_outline(_blend(p.focus, p.bg, keep)))
        self.set_timer(len(EDGE_FADE) * EDGE_STEP_SECONDS, lambda: self.set_outline(None))

    def set_outline(self, color) -> None:
        screen = self.screen
        if color:
            screen.styles.outline = ("heavy", color)
        else:
            screen.styles.outline = None

    def flash_banner(self, alert) -> None:
        from rich.text import Text
        p = self.palette
        banner = self.query_one("#flash-banner")
        label = p.severity_name(alert["severity"])
        banner.update(Text(f"F L A S H  ·  {label}  ·  {alert['title'][:90]}", style=f"bold {p.bg} on {p.focus}", justify="center"))
        banner.display = True
        state = {"n": 0}

        def blink():
            state["n"] += 1
            if state["n"] >= BANNER_BLINKS:
                banner.display = False
                timer.stop()
            else:
                banner.styles.visibility = "hidden" if state["n"] % 2 else "visible"

        banner.styles.visibility = "visible"
        timer = self.set_interval(0.25, blink)
