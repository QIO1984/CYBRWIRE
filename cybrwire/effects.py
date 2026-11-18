"""Atmosphere that reacts to what is happening: the idle screensaver, and the flash when something
urgent arrives. Everything here obeys the Effects switch (x)."""

import time
from datetime import datetime, timedelta, timezone

from textual import events

from .screensaver import ScreensaverScreen
from .worldmap import _blend

EDGE_FADE = (1.0, 0.75, 0.45, 0.2)   # How much of the edge colour is left at each step
EDGE_STEP_SECONDS = 0.3
BANNER_BLINKS = 8
SEVERITY_WEIGHT = {"critical": 4, "zeroday": 5, "ransomware": 3, "apt": 3, "exploit": 2}


class EffectsMixin:
    IDLE_SECONDS = 300  # Five minutes with no key, click or mouse movement

    async def on_event(self, event) -> None:
        if isinstance(event, (events.Key, events.MouseDown, events.MouseMove, events.MouseScrollDown, events.MouseScrollUp)):
            self.last_input = time.monotonic()
        await super().on_event(event)

    def idle_check(self) -> None:
        """Start the screensaver once nobody has touched the app for a while"""
        if (not self.effects_on or self.is_loading or len(self.screen_stack) > 1
                or time.monotonic() - self.last_input < self.IDLE_SECONDS):
            return
        self.push_screen(ScreensaverScreen(self.screensaver_headlines, self.threat_heat))

    def screensaver_headlines(self):
        """(tag, title) for the strongest recent alerts, for the screensaver to type out"""
        p = self.palette
        picks = [a for a in self.all_alerts if self.is_alert(a) and a.get("kind") != "outage"]
        picks.sort(key=lambda a: ((a.get("evidence").score if a.get("evidence") else 0), a["ts"]), reverse=True)
        return [(p.severity_name(a["severity"]), a["title"]) for a in picks[:12]]

    def threat_heat(self) -> float:
        """0-100: how much weighted trouble there is in the last day, for the screensaver's glow"""
        cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
        recent = [a for a in self.all_alerts if a["ts"] >= cutoff]
        if not recent:
            return 0.0
        weighted = sum(SEVERITY_WEIGHT.get(a["severity"], 0) for a in recent)
        return min(100.0, weighted / (len(recent) * 17) * 100 * 3)  # Scaled up: most feeds are mostly routine

    # ---- arrivals
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
