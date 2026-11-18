"""Atmosphere that reacts to what is happening: the flash when something urgent arrives, and a mood
light that tints the borders as the threat level rises. Both obey the Effects switch (x), and the
period simulations (Cold War mode, the Amber CRT theme) never get the mood light."""

from datetime import datetime, timedelta, timezone

from .worldmap import _blend

EDGE_FADE = (1.0, 0.75, 0.45, 0.2)   # How much of the edge colour is left at each step
EDGE_STEP_SECONDS = 0.3
BANNER_BLINKS = 8
CALM_BELOW = 30          # Heat Level (percent of stories that are threats) under which nothing is tinted
RED_FROM = 60            # ...and from which the tint is fully red
MOOD_STEPS = 12          # The tint moves in this many steps, so it redraws rarely
MOOD_EASE = 0.25         # How far the shown level moves toward the real one each tick: changes glide, they don't jump
THREATS = ("critical", "zeroday", "ransomware", "apt", "exploit")


class EffectsMixin:
    mood_heat = 0.0   # What the tint currently shows, 0-100
    mood_q = 0        # That, in steps

    def threat_heat(self) -> float:
        """The same Heat Level the dashboard shows: the share of stories in the data window that are threats"""
        cutoff = datetime.now(timezone.utc) - timedelta(hours=self.recency_hours)
        stories = [a for a in self.all_alerts if a["ts"] >= cutoff and a.get("kind") != "indicators"]
        return sum(a["severity"] in THREATS for a in stories) / len(stories) * 100 if stories else 0.0

    def mood_active(self) -> bool:
        p = self.palette
        return self.effects_on and not p.pure and not p.monochrome

    def mood(self, color: str, reach: float = 0.45) -> str:
        """`color`, tinted toward amber and then red as the threat level rises (unchanged when calm or when
        this look is a period simulation)"""
        if not self.mood_active() or self.mood_heat <= CALM_BELOW:
            return color
        p = self.palette
        t = min(1.0, (self.mood_heat - CALM_BELOW) / (100 - CALM_BELOW))
        toward = _blend(p.bad, p.warn, max(0.0, min(1.0, (self.mood_heat - CALM_BELOW) / (RED_FROM - CALM_BELOW))))  # Amber, then red
        return _blend(toward, color, reach * t)  # _blend(a, b, keep) keeps `keep` of a

    def mood_tick(self) -> None:
        """Ease the shown level toward the real one and redraw only when it moves a whole step"""
        target = self.threat_heat() if self.mood_active() else 0.0
        self.mood_heat += (target - self.mood_heat) * MOOD_EASE
        if abs(self.mood_heat - target) < 0.5:
            self.mood_heat = target
        q = round(self.mood_heat / 100 * MOOD_STEPS)
        if q != self.mood_q:
            self.mood_q = q
            self.mark_dirty()

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
