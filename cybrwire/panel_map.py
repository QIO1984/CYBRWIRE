"""The threat map view: the world map, a legend per layer, the latest alerts and the activity scope.

Shown as a main view (v cycles to it) and in the full-window card (m). Both use map_view_content."""

from datetime import datetime, timezone

from rich.align import Align
from rich.console import Group
from rich.padding import Padding
from rich.text import Text

from . import scope, worldmap
from .incidents import age

MAP_DAYS = 7
LATEST = 4          # Alerts listed under the map
SCOPE_ROWS = 2
MAP_CACHE_SECONDS = 20


class MapMixin:
    map_step = 0  # Counts pulse steps; every marker is out of step with the others
    _map_cache = None

    def map_spots(self):
        """The markers, worked out again only when the alerts change or every 20 seconds"""
        now = datetime.now(timezone.utc)
        alerts = self.all_alerts
        key = (id(alerts), len(alerts), alerts[0]["title"] if alerts else "", int(now.timestamp() // MAP_CACHE_SECONDS))
        if not self._map_cache or self._map_cache[0] != key:
            self._map_cache = (key, worldmap.gather_spots(alerts, now, MAP_DAYS))
        return self._map_cache[1]

    def latest_lines(self, width, count=LATEST):
        """The strongest recent alerts: what is worth knowing alongside the map"""
        p = self.palette
        picks = [a for a in self.all_alerts if self.is_alert(a) and a.get("kind") != "outage"]
        picks.sort(key=lambda a: ((a.get("evidence").score if a.get("evidence") else 0), a["ts"]), reverse=True)
        lines = [Text("LATEST", style=f"bold {p.accent}")]
        for a in picks[:count]:
            line = Text()
            line.append(f" {p.severity_name(a['severity']):<10.10}", style=p.badge(a["severity"]) if a["severity"] != "info" else p.muted)
            tail = f"  {a['source']} · {age(a['ts'])}"
            line.append(" " + a["title"][:max(10, width - 14 - len(tail))], style=p.text)
            line.append(tail, style=p.muted)
            line.truncate(width, overflow="ellipsis")
            lines.append(line)
        if not picks:
            lines.append(Text("  Nothing urgent in the data window", style=p.muted))
        return lines

    def map_view_content(self, width: int, height: int):
        """The map and everything under it, sized to width x height cells and centred in it"""
        spots = self.map_spots()
        text_width = min(width, 110)  # Lines of text stay readable on a very wide screen
        legend = worldmap.legend(spots, self.palette, width=text_width)
        latest = self.latest_lines(text_width) if height >= 24 else []
        counts = scope.hourly_counts(self.all_alerts, datetime.now(timezone.utc))
        trace = scope.render(counts, min(text_width, 100), SCOPE_ROWS, self.map_step, self.palette) if height >= 30 else []
        below = len(legend) + (len(latest) + 1 if latest else 0) + (len(trace) + 1 if trace else 0) + 1
        cols, rows = worldmap.fit(width, max(worldmap.MIN_ROWS, height - below))
        picture = worldmap.render(cols, rows, spots, self.map_step if self.effects_on else 0, self.palette)
        block = max(cols, text_width)  # The map and the text under it share one centred column
        parts = [Align.center(picture, width=block), ""]
        parts += legend
        if latest:
            parts += ["", *latest]
        if trace:
            parts += ["", *trace]
        return Padding(Group(*parts), (0, 0, 0, max(0, (width - block) // 2)))

    def sync_map_view(self):
        """Fill the main-panel map view and its frame"""
        view = self.query_one("#map-panel")
        content = self.query_one("#map-main")
        width = max(30, (content.size.width or view.size.width - 6) - 1)
        height = max(10, content.size.height or view.size.height - 4)
        content.update(self.map_view_content(width, height))
        status = Text(" last 7 days   ", style=self.palette.muted)
        status.append_text(self.hint_bar([("m", "full screen"), ("v", "next view")]))
        status.append(" ")
        title, border = self.frame("THREAT MAP", self.panel_focus == "main")
        view.border_title = title
        view.border_subtitle = status
        view.styles.border = ("round", border)

    def map_tick(self):
        """Pulse the markers and move the scope. Only the map redraws, and only while it is showing."""
        if not self.effects_on:
            return
        self.map_step += 1
        if self.is_loading or self.main_view_mode != "map" or len(self.screen_stack) > 1:
            return
        try:
            self.sync_map_view()
        except Exception:  # The view may be mid-redraw or gone; the next tick tries again
            pass
