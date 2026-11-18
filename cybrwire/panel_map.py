"""The threat map panel: the world map and its legend, in the right-hand dashboard panel."""

from datetime import datetime, timezone

from rich import box
from rich.console import Group
from rich.panel import Panel

from . import worldmap

MAP_DAYS = 7


class MapMixin:
    map_step = 0  # Counts pulse steps; every spot is out of step with the others

    def map_spots(self):
        return worldmap.gather_spots(self.all_alerts, datetime.now(timezone.utc), MAP_DAYS)

    def map_text(self, width: int, height: int, with_legend: bool = True):
        """(map, legend lines) sized to fit width x height cells"""
        spots = self.map_spots()
        lines = worldmap.legend(spots, self.palette, width=width) if with_legend else []
        cols, rows = worldmap.fit(width, max(worldmap.MIN_ROWS, height - len(lines) - 1))
        return worldmap.render(cols, rows, spots, self.map_step, self.palette), lines

    def make_threat_map_panel(self):
        size = self.query_one("#dashboard").size
        width, height = max(30, size.width - 6), max(12, size.height - 4)
        picture, lines = self.map_text(width, height)
        title, border = self.frame("THREAT MAP · last 7 days", self.panel_focus == "dashboard")
        return Panel(Group(picture, "", *lines), title=title, subtitle=self.hint_bar([("m", "full screen"), ("v", "next view")]),
                     border_style=border, box=box.ROUNDED, padding=(1, 2))

    def map_tick(self):
        """Pulse the markers: only the map redraws, and only while it is on screen"""
        self.map_step += 1
        if self.is_loading or self.dashboard_panel_index != 3:
            return
        try:
            self.query_one("#dashboard").update(self.make_threat_map_panel())
        except Exception:  # The panel may be mid-redraw or gone; the next tick tries again
            pass
