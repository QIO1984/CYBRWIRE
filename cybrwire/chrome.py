"""The strips around the main window: header, world clock and footer."""

import asyncio
from datetime import datetime, timezone

from rich.text import Text
from textual.widgets import Header, Static

from . import clocks

# What '4' cycles through. "All" leaves indicators out; they have their own view.
CONTENT_KINDS = [("all", "All"), ("advisory", "Advisories"), ("news", "News & Research"),
                 ("ransomware", "Ransomware"), ("indicators", "Indicators"), ("outage", "Outages")]


class StyledHeader(Header):
    """Custom header that supports cold war mode styling"""
    def render(self) -> str:
        app = self.app
        header_str = super().render()
        # If app has cold_war_mode, we'll style it via the watcher instead
        return header_str


class WorldClock(Static):
    """Your time and a few reference cities, one line under the header (z shows or hides it)"""

    DEFAULT_CSS = """
    WorldClock {
        height: 1;
        padding: 0 1;
        text-align: center;
    }
    """

    shown = None

    def __init__(self, home_zone=None, cities=None, **kwargs):
        super().__init__(**kwargs)
        self.home_zone = home_zone  # timezone: from the config file, if any
        self.cities = cities        # clocks: from the config file, if any

    def on_mount(self) -> None:
        self.local = clocks.local_zone(self.home_zone)
        self.zones = clocks.parse_clocks(clocks.from_env() or self.cities)
        self.set_interval(1.0, self.tick)
        self.tick()

    def on_resize(self, event) -> None:
        self.tick()  # The line is squeezed to the width, which isn't known until the window is laid out

    def tick(self) -> None:
        """Redraw only when the minute or the colours change"""
        app = self.app
        text = clocks.render(datetime.now(timezone.utc), self.local, self.zones, app.palette, max(0, self.size.width - 2))
        key = (text.plain, app.palette.accent, app.palette.text)
        if key != self.shown:
            self.shown = key
            self.update(text)


class CybrWireFooter(Static):
    """Custom footer that shows dynamic state indicators for data age and filter type"""
    
    regions = []
    
    def render(self) -> Text:
        """Build and render footer text with dynamic state indicators"""
        app = self.app
        
        # Get current state strings
        time_windows = ["24h", "48h", "7d"]
        filter_types = ["All", "Alerts", "Posts"]
        
        data_age_label = time_windows[app.data_age_index]
        filter_label = filter_types[app.filter_type_index]
        
        # Count of what the feed panel is showing
        count = len(app.filtered_alerts()) if not app.is_loading else 0
        
        kind_label = CONTENT_KINDS[app.kind_index][1].replace("News & Research", "News")
        
        def commands_for(compact):
            return [
                ("r", "Refresh", "refresh"),
                ("d", data_age_label if compact else f"Age {data_age_label}", "cycle_data_age"),
                ("f", f"{filter_label} ({count})", "cycle_filter_type"),
                ("4", kind_label if compact else f"Type {kind_label}", "cycle_feeds"),
                ("/", "Search", "start_search"),
                ("w", f"Watch {'On' if app.watch_only else 'Off'}", "toggle_watch_only"),
                ("W", "Terms", "edit_watchlist"),
                ("tab", "Panel", "toggle_panel_focus"),
                ("v", "View", "toggle_view"),
                ("K", "Keys", "manage_keys"),
                ("c", "CW", "toggle_cold_war"),
                ("t", "Theme", "cycle_theme"),
                ("h", "Help", "show_help"),
                ("q", "Quit", "quit"),
            ]
        
        def length(commands, gap):
            return sum(len(k) + 1 + len(label) for k, label, _ in commands) + gap * (len(commands) - 1)
        
        # Roomiest layout that fits: wider gaps first, then shorter labels
        width = self.size.width
        commands = commands_for(False)
        gap = " " * (2 if length(commands, 2) <= width else 1)
        if length(commands, len(gap)) > width:
            commands = commands_for(True)
        key_color = f"bold {app.palette.accent}"
        desc_color = app.palette.muted
        footer_text = Text(no_wrap=True, overflow="ellipsis")
        self.regions = []  # (first column, last column, action), so each command is clickable
        for i, (key, label, action) in enumerate(commands):
            start = footer_text.cell_len
            footer_text.append(f"{key} ", style=key_color)
            footer_text.append(label, style=desc_color)
            self.regions.append((start, footer_text.cell_len - 1, action))
            if i < len(commands) - 1:
                footer_text.append(gap)
        return footer_text
    
    def on_click(self, event) -> None:
        action = next((a for first, last, a in self.regions if first <= event.x <= last), None)
        if not action or event.button != 1:
            return
        event.stop()
        self.app.finish_typing()
        result = getattr(self.app, f"action_{action}")()
        if asyncio.iscoroutine(result):
            asyncio.ensure_future(result)
