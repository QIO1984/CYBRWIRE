"""Full-window threat map, opened with 'm'."""

from rich.console import Group
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Static

from .widgets import Card, CardButton

PULSE_SECONDS = 0.5


class MapCard(Card):
    DEFAULT_CSS = """
    MapCard { align: center middle; }
    #map-card-body {
        width: 100%; height: 100%; padding: 0 1; border: round $primary; background: $background;
    }
    #map-title { height: 1; text-style: bold; color: $accent; }
    #map-view { height: 1fr; content-align: center middle; }
    #map-buttons { height: 1; }
    """

    BINDINGS = [("escape", "close", "Close"), ("q", "close", "Close"), ("m", "close", "Close")]

    def compose(self) -> ComposeResult:
        with Vertical(id="map-card-body"):
            yield Static("THREAT MAP · last 7 days", id="map-title")
            yield Static(id="map-view")
            with Horizontal(id="map-buttons"):
                yield CardButton("Close", id="map-close")

    def on_mount(self) -> None:
        self.query_one("#map-card-body").border_subtitle = "m or Esc close"
        self.set_interval(PULSE_SECONDS, self.pulse)
        self.redraw()

    def on_resize(self) -> None:
        self.redraw()

    def pulse(self) -> None:
        self.app.map_step += 1
        self.redraw()

    def redraw(self) -> None:
        view = self.query_one("#map-view", Static)
        width, height = max(30, view.size.width - 2), max(8, view.size.height)
        picture, lines = self.app.map_text(width, height)
        self.shown = Group(picture, "", *lines)  # Kept so a test can read what was drawn
        view.update(self.shown)

    def on_button_pressed(self, event) -> None:
        if event.button.id == "map-close":
            self.dismiss()

    def action_close(self) -> None:
        self.dismiss()
