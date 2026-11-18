"""Theme picker, opened with Shift+T: every theme with a colour strip. Moving the highlight applies it live."""

from rich.text import Text
from textual import events
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Static

from .theme import PALETTES
from .widgets import Card, CardButton, RowTable

HINTS = "↑↓ preview live · Enter or Esc keep · c Cold War stays on its own key"
STRIP_ROLES = ("bg", "surface", "focus", "accent", "critical", "zeroday", "ransomware", "apt", "good")
NOTES = {"neon": "default", "retro_warm": "warm, Gruvbox-style", "amber_crt": "period simulation, one amber hue"}


class ThemeTable(RowTable):
    def was_clicked(self) -> None:
        self.screen.dismiss()  # Clicking the highlighted theme keeps it, like Enter


class ThemeCard(Card):
    AUTO_FOCUS = "#theme-table"

    DEFAULT_CSS = """
    ThemeCard { align: center middle; }
    #theme-card-body {
        width: 72; max-width: 100%; height: auto; max-height: 90%;
        padding: 1 2; border: round $primary; background: $background;
    }
    #theme-title { height: 1; margin-bottom: 1; text-style: bold; color: $accent; }
    #theme-table { height: auto; max-height: 20; background: $background; scrollbar-size-vertical: 1; }
    #theme-table > .datatable--cursor, #theme-table > .datatable--hover {
        background: $panel; color: $foreground; text-style: none;
    }
    #theme-buttons { height: 1; margin-top: 1; }
    """

    BINDINGS = [("escape", "close", "Close"), ("q", "close", "Close"), ("T", "close", "Close"), ("enter", "close", "Keep")]

    def compose(self) -> ComposeResult:
        with Vertical(id="theme-card-body"):
            yield Static("THEMES", id="theme-title")
            yield ThemeTable(id="theme-table", cursor_type="row", show_header=False)
            with Horizontal(id="theme-buttons"):
                yield CardButton("Close", id="theme-close")

    def on_mount(self) -> None:
        self.query_one("#theme-card-body").border_subtitle = HINTS
        table = self.query_one("#theme-table", ThemeTable)
        table.add_column("", key="name", width=16)
        table.add_column("", key="strip", width=2 * len(STRIP_ROLES))
        table.add_column("", key="note", width=30)
        self.keys = list(PALETTES)
        for key in self.keys:
            p = PALETTES[key]
            strip = Text()
            for role in STRIP_ROLES:
                strip.append("██", style=getattr(p, role))
            table.add_row(Text(p.name, style="bold"), strip, Text(NOTES.get(key, ""), style="dim"), key=key)
        self.current = self.app.theme_mode if self.app.theme_mode in self.keys and not self.app.cold_war_mode else None
        if self.current:
            table.move_cursor(row=self.keys.index(self.current), animate=False)
        self.ready = True

    def on_data_table_row_highlighted(self, event) -> None:
        event.stop()
        if not getattr(self, "ready", False) or event.row_key is None:
            return
        key = event.row_key.value
        if key != self.current:
            self.current = key
            self.app.set_theme_by_key(key)

    def on_key(self, event: events.Key) -> None:
        table = self.query_one("#theme-table", ThemeTable)  # The table never takes focus, so keys are routed to it here
        actions = {"up": table.action_cursor_up, "down": table.action_cursor_down,
                   "pageup": table.action_page_up, "pagedown": table.action_page_down}
        if event.key in actions:
            actions[event.key]()
            event.stop()
            event.prevent_default()

    def on_button_pressed(self, event) -> None:
        if event.button.id == "theme-close":
            self.dismiss()

    def action_close(self) -> None:
        self.dismiss()
