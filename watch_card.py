"""Watchlist manager for CybrWire: see every term and what it catches, add or remove them."""

from rich.text import Text
from textual import events
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, Input, Static

from widgets import Card, CardButton, RowTable

HINTS = "Enter add or remove · ↑↓ select · Del remove · Esc close"


class WatchCard(Card):
    AUTO_FOCUS = "#watch-input"

    DEFAULT_CSS = """
    WatchCard { align: center middle; }
    #watch-card-body {
        width: 80; max-width: 100%; height: auto; max-height: 80%;
        padding: 1 2; border: round $primary; background: $background;
    }
    #watch-title { height: 1; margin-bottom: 1; text-style: bold; color: $accent; }
    #watch-input { margin-bottom: 1; }
    #watch-help { height: 1; margin-bottom: 1; color: $text-muted; }
    #watch-table { height: auto; max-height: 20; background: $background; scrollbar-size-vertical: 1; }
    #watch-table > .datatable--cursor, #watch-table > .datatable--hover {
        background: $panel; color: $foreground; text-style: none;
    }
    #watch-buttons { height: 1; margin-top: 1; }
    """

    def compose(self) -> ComposeResult:
        with Vertical(id="watch-card-body"):
            yield Static(id="watch-title")
            yield Input(id="watch-input", placeholder="Type a vendor, product or keyword, then press Enter", compact=True)
            yield Static("Whole words in titles and descriptions; a trailing * matches a prefix", id="watch-help")
            yield RowTable(id="watch-table", cursor_type="row", show_header=False)
            with Horizontal(id="watch-buttons"):
                yield CardButton("Remove selected", id="watch-remove")
                yield CardButton("Close", id="watch-close")

    def on_mount(self) -> None:
        self.query_one("#watch-card-body").border_subtitle = HINTS
        table = self.query_one("#watch-table", RowTable)
        table.add_column("", key="term", width=36)
        table.add_column("", key="count", width=11)
        table.add_column("", key="source", width=10)
        self.redraw()

    def redraw(self) -> None:
        p = self.app.palette
        watchlist = self.app.watchlist
        count = len(watchlist.terms)
        self.query_one("#watch-title", Static).update(f"WATCHLIST  {count} term{'s' if count != 1 else ''}")
        table = self.query_one("#watch-table", RowTable)
        row = table.cursor_row
        table.clear()
        counts = self.app.watch_hit_counts()
        for term in watchlist.terms:
            hits = counts.get(term, 0)
            table.add_row(Text(f"★ {term}", style=f"bold {p.text}", no_wrap=True, overflow="ellipsis"),
                          Text(f"{hits:>4} loaded", style=p.text if hits else p.muted),
                          Text("from YAML" if term in watchlist.configured else "", style=p.muted))
        table.show_cursor = bool(watchlist.terms)
        if not watchlist.terms:
            table.add_row(Text("No terms yet.", style=p.muted), Text(""), Text(""))
        table.move_cursor(row=max(0, min(row, count - 1)), animate=False)

    def toggle(self, term: str) -> None:
        """Add or remove a term; ones set in a YAML file can only change there"""
        result = self.app.watchlist.toggle(term)
        if result == "configured":
            self.app.notify(f"'{term}' is set in your YAML file; remove it there", timeout=4)
            return
        self.app.save_watchlist()
        self.app.notify(f"Watchlist: {result} '{term}'", timeout=2)
        self.redraw()

    def remove_selected(self) -> None:
        terms = self.app.watchlist.terms
        row = self.query_one("#watch-table", RowTable).cursor_row
        if 0 <= row < len(terms):
            self.toggle(terms[row])

    def on_input_submitted(self, event: Input.Submitted) -> None:
        event.stop()
        if event.value.strip():
            self.toggle(event.value)
        event.input.value = ""

    def on_button_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        if event.button.id == "watch-remove":
            self.remove_selected()
        else:
            self.dismiss()

    def on_key(self, event: events.Key) -> None:
        box = self.query_one("#watch-input", Input)
        table = self.query_one("#watch-table", RowTable)
        if event.key == "escape":
            self.dismiss()
        elif event.key == "up":
            table.action_cursor_up()
        elif event.key == "down":
            table.action_cursor_down()
        elif event.key == "delete" and not box.value:
            self.remove_selected()
        else:
            return  # Everything else belongs to the input
        event.stop()
        event.prevent_default()

    def on_data_table_row_selected(self, event) -> None:
        event.stop()  # Removing needs the button or Del, so a stray double click can't lose a term
