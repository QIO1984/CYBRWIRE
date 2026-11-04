"""Watchlist manager for CybrWire: see every term and what it catches, add or remove them."""

from rich.text import Text
from textual import events
from textual.app import ComposeResult
from textual.containers import VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Static


class WatchCard(ModalScreen):
    AUTO_FOCUS = ""  # Keys come straight to this screen, which treats them as typing

    DEFAULT_CSS = """
    WatchCard { align: center middle; }
    #watch-card-scroll {
        width: 80; max-width: 100%; height: auto; max-height: 80%;
        padding: 1 2; border: round $primary; background: $background;
    }
    """

    def __init__(self):
        super().__init__()
        self.buffer = ""
        self.selected = 0

    def compose(self) -> ComposeResult:
        with VerticalScroll(id="watch-card-scroll"):
            yield Static(id="watch-card")

    def on_mount(self) -> None:
        self.query_one("#watch-card-scroll").border_subtitle = "Enter add or remove · ↑↓ select · Del remove · Esc close"
        self.redraw()

    def render_card(self) -> Text:
        app = self.app
        p = app.palette
        watchlist = app.watchlist
        text = Text()
        text.append(f"WATCHLIST  {len(watchlist.terms)} term{'s' if len(watchlist.terms) != 1 else ''}\n\n", style=f"bold {p.accent}")
        text.append("Term: ", style=f"bold {p.warn}")
        text.append(self.buffer + "█\n", style=f"bold {p.text}")
        text.append("Whole words in titles and descriptions; a trailing * matches a prefix\n\n", style=p.muted)
        if not watchlist.terms:
            text.append("No terms yet. Type a vendor, product or keyword and press Enter.\n", style=p.muted)
            return text
        counts = app.watch_hit_counts()
        for i, term in enumerate(watchlist.terms):
            selected = i == self.selected
            style = f"on {p.surface}" if selected else ""
            text.append("› " if selected else "  ", style=f"bold {p.accent} {style}".strip())
            text.append(f"★ {term:<34}", style=f"bold {p.text} {style}".strip())
            text.append(f"{counts.get(term, 0):>4} loaded", style=f"{p.text if counts.get(term) else p.muted} {style}".strip())
            text.append("  from YAML\n" if term in watchlist.configured else "\n", style=f"{p.muted} {style}".strip())
        return text

    def redraw(self) -> None:
        count = len(self.app.watchlist.terms)
        self.selected = max(0, min(self.selected, count - 1))
        self.query_one("#watch-card", Static).update(self.render_card())

    def toggle(self, term: str) -> None:
        """Add or remove a term; ones set in a YAML file can only change there"""
        result = self.app.watchlist.toggle(term)
        if result == "configured":
            self.app.notify(f"'{term}' is set in your YAML file; remove it there", timeout=4)
            return
        self.app.save_watchlist()
        self.app.notify(f"Watchlist: {result} '{term}'", timeout=2)

    def on_key(self, event: events.Key) -> None:
        event.stop()
        event.prevent_default()
        terms = self.app.watchlist.terms
        if event.key == "escape":
            self.dismiss()
            return
        if event.key == "enter":
            if self.buffer.strip():
                self.toggle(self.buffer)
            self.buffer = ""
        elif event.key == "backspace":
            self.buffer = self.buffer[:-1]
        elif event.key == "up":
            self.selected -= 1
        elif event.key == "down":
            self.selected += 1
        elif event.key == "delete":
            if terms:
                self.toggle(terms[self.selected])
        elif event.character and event.character.isprintable():
            self.buffer += event.character
        self.redraw()

    def on_paste(self, event: events.Paste) -> None:
        event.stop()
        self.buffer += event.text.strip()
        self.redraw()
