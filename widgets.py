"""Widgets shared by the main views and the cards, so keyboard and mouse both work everywhere."""

import time
from typing import Callable, Optional, Tuple

from rich.text import Text
from textual import events
from textual.coordinate import Coordinate
from textual.screen import ModalScreen
from textual.widgets import Button, DataTable, Input, Static


class RowTable(DataTable, can_focus=False):
    """A row list. Keys are routed to it, so typing never lands here by accident. Clicking the selected row activates it."""

    def __init__(self, **kwargs):
        # The selected row only changes background; its cells keep their own colors, so badges stay readable
        super().__init__(cursor_foreground_priority="renderable", **kwargs)

    def _on_click(self, event: events.Click) -> None:
        if event.button != 1:  # Other buttons pass up to the panel, and never select or open a row
            event.prevent_default()
            return
        # Textual then runs DataTable's own handler, which activates on a click at the cursor's
        # exact cell. Any column of the selected row should count, so line the column up first.
        meta = event.style.meta
        if "column" in meta and meta["column"] >= 0:
            self.cursor_coordinate = Coordinate(self.cursor_row, meta["column"])
        self.was_clicked()

    def was_clicked(self) -> None:
        pass


class ViewTable(RowTable):
    """A table in one of the main views"""

    def on_resize(self) -> None:
        self.app.call_later(self.app.update_display)  # Column widths follow the panel

    def was_clicked(self) -> None:
        self.app.panel_focus = "main"
        if self.app.prompt:
            self.app.finish_typing()  # Clicking the list leaves the text box


class TypingBox(Input):
    """Single-key commands are off for as long as one of these has focus"""

    prompt_name = "typing"

    def on_focus(self) -> None:
        self.app.prompt = self.prompt_name

    def on_blur(self) -> None:
        self.app.prompt = None


class SearchBox(TypingBox):
    prompt_name = "search"


class IndicatorBox(TypingBox):
    prompt_name = "indicator"

    def on_key(self, event: events.Key) -> None:
        # With nothing typed, v still changes view, so this box can't trap the keyboard
        if event.key == "v" and not self.value:
            event.stop()
            event.prevent_default()
            self.app.action_toggle_view()


class PagerBar(Static):
    """Clickable paging for a paged panel, plus any extra command it offers"""

    regions = []
    WIDE = 36  # Columns needed for the full labels

    def show(self, page: int, total: int, extra: Optional[Tuple[str, Callable]] = None) -> None:
        self.display = total > 1 or extra is not None
        if not self.display:
            return
        p = self.app.palette
        text = Text(no_wrap=True)
        self.regions = []

        def add(label, action, enabled=True):
            start = text.cell_len
            text.append(label, style=f"bold {p.accent}" if enabled else p.muted)
            if enabled:
                self.regions.append((start, text.cell_len - 1, action))

        if total > 1:
            # Narrow panels get shorter labels, so everything stays on the one line
            room = self.size.width >= self.WIDE
            add("◀ Prev" if room else " ◀ ", lambda: self.app.page_dashboard(-1), page > 0)
            text.append(f"  {page + 1}/{total}  ", style=p.muted)
            add("Next ▶" if room else " ▶ ", lambda: self.app.page_dashboard(1), page < total - 1)
            text.append("   ")
        if extra:
            add(*extra)
        self.update(text)

    def on_click(self, event: events.Click) -> None:
        if event.button != 1:
            return
        event.stop()
        action = next((a for first, last, a in self.regions if first <= event.x <= last), None)
        if action:
            action()


class DashboardPanel(Static):
    """The right panel. Its pages turn with the mouse wheel, like scrolling in the feed."""

    WHEEL_GAP = 0.2  # Seconds; one wheel notch can send several events
    last_turn = 0.0

    def turn(self, delta: int) -> None:
        if time.monotonic() - self.last_turn >= self.WHEEL_GAP:
            self.last_turn = time.monotonic()
            self.app.page_dashboard(delta)

    def on_mouse_scroll_down(self, event: events.MouseScrollDown) -> None:
        self.turn(1)

    def on_mouse_scroll_up(self, event: events.MouseScrollUp) -> None:
        self.turn(-1)


class CardButton(Button, can_focus=False):
    """Mouse access to a card command. Keyboard users have the matching key."""

    DEFAULT_CSS = """
    CardButton { margin-right: 1; }
    CardButton.-style-default { background: $panel; color: $foreground; }
    CardButton.-style-default:hover { background: $primary; color: $background; }
    """

    def __init__(self, label: str, id: str, **kwargs):
        super().__init__(label, id=id, compact=True, **kwargs)

    async def _on_click(self, event: events.Click) -> None:
        if event.button != 1:  # A right click is not a press
            event.prevent_default()


class Card(ModalScreen):
    """A pop-up card. Clicking outside it closes it, like Esc."""

    def on_click(self, event: events.Click) -> None:
        if event.button == 1 and event.widget is self and self.can_close_by_click():
            self.dismiss()

    def can_close_by_click(self) -> bool:
        return True
