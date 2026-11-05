"""Widgets shared by the main views and the cards, so keyboard and mouse both work everywhere."""

from textual import events
from textual.coordinate import Coordinate
from textual.screen import ModalScreen
from textual.widgets import Button, DataTable, Input


class RowTable(DataTable, can_focus=False):
    """A row list. Keys are routed to it, so typing never lands here by accident. Clicking the selected row activates it."""

    def _on_click(self, event: events.Click) -> None:
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


class CardButton(Button, can_focus=False):
    """Mouse access to a card command. Keyboard users have the matching key."""

    DEFAULT_CSS = """
    CardButton { margin-right: 1; }
    CardButton.-style-default { background: $panel; color: $foreground; }
    CardButton.-style-default:hover { background: $primary; color: $background; }
    """

    def __init__(self, label: str, id: str, **kwargs):
        super().__init__(label, id=id, compact=True, **kwargs)


class Card(ModalScreen):
    """A pop-up card. Clicking outside it closes it, like Esc."""

    def on_click(self, event: events.Click) -> None:
        if event.widget is self and self.can_close_by_click():
            self.dismiss()

    def can_close_by_click(self) -> bool:
        return True
