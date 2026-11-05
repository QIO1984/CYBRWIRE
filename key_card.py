"""API key manager for CybrWire: enter, test, remove and secure keys without editing files."""

import asyncio
from typing import Dict, Optional

from rich.text import Text
from textual import events
from textual.app import ComposeResult
from textual.containers import VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Input, Static

import key_check
from key_check import CheckResult
from keystore import ENV, FILE, KEYCHAIN, SECRETS_FILE, SLOTS, SLOTS_BY_ID, SOURCE_LABELS, YAML, KeyStoreError, clean_value, mask

HINTS = "Enter set · t test · Del remove · ↑↓ select · Esc close"
EDIT_HINTS = "Enter test and save · Esc cancel"


class KeyCard(ModalScreen):
    AUTO_FOCUS = ""  # The key input only takes focus while a key is being entered

    DEFAULT_CSS = """
    KeyCard { align: center middle; }
    #key-card-scroll {
        width: 92; max-width: 100%; height: auto; max-height: 90%;
        padding: 1 2; border: round $primary; background: $background;
    }
    #key-input { display: none; margin: 1 0 0 0; }
    #key-input.editing { display: block; }
    """

    def __init__(self):
        super().__init__()
        self.selected = 0
        self.editing = False
        self.confirm: Optional[str] = None  # "delete" or "move" while waiting for a second press
        self.force_value: Optional[str] = None  # Rejected key the user can still save by pressing Enter again
        self.busy = False
        self.message: Optional[Text] = None
        self.results: Dict[str, CheckResult] = {}
        self.pending_task: Optional[asyncio.Task] = None

    @property
    def config(self):
        return self.app.key_config

    @property
    def slot(self):
        return SLOTS[self.selected]

    def compose(self) -> ComposeResult:
        with VerticalScroll(id="key-card-scroll"):
            yield Static(id="key-card")
            yield Input(password=True, id="key-input", placeholder="Paste the key; it stays hidden")
            yield Static(id="key-card-status")

    def on_mount(self) -> None:
        self.query_one("#key-card-scroll").border_subtitle = HINTS
        self.redraw()

    def say(self, message: str, style: str = "") -> None:
        self.message = Text(message, style=style or self.app.palette.text)

    def storage_notice(self) -> Text:
        p = self.app.palette
        store = self.config.keys
        text = Text()
        if store.keychain_available:
            text.append(f"New keys go to the system keychain ({store.keychain_name})\n", style=p.muted)
        else:
            text.append(f"⚠ No keychain: {store.problem}.\n", style=f"bold {p.warn}")
            text.append(f"  New keys go to {SECRETS_FILE}: your user only, but NOT encrypted.\n", style=p.warn)
            text.append("  On servers, environment variables are better. See the README.\n", style=p.muted)
        movable = store.movable()
        if movable:
            place = "the keychain" if store.keychain_available else "the restricted file"
            text.append(f"⚠ {len(movable)} outside {place}. Press m to move them and clear the old copies.\n", style=f"bold {p.warn}")
        return text

    def render_card(self) -> Text:
        p = self.app.palette
        text = Text()
        text.append("API KEYS\n\n", style=f"bold {p.accent}")
        text.append_text(self.storage_notice())
        group = None
        for i, slot in enumerate(SLOTS):
            if slot.group != group:
                group = slot.group
                text.append(f"\n{group}\n", style=f"bold {p.muted}")
            selected = i == self.selected
            bg = f" on {p.surface}" if selected else ""
            value = self.config.key_value(slot.id)
            source = self.config.key_sources.get(slot.id)
            text.append("› " if selected else "  ", style=f"bold {p.accent}{bg}")
            label = slot.label
            if slot.id == "ai_api_key" and self.config.ai.get("provider"):
                label = f"AI: {self.config.ai['provider']}"[:17]
            text.append(f"{label:<18}", style=f"bold {p.text}{bg}")
            text.append(f"{mask(value) if value else 'not set':<16}", style=f"{p.text if value else p.muted}{bg}")
            where = SOURCE_LABELS.get(source, "") if value else ""
            weak = source == YAML or source == FILE
            text.append(f"{where:<22}", style=f"{p.warn if weak else p.muted}{bg}")
            result = self.results.get(slot.id)
            if result:
                mark = {key_check.OK: ("✓ works", p.good), key_check.REJECTED: ("✗ rejected", p.bad)}.get(
                    result.status, ("? unconfirmed", p.warn))
                text.append(mark[0], style=f"{mark[1]}{bg}")
            text.append("\n")
        text.append(f"\n{self.slot.hint}", style=p.muted)
        return text

    def redraw(self) -> None:
        self.query_one("#key-card", Static).update(self.render_card())
        self.query_one("#key-card-status", Static).update(self.message or "")

    # Entering a key

    def start_edit(self) -> None:
        slot = self.slot
        if self.config.key_sources.get(slot.id) == ENV:
            self.say(f"{slot.label} is set by {slot.env}. Change it there.", self.app.palette.warn)
            return
        box = self.query_one("#key-input", Input)
        box.value = ""
        box.add_class("editing")
        box.focus()
        self.editing = True
        self.force_value = None
        self.message = None
        self.query_one("#key-card-scroll").border_subtitle = EDIT_HINTS

    def stop_edit(self) -> None:
        box = self.query_one("#key-input", Input)
        box.value = ""  # Don't leave the key in a hidden widget
        box.remove_class("editing")
        self.set_focus(None)
        self.editing = False
        self.force_value = None
        self.query_one("#key-card-scroll").border_subtitle = HINTS

    def on_input_submitted(self, event: Input.Submitted) -> None:
        event.stop()
        if self.busy:
            return
        p = self.app.palette
        try:
            value = clean_value(self.slot, event.value)
        except KeyStoreError as e:
            self.say(str(e), p.warn)
            self.redraw()
            return
        if value == self.force_value:
            self.run_task(self.save_key(self.slot.id, value))
        else:
            self.run_task(self.test_then_save(self.slot.id, value))

    def run_task(self, coroutine) -> None:
        self.busy = True
        self.pending_task = asyncio.create_task(self.guarded(coroutine))

    async def guarded(self, coroutine) -> None:
        try:
            await coroutine
        except asyncio.CancelledError:
            raise
        except Exception as e:  # Name only: the text could carry a key
            self.say(f"That failed ({type(e).__name__})", self.app.palette.bad)
        finally:
            self.busy = False
            if self.is_attached:
                self.redraw()

    async def test_then_save(self, slot_id: str, value: str) -> None:
        p = self.app.palette
        self.say("Testing...", p.muted)
        self.redraw()
        result = await key_check.check_key(slot_id, value, self.config.ai, self.config.notifications)
        self.results[slot_id] = result
        if result.status == key_check.REJECTED:
            self.force_value = value
            self.say(f"{result.message}. Not saved. Enter saves it anyway, Esc cancels.", p.bad)
            return
        await self.save_key(slot_id, value, result)

    async def save_key(self, slot_id: str, value: str, result: Optional[CheckResult] = None) -> None:
        p = self.app.palette
        try:
            where = await asyncio.to_thread(self.config.keys.save, slot_id, value)
        except KeyStoreError as e:
            # Stored, but a YAML copy remains and would need removing by hand
            self.apply(slot_id, value, self.config.keys.resolve_all({}).get(slot_id, (value, KEYCHAIN))[1])
            self.say(f"Saved, but: {e}", p.warn)
            self.stop_edit()
            return
        self.apply(slot_id, value, where)
        self.stop_edit()
        prefix = f"{result.message}. " if result else ""
        if where == FILE:
            self.say(f"{prefix}⚠ No keychain, so it went to {SECRETS_FILE} (your user only, not encrypted).", p.warn)
            self.app.notify(f"No keychain: {SLOTS_BY_ID[slot_id].label} is in a restricted file, not encrypted",
                            severity="warning", timeout=6)
        else:
            self.say(f"{prefix}Saved to the keychain.", p.good if not result or result.status == key_check.OK else p.warn)

    def apply(self, slot_id: str, value: Optional[str], source: Optional[str]) -> None:
        self.config.set_key_value(slot_id, value, source)
        self.app.key_changed(slot_id)

    # Testing, removing and moving stored keys

    async def test_stored(self, slot_id: str) -> None:
        p = self.app.palette
        self.say("Testing...", p.muted)
        self.redraw()
        result = await key_check.check_key(slot_id, self.config.key_value(slot_id), self.config.ai, self.config.notifications)
        self.results[slot_id] = result
        style = {key_check.OK: p.good, key_check.REJECTED: p.bad}.get(result.status, p.warn)
        self.say(f"{SLOTS_BY_ID[slot_id].label}: {result.message}", style)

    async def delete_key(self, slot_id: str) -> None:
        p = self.app.palette
        store = self.config.keys
        try:
            await asyncio.to_thread(store.delete, slot_id)
        except KeyStoreError as e:
            self.say(str(e), p.warn)
            return
        self.results.pop(slot_id, None)
        self.apply(slot_id, None, None)
        self.say(f"Removed {SLOTS_BY_ID[slot_id].label}.", p.good)

    async def move_keys(self) -> None:
        p = self.app.palette
        store = self.config.keys
        moved, problems = await asyncio.to_thread(store.move_all)
        resolved = store.resolve_all(store.read_yaml_values())
        for slot_id in moved:
            value, source = resolved[slot_id]
            self.apply(slot_id, value, source)
        place = "the keychain" if store.keychain_available else "the restricted file"
        summary = f"Moved {len(moved)} to {place} and cleared the old copies."
        if problems:
            self.say(f"{summary} {'; '.join(problems)}", p.warn)
        else:
            self.say(summary, p.good)

    def on_key(self, event: events.Key) -> None:
        if self.editing:
            if event.key == "escape":
                event.stop()
                self.cancel_task()
                self.stop_edit()
                self.message = None
                self.redraw()
            return  # Everything else belongs to the input
        event.stop()
        event.prevent_default()
        key = event.key
        confirm, self.confirm = self.confirm, None
        if key == "escape":
            self.dismiss()
            return
        if self.busy:
            return
        p = self.app.palette
        slot = self.slot
        has_value = bool(self.config.key_value(slot.id))
        if key == "up":
            self.selected = (self.selected - 1) % len(SLOTS)
            self.message = None
        elif key == "down":
            self.selected = (self.selected + 1) % len(SLOTS)
            self.message = None
        elif key == "enter":
            self.start_edit()
        elif key == "t":
            if has_value:
                self.run_task(self.test_stored(slot.id))
            else:
                self.say("Nothing to test yet. Press Enter to add this key.", p.muted)
        elif key == "delete":
            if not has_value:
                self.say("Nothing to remove.", p.muted)
            elif self.config.key_sources.get(slot.id) == ENV:
                self.say(f"{slot.label} is set by {slot.env}. Remove it there.", p.warn)
            elif confirm == "delete":
                self.run_task(self.delete_key(slot.id))
            else:
                self.confirm = "delete"
                self.say(f"Press Del again to remove {slot.label}.", p.warn)
        elif key == "m":
            if not self.config.keys.movable():
                self.say("Nothing to move.", p.muted)
            elif confirm == "move":
                self.run_task(self.move_keys())
            else:
                self.confirm = "move"
                self.say("Press m again to move these keys and clear the old copies.", p.warn)
        self.redraw()

    def cancel_task(self) -> None:
        if self.pending_task and not self.pending_task.done():
            self.pending_task.cancel()
        self.busy = False

    def on_unmount(self) -> None:
        self.cancel_task()
