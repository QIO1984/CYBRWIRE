"""API key manager for CybrWire: choose the AI provider, enter, test, remove and secure keys without editing files."""

import asyncio
from typing import Dict, Optional

from rich.text import Text
from textual import events
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.widgets import Button, Input, Select, Static

from . import ai
from . import key_check
from .key_check import CheckResult
from .keystore import (ENV, FILE, KEYCHAIN, OLD_COPY, SECRETS_FILE, SLOTS, SLOTS_BY_ID, SOURCE_LABELS, YAML, KeyStoreError,
                      clean_value, mask)
from .widgets import Card, CardButton, RowTable

HINTS = "Enter set · t test · Del remove · a switch AI · Tab AI settings · Esc close"
EDIT_HINTS = "Enter test and save · Esc cancel"
PROVIDER_LABELS = {"anthropic": "Anthropic", "gemini": "Google Gemini", "openai": "OpenAI", "openrouter": "OpenRouter",
                   "ollama": "Ollama (on this machine, no key)", "openai_compatible": "OpenAI-compatible server"}
NEEDS_URL = ("ollama", "openai_compatible")
NO_PROVIDER = "none"
PROFILE_NAMES = ("Primary", "Alternate")


class KeyCard(Card):
    AUTO_FOCUS = ""  # Text boxes only take focus when asked, so single-key commands work first

    DEFAULT_CSS = """
    KeyCard { align: center middle; }
    #key-card-scroll {
        width: 94; max-width: 100%; height: auto; max-height: 95%;
        padding: 1 2; border: round $primary; background: $background;
    }
    #key-title { height: 1; text-style: bold; color: $accent; }
    #key-notice { height: auto; margin-top: 1; }
    #ai-section { height: auto; margin-top: 1; }
    .ai-profile, .ai-url-row { height: 1; }
    .ai-use { width: 13; min-width: 13; }
    .ai-provider { width: 30; }
    .ai-model { width: 1fr; margin-left: 1; }
    .ai-url-label { width: 14; height: 1; color: $text-muted; padding-left: 2; }
    .ai-url { width: 1fr; }
    #key-table { height: auto; margin-top: 1; background: $background; scrollbar-size-vertical: 1; }
    #key-table > .datatable--cursor, #key-table > .datatable--hover {
        background: $panel; color: $foreground; text-style: none;
    }
    #key-hint { height: 1; margin-top: 1; color: $text-muted; }
    #key-input { display: none; margin-top: 1; }
    #key-input.editing { display: block; }
    #key-status { height: auto; margin-top: 1; }
    #key-buttons { height: 1; margin-top: 1; }
    #key-table { overflow-x: hidden; }
    """

    def __init__(self):
        super().__init__()
        self.editing = False
        self.confirm: Optional[str] = None  # "delete" or "move" while waiting for a second press
        self.force_value: Optional[str] = None  # Rejected key the user can still save by pressing Enter again
        self.busy = False
        self.message: Optional[Text] = None
        self.results: Dict[str, CheckResult] = {}
        self.pending_task: Optional[asyncio.Task] = None
        self.rows = []

    @property
    def config(self):
        return self.app.key_config

    @property
    def slot(self):
        table = self.query_one("#key-table", RowTable)
        return self.rows[table.cursor_row] if 0 <= table.cursor_row < len(self.rows) else self.rows[0]

    def visible_slots(self):
        """AI keys show for the chosen providers, along with everything else"""
        providers = {p["provider"] for p in self.config.ai_profiles}
        return [s for s in SLOTS if s.section != "ai" or s.provider in providers]

    def compose(self) -> ComposeResult:
        options = [("None (AI features off)", NO_PROVIDER)] + [(PROVIDER_LABELS[p], p) for p in ai.PROVIDERS]
        with VerticalScroll(id="key-card-scroll"):
            yield Static("API KEYS", id="key-title")
            yield Static(id="key-notice")
            with Vertical(id="ai-section"):
                for i, name in enumerate(PROFILE_NAMES):
                    profile = self.config.ai_profiles[i]
                    with Horizontal(classes="ai-profile"):
                        yield CardButton(name, id=f"ai-use-{i}", classes="ai-use")
                        yield Select(options, value=profile["provider"] or NO_PROVIDER, allow_blank=False,
                                     id=f"ai-provider-{i}", classes="ai-provider", compact=True)
                        yield Input(id=f"ai-model-{i}", classes="ai-model", compact=True)
                    with Horizontal(classes="ai-url-row", id=f"ai-url-row-{i}"):
                        yield Static("Server URL", classes="ai-url-label")
                        yield Input(id=f"ai-url-{i}", classes="ai-url", compact=True)
            yield RowTable(id="key-table", cursor_type="row", show_header=False)
            yield Static(id="key-hint")
            yield Input(password=True, id="key-input", placeholder="Paste the key; it stays hidden", compact=True)
            yield Static(id="key-status")
            with Horizontal(id="key-buttons"):
                yield CardButton("Set key", id="key-set")
                yield CardButton("Test", id="key-test")
                yield CardButton("Remove", id="key-remove")
                yield CardButton("Move to safe storage", id="key-move")
                yield CardButton("Close", id="key-close")

    def on_mount(self) -> None:
        scroll = self.query_one("#key-card-scroll")
        scroll.can_focus = False  # So Tab goes straight to the AI settings
        scroll.border_subtitle = HINTS
        table = self.query_one("#key-table", RowTable)
        table.add_column("", key="group", width=13)
        table.add_column("", key="label", width=19)
        table.add_column("", key="value", width=12)
        table.add_column("", key="where", width=20)
        table.add_column("", key="test", width=13)
        for i in range(len(PROFILE_NAMES)):
            self.fill_ai_fields(i)
        self.redraw()

    def say(self, message: str, style: str = "") -> None:
        self.message = Text(message, style=style or self.app.palette.text)

    # What's on screen

    def fill_ai_fields(self, index: int) -> None:
        profile = self.config.ai_profiles[index]
        provider = profile["provider"]
        model = self.query_one(f"#ai-model-{index}", Input)
        example = ai.MODEL_EXAMPLES.get(provider)
        model.value = profile["model"]
        model.placeholder = f"Required: model, e.g. {example}" if example else "Required: the model's ID"
        model.display = provider in ai.PROVIDERS
        url = self.query_one(f"#ai-url-{index}", Input)
        url.value = profile["base_url"]
        url.placeholder = ai.PROVIDERS.get(provider) or "Required, e.g. http://localhost:1234/v1"
        self.query_one(f"#ai-url-row-{index}").display = provider in NEEDS_URL

    def update_profile_buttons(self) -> None:
        for i, name in enumerate(PROFILE_NAMES):
            active = i == self.config.active_ai_profile
            self.query_one(f"#ai-use-{i}", CardButton).label = f"{'●' if active else '○'} {name}"

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
        if store.old_copy_exists:
            text.append(f"⚠ {OLD_COPY} may hold plaintext keys, even in comments. Check it, then delete it.\n", style=f"bold {p.warn}")
        if self.app.ai_problem:
            text.append(f"AI is off: {self.app.ai_problem}.\n", style=p.warn if self.config.ai.get("provider") else p.muted)
        text.rstrip()
        return text

    def row_cells(self, slot, first_in_group: bool):
        p = self.app.palette
        value = self.config.key_value(slot.id)
        source = self.config.key_sources.get(slot.id)
        where = SOURCE_LABELS.get(source, "") if value else ""
        weak = source in (YAML, FILE)
        result = self.results.get(slot.id)
        mark, mark_style = "", p.muted
        if result:
            mark, mark_style = {key_check.OK: ("✓ works", p.good), key_check.REJECTED: ("✗ rejected", p.bad)}.get(
                result.status, ("? unconfirmed", p.warn))
        return (Text(slot.group if first_in_group else "", style=f"bold {p.muted}"),
                Text(slot.label, style=f"bold {p.text}", no_wrap=True, overflow="ellipsis"),
                Text(mask(value) if value else "not set", style=p.text if value else p.muted),
                Text(where, style=p.warn if weak else p.muted),
                Text(mark, style=mark_style))

    def redraw(self) -> None:
        table = self.query_one("#key-table", RowTable)
        chosen = self.rows[table.cursor_row].id if self.rows and table.cursor_row < len(self.rows) else None
        self.rows = self.visible_slots()
        table.clear()
        group = None
        for slot in self.rows:
            table.add_row(*self.row_cells(slot, slot.group != group))
            group = slot.group
        ids = [s.id for s in self.rows]
        table.move_cursor(row=ids.index(chosen) if chosen in ids else 0, animate=False)
        self.query_one("#key-notice", Static).update(self.storage_notice())
        self.query_one("#key-status", Static).update(self.message or "")
        self.update_hint()
        self.update_profile_buttons()
        self.query_one("#key-move").display = bool(self.config.keys.movable())

    def update_hint(self) -> None:
        self.query_one("#key-hint", Static).update(self.slot.hint)

    def on_data_table_row_highlighted(self, event) -> None:
        event.stop()
        if self.rows:
            self.update_hint()

    def on_data_table_row_selected(self, event) -> None:
        """Clicking the selected row is the mouse version of Enter"""
        event.stop()
        if not self.editing and not self.busy:
            self.start_edit()
            self.redraw()

    # The AI provider

    def on_select_changed(self, event: Select.Changed) -> None:
        event.stop()
        index = int(event.select.id.rsplit("-", 1)[1])
        provider = "" if event.value in (NO_PROVIDER, Select.BLANK) else event.value
        if provider == self.config.ai_profiles[index]["provider"]:
            self.set_focus(None)
            return
        self.app.set_ai_profile(index, provider, "", "")  # A model belongs to one provider
        self.fill_ai_fields(index)
        self.message = None
        self.redraw()
        if provider:  # The next thing this provider needs
            self.query_one(f"#ai-model-{index}", Input).focus()
        else:
            self.set_focus(None)

    def save_ai_fields(self, index: int) -> None:
        profile = self.config.ai_profiles[index]
        model = self.query_one(f"#ai-model-{index}", Input).value.strip()
        url = self.query_one(f"#ai-url-{index}", Input).value.strip()
        if url and not url.startswith(("https://", "http://")):
            self.say("The server URL should start with http:// or https://", self.app.palette.warn)
            self.redraw()
            return
        if (model, url) != (profile["model"], profile["base_url"]):
            self.app.set_ai_profile(index, profile["provider"], model, url)
            self.say("AI settings saved.", self.app.palette.good)
            self.redraw()

    def use_profile(self, index: int) -> None:
        p = self.app.palette
        if not self.config.ai_profiles[index]["provider"]:
            self.say(f"Choose a provider for {PROFILE_NAMES[index]} first.", p.warn)
            return
        self.app.activate_ai_profile(index)
        self.say(f"{PROFILE_NAMES[index]} AI is now active.", p.good)

    def on_input_blurred(self, event: Input.Blurred) -> None:
        if event.input.id.startswith("ai-"):
            self.save_ai_fields(int(event.input.id.rsplit("-", 1)[1]))

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
        self.editing_slot = slot.id
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
        if event.input.id != "key-input":
            self.save_ai_fields(int(event.input.id.rsplit("-", 1)[1]))
            self.set_focus(None)
            return
        if self.busy:
            return
        p = self.app.palette
        slot = SLOTS_BY_ID[self.editing_slot]
        try:
            value = clean_value(slot, event.value)
        except KeyStoreError as e:
            self.say(str(e), p.warn)
            self.redraw()
            return
        if value == self.force_value:
            self.run_task(self.save_key(slot.id, value))
        else:
            self.run_task(self.test_then_save(slot.id, value))

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

    def check(self, slot_id: str, value: str):
        return key_check.check_key(slot_id, value, self.config.ai, self.config.notifications, self.config.sources)

    async def test_then_save(self, slot_id: str, value: str) -> None:
        p = self.app.palette
        self.say("Testing...", p.muted)
        self.redraw()
        result = await self.check(slot_id, value)
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
        result = await self.check(slot_id, self.config.key_value(slot_id))
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

    # Commands: every one is reachable by key and by mouse

    def command_test(self) -> None:
        slot = self.slot
        if self.config.key_value(slot.id):
            self.run_task(self.test_stored(slot.id))
        else:
            self.say("Nothing to test yet. Press Enter to add this key.", self.app.palette.muted)

    def command_delete(self, confirm: Optional[str]) -> None:
        p = self.app.palette
        slot = self.slot
        if not self.config.key_value(slot.id):
            self.say("Nothing to remove.", p.muted)
        elif self.config.key_sources.get(slot.id) == ENV:
            self.say(f"{slot.label} is set by {slot.env}. Remove it there.", p.warn)
        elif confirm == "delete":
            self.run_task(self.delete_key(slot.id))
        else:
            self.confirm = "delete"
            self.say(f"Press again to remove {slot.label}.", p.warn)

    def command_move(self, confirm: Optional[str]) -> None:
        p = self.app.palette
        if not self.config.keys.movable():
            self.say("Nothing to move.", p.muted)
        elif confirm == "move":
            self.run_task(self.move_keys())
        else:
            self.confirm = "move"
            self.say("Press again to move these keys and clear the old copies.", p.warn)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        confirm, self.confirm = self.confirm, None
        button = event.button.id
        if button == "key-close":
            self.dismiss()
            return
        if self.busy or self.editing:
            return
        if button.startswith("ai-use-"):
            self.use_profile(int(button.rsplit("-", 1)[1]))
        if button == "key-set":
            self.start_edit()
        elif button == "key-test":
            self.command_test()
        elif button == "key-remove":
            self.command_delete(confirm)
        elif button == "key-move":
            self.command_move(confirm)
        self.redraw()

    def on_key(self, event: events.Key) -> None:
        if self.editing:
            if event.key == "escape":
                event.stop()
                self.cancel_task()
                self.stop_edit()
                self.message = None
                self.redraw()
            return  # Everything else belongs to the input
        focused = self.focused
        if isinstance(focused, Input):
            if event.key == "escape":
                event.stop()
                self.set_focus(None)
            return
        if focused is not None:  # The provider list has its own keys
            if event.key == "escape" and isinstance(focused, Select) and not focused.expanded:
                event.stop()
                self.set_focus(None)
            return
        if event.key in ("tab", "shift+tab"):
            return  # Tab reaches the AI settings
        event.stop()
        event.prevent_default()
        key = event.key
        confirm, self.confirm = self.confirm, None
        if key == "escape":
            self.dismiss()
            return
        if self.busy:
            return
        table = self.query_one("#key-table", RowTable)
        if key == "up":
            table.action_cursor_up()
            self.message = None
        elif key == "down":
            table.action_cursor_down()
            self.message = None
        elif key == "enter":
            self.start_edit()
        elif key == "t":
            self.command_test()
        elif key == "delete":
            self.command_delete(confirm)
        elif key == "m":
            self.command_move(confirm)
        elif key == "a":
            self.use_profile((self.config.active_ai_profile + 1) % len(PROFILE_NAMES))
        else:
            return
        self.redraw()

    def can_close_by_click(self) -> bool:
        return not self.editing

    def cancel_task(self) -> None:
        if self.pending_task and not self.pending_task.done():
            self.pending_task.cancel()
        self.busy = False

    def on_unmount(self) -> None:
        self.cancel_task()
