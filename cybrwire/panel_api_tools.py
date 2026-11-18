"""The IOC lookup page (API Tools view).

Idle, it shows the box and a short list to try: your recent lookups and the freshest indicators
from your feeds. After a lookup it shows one verdict and a row per provider. These are methods of
the app, kept here so each panel lives in its own file."""

import asyncio
import logging

from rich.text import Text
from textual.widgets import Static

from . import ioc
from .enrichment import enrichment_engine
from .widgets import IndicatorBox, IocTable


class ApiToolsMixin:
    def idle_api(self) -> bool:
        """True while the page is waiting for something to look up (and there is something to look up with)"""
        return bool(enrichment_engine.providers) and not self.api_tools_last_query and not self.api_tools_loading

    def sync_api_view(self):
        """The box, its type label, the providers, then either the suggestions or the answer"""
        p = self.palette
        view = self.query_one("#api-view")
        box = self.query_one("#indicator-box", IndicatorBox)
        has_providers = bool(enrichment_engine.providers)
        idle = self.idle_api()
        self.query_one("#indicator-row").display = has_providers
        self.query_one("#api-providers").display = has_providers
        self.query_one("#ioc-heading").display = idle
        self.query_one("#ioc-table").display = idle
        self.query_one("#api-results").display = not idle
        self.query_one("#act-clear").display = has_providers and not idle
        self.query_one("#indicator-kind", Static).update(ioc.kind_chip(box.value, p))
        typed_kind = ioc.describe(ioc.refang(box.value))[1]
        self.query_one("#api-providers", Static).update(
            ioc.providers_line(enrichment_engine.providers, typed_kind or self.api_tools_last_kind, p))
        if idle:
            self.sync_ioc_table()
        self.query_one("#api-content", Static).update(self.make_api_tools_content())
        if self.prompt == "indicator":
            hints = [("Enter", "look up"), ("↑↓", "pick a suggestion" if idle else "scroll"), ("Esc", "clear"), ("v", "next view when empty")]
        elif idle:
            hints = [("↑↓", "select"), ("Enter", "look up"), ("/", "type or paste one"), ("v", "next view")]
        elif has_providers:
            hints = [("Esc", "new lookup"), ("/", "type another"), ("↑↓", "scroll"), ("v", "next view")]
        else:
            hints = [("Shift+K", "add keys"), ("v", "next view")]
        title_text, border = self.frame("IOC LOOKUP", self.panel_focus == "main")
        view.border_title = title_text
        view.border_subtitle = self.hint_bar(hints)
        view.styles.border = ("round", border)

    def sync_ioc_table(self):
        """Suggestions to try, rebuilt only when they change"""
        p = self.palette
        rows = ioc.suggestions(self.api_tools_recent, self.all_alerts)
        table = self.query_one("#ioc-table", IocTable)
        heading = Text()
        heading.append("TRY ONE  ", style=f"bold {p.accent}")
        heading.append("your recent lookups, then fresh indicators from your feeds" if rows
                       else "Nothing to suggest yet. Type or paste an IP, hash, domain or URL above.", style=p.muted)
        self.query_one("#ioc-heading", Static).update(heading)
        width = table.size.width or max(60, self.size.width * 3 // 4 - 8)
        avail = max(56, width - 12)
        value_w = min(46, int(avail * 0.45))
        note_w = max(10, avail - 7 - 8 - value_w)
        signature = (p.key, width, tuple((r.origin, r.value, r.note) for r in rows))
        self.ioc_rows = rows
        if signature == self.ioc_signature:
            return
        self.ioc_signature = signature
        old = table.cursor_row
        table.clear(columns=True)
        for key, w in (("origin", 7), ("value", value_w), ("kind", 8), ("note", note_w)):
            table.add_column("", key=key, width=w)
        for r in rows:
            label = ioc.describe(r.value)[0]
            table.add_row(Text("RECENT" if r.origin == "recent" else "FEED", style=p.accent if r.origin == "recent" else p.muted),
                          Text(r.value[:value_w], style=f"bold {p.text}", no_wrap=True),
                          Text(label, style=p.muted),
                          Text(r.note[:note_w], style=p.muted, no_wrap=True))
        table.show_cursor = bool(rows)
        if rows:
            table.move_cursor(row=min(old, len(rows) - 1), animate=False)

    def selected_ioc(self):
        table = self.query_one("#ioc-table", IocTable)
        return self.ioc_rows[table.cursor_row] if 0 <= table.cursor_row < len(self.ioc_rows) else None

    def run_selected_ioc(self):
        choice = self.selected_ioc()
        if choice:
            self.query_one("#indicator-box", IndicatorBox).value = choice.value
            self.run_api_lookup(choice.value)

    def focus_indicator_box(self):
        if enrichment_engine.providers:
            box = self.query_one("#indicator-box", IndicatorBox)
            box.focus()
            self.prompt = box.prompt_name

    def run_api_lookup(self, indicator):
        typed = indicator.strip()
        indicator = ioc.refang(typed)  # hxxps://evil[.]com is looked up as https://evil.com
        if self.api_tools_loading or not indicator or not enrichment_engine.providers:
            return
        box = self.query_one("#indicator-box", IndicatorBox)
        if box.value != indicator:
            box.value = indicator
        self.api_tools_shown_as = typed
        self.api_tools_last_kind = ioc.describe(indicator)[1]
        self.api_tools_recent = [indicator] + [v for v in self.api_tools_recent if v != indicator][:ioc.MAX_RECENT - 1]
        self.api_tools_last_query = indicator
        self.api_tools_last_results = {}
        self.api_tools_loading = True
        asyncio.create_task(self._run_api_tools_query(indicator))
        self.update_display()

    def clear_api_results(self):
        """Back to the suggestions for a new lookup"""
        self.api_tools_last_query = ""
        self.api_tools_last_results = {}
        self.api_tools_last_kind = ""
        self.api_tools_shown_as = ""
        self.query_one("#indicator-box", IndicatorBox).value = ""
        self.finish_typing()
        self.update_display()

    def make_api_tools_content(self) -> Text:
        """What fills the results area: the empty state, a progress line, or the answer"""
        p = self.palette
        if not enrichment_engine.providers:
            return ioc.render_no_providers(p)
        if self.api_tools_loading:
            return ioc.render_loading(self.api_tools_last_query, len(enrichment_engine.providers), p)
        if self.api_tools_last_query:
            return ioc.render_results(self.api_tools_last_query, self.api_tools_last_results, p, self.api_tools_shown_as)
        return Text("")

    def lookup_indicator(self, alert):
        """Send an indicator from the Indicators view to API Tools and run the lookup"""
        if not enrichment_engine.providers:
            self.notify("No enrichment providers yet. Press Shift+K to add keys", timeout=4)
            return
        value = alert.get("ioc") or ""
        if alert.get("ioc_type") == "cidr":
            value = value.split("/")[0]
            self.notify("Looking up the network address of this range", timeout=3)
        self.app_state.mark_read(alert)
        self.main_view_mode = "api_tools"
        self.query_one("#indicator-box", IndicatorBox).value = value
        self.run_api_lookup(value)
        self.update_display()

    async def _run_api_tools_query(self, indicator: str):
        """Run an enrichment lookup for the indicator across all configured providers"""
        try:
            self.api_tools_last_results = await enrichment_engine.enrich(indicator)
        except Exception as e:
            logging.error(f"Error querying providers for {indicator}: {e}")
            self.api_tools_last_results = {}
        finally:
            self.api_tools_loading = False
            self.update_display()  # The answer shows straight away, not at the next scheduled redraw
