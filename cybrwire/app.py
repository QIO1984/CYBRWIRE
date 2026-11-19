#!/usr/bin/env python3
import argparse
import asyncio
import time
import httpx
import logging
import os
import sys
from datetime import datetime, timedelta, timezone
from typing import Dict, Any
from rich.console import Console
from rich.text import Text
from rich.theme import Theme
from rich.panel import Panel
from rich import box
from collections import Counter
from .enrichment import enrichment_engine, initialize_enrichment
from . import ai
from . import USER_AGENT, __version__
from . import paths
from .config import ENRICHMENT_SLOTS as ENRICHMENT_KEYS, RedactingFormatter, load_config, redact, secure_file
from .keystore import FILE, OLD_COPY, SECRETS_FILE, SLOTS_BY_ID
from .links import open_link
from .feeds import MAX_TITLE_LEN, KEV_CATALOG, parse_json, parse_rss, parse_threatfox, parse_txt, parse_urlhaus, parse_circl, parse_euvd, parse_metasploit, parse_status, fetch_doomsday_seconds
from .incidents import CVE_RE, age
from . import cve_intel
from .cve_card import CveCard
from .state import AppState, alert_key
from .watch_card import WatchCard
from .key_card import KeyCard
from .watchlist import Watchlist, matches_search
from .dedupe import group_duplicates
from .digest import build_digest
from .history import History
from . import notify
from textual.app import App, ComposeResult
from textual.coordinate import Coordinate
from textual.css.query import NoMatches
from textual.widgets import Input, Static
from . import sound
from . import evidence
from .livewire import LiveWire, LiveWirePanel, wire_items
from .panel_dashboard import DashboardMixin
from .panel_api_tools import ApiToolsMixin
from .panel_war_room import WarRoomMixin
from .panel_alerts import AlertViewsMixin
from .panel_map import MapMixin
from .effects import EffectsMixin
from . import web_sound
from .map_card import MapCard
from .theme_card import ThemeCard
from .screens import EDITION, HelpScreen, LoadingScreen, boxed
from .chrome import CONTENT_KINDS, CybrWireFooter, StyledHeader, WorldClock
from .widgets import CardButton, DashboardPanel, IndicatorBox, IocTable, PagerBar, SearchBox, ViewTable
from textual.containers import Container, Horizontal, Vertical, VerticalScroll
from textual.reactive import reactive
from textual.screen import ModalScreen
from textual.theme import Theme as TextualTheme
from .theme import COLD_WAR, DEFAULT_PALETTE, PALETTES, Palette
from textual import events

MIGRATED = paths.bootstrap()

# Log to a file - writing to stderr would draw over the TUI
logging.basicConfig(
    level=logging.WARNING,
    format='%(asctime)s %(levelname)s %(name)s: %(message)s',
    filename=os.path.join(paths.USER_DIR, "cybrwire.log"),
)
for _handler in logging.getLogger().handlers:
    _handler.setFormatter(RedactingFormatter(_handler.formatter._fmt if _handler.formatter else None))
    if getattr(_handler, "baseFilename", None):
        secure_file(_handler.baseFilename)
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)

# Console for Rich rendering
console = Console(color_system="truecolor", theme=Theme({
    "critical": "bold white on red",
    "zeroday": "bold black on bright_yellow",
    "ransomware": "bold white on #ff0066",
    "apt": "bold white on #800080",
    "exploit": "bold bright_red",
    "info": "bright_cyan",
    "new": "bold reverse white on #00ff00",
}))



HEADERS = {"User-Agent": USER_AGENT}
HEAT_BAR_WIDTH = 33
REFRESH_INTERVAL = 300
SIGHTING_DAYS = 7
DOOMSDAY_DEFAULT_SECONDS = 85  # Setting announced January 2026; refreshed from thebulletin.org at runtime
DOOMSDAY_CHECK_INTERVAL = timedelta(days=1)
FEED_TIMEOUT = 15          # Seconds before giving up on a single feed
MAX_CONCURRENT_FEEDS = 8   # Higher values can overwhelm local DNS resolvers

CONFIG = load_config()
STATE = AppState()
HISTORY = History()


# Global state
alert_queue = []
breach_list = []
source_file_stats = {"curated": 0, "custom": 0, "community": 0}
failed_feeds = {}  # Tracks current cycle failures: {feed_name: (error_msg, failure_count)}
disabled_feeds = {}  # Tracks disabled feeds: {feed_name: (error_msg, disable_reason)}
currently_loading = None
incidents_cache = []
start_time = datetime.now(timezone.utc)

force_event = asyncio.Event()


BREACH_CHECK_SECONDS = 3600  # New breaches are added a few times a day at most
_breaches_checked = None


async def fetch_breaches():
    """Fetch recent breaches from HaveIBeenPwned, at most once an hour"""
    global breach_list, _breaches_checked
    if _breaches_checked is not None and time.monotonic() - _breaches_checked < BREACH_CHECK_SECONDS:
        return
    try:
        async with httpx.AsyncClient(headers={"User-Agent": USER_AGENT}, timeout=10) as c:
            r = await c.get("https://haveibeenpwned.com/api/v3/breaches")
            breaches = r.json()
            # Get the 7 most recently added breaches (sorted by AddedDate, not BreachDate)
            breach_list = sorted(breaches, key=lambda x: x.get("AddedDate", ""), reverse=True)[:7]
            _breaches_checked = time.monotonic()
    except Exception as e:
        logging.error(f"Failed to fetch breaches: {e}")


class CybrWireApp(DashboardMixin, ApiToolsMixin, WarRoomMixin, AlertViewsMixin, MapMixin, EffectsMixin, App):
    """Textual-based CybrWire threat intelligence dashboard"""
    
    # Colors come from the active palette, registered as a Textual theme (see apply_theme)
    CSS = """
    Screen, #main-layout, #feeds-container, #dashboard, #ticker {
        background: $background;
        color: $foreground;
    }
    
    Header {
        background: $background;
        color: $foreground;
    }
    
    CybrWireFooter {
        background: $panel;
        color: $foreground;
        height: 1;
    }
    
    #main-layout {
        border: none;
    }
    
    #feeds-container {
        width: 3fr;
        height: 100%;
    }
    
    .view {
        height: 100%;
        padding: 1 2;
        border: round $primary;
        border-title-align: center;
        border-subtitle-align: center;
    }
    
    #flash-banner {
        height: 1;
        display: none;
        text-style: bold;
    }

    #map-main {
        width: 100%;
        height: 1fr;
    }

    #indicator-row {
        height: 1;
        margin-bottom: 1;
    }
    
    #indicator-prefix {
        width: 11;
        color: $accent;
        text-style: bold;
    }
    
    #indicator-box {
        width: 1fr;
        background: transparent;
    }
    
    #api-results {
        height: 1fr;
        scrollbar-size-vertical: 1;
    }

    #indicator-kind {
        width: 12;
        content-align: center middle;
    }

    #api-providers {
        height: auto;
        margin-bottom: 1;
    }

    #ioc-heading {
        height: auto;
        margin-bottom: 1;
    }
    
    #search-row {
        height: 1;
        margin-bottom: 1;
    }
    
    #search-prefix {
        width: 2;
        color: $accent;
        text-style: bold;
    }
    
    #search-box {
        width: 1fr;
        background: transparent;
    }
    
    ViewTable {
        height: 1fr;
        background: $background;
        scrollbar-size-vertical: 1;
    }
    
    ViewTable > .datatable--cursor, ViewTable > .datatable--hover {
        background: $panel;
        color: $foreground;
        text-style: none;
    }
    
    ViewTable > .datatable--header {
        background: $background;
        color: $text-muted;
        text-style: bold;
    }
    
    #alert-preview {
        margin-top: 1;
        height: auto;
    }
    
    #dashboard-column {
        width: 1fr;
        height: 100%;
    }
    
    #dashboard {
        height: 1fr;
    }
    
    #dashboard-pager {
        height: 1;
        content-align: center middle;
    }
    
    .view-actions {
        height: 1;
    }
    
    #loading-content {
        padding: 2;
    }
    """
    
    TITLE = f" C Y B R W I R E // v{__version__} LEGENDARY EDITION "
    
    BINDINGS = [
        ("r", "refresh", "Force Refresh"),
        ("d", "cycle_data_age", "Data Age"),
        ("f", "cycle_filter_type", "Alert Type"),
        ("4", "cycle_feeds", "Content Type"),
        ("slash", "start_search", "Search"),
        ("w", "toggle_watch_only", "Watchlist Only"),
        ("W", "edit_watchlist", "Edit Watchlist"),
        ("l", "jump_to_wire", "Go To Live Wire Alert"),
        ("b", "cycle_sound", "Alert Sound"),
        ("z", "toggle_clocks", "World Clock"),
        ("m", "show_map", "Threat Map"),
        ("x", "toggle_effects", "Effects"),
        ("k", "toggle_kiosk", "Kiosk"),
        ("B", "toggle_hum", "Ambient Hum"),
        ("K", "manage_keys", "API Keys"),
        ("i", "open_cve_card", "CVE Card"),
        ("u", "toggle_grouping", "Group Duplicates"),
        ("tab", "toggle_panel_focus", "Switch Panel"),
        ("v", "toggle_view", "Toggle View"),
        ("e", "re_enable_feeds", "Re-enable Feeds"),
        ("c", "toggle_cold_war", "Cold War Mode"),
        ("g", "ai_refresh", "AI Briefing"),
        ("t", "cycle_theme", "Cycle Theme"),
        ("T", "theme_picker", "Theme Picker"),
        ("h", "show_help", "Help"),
        ("q", "quit", "Quit"),
    ]
    
    recency_hours = reactive(24)
    cold_war_mode = reactive(False)
    next_refresh = reactive(datetime.now(timezone.utc))
    is_loading = reactive(True)
    dashboard_page_offset = reactive(0)  # Pagination for dashboard panel
    panel_focus = reactive("main")  # "main" or "dashboard" - which panel gets paged by arrows
    filter_mode = reactive("all")  # all, alerts, posts
    theme_mode = reactive("default")  # default, dark, blue, purple, matrix
    kind_index = reactive(0)  # Index into CONTENT_KINDS
    data_age_index = reactive(0)  # Cycle: 0=24h, 1=48h, 2=7d
    filter_type_index = reactive(1)  # Cycle: 0=all, 1=alerts, 2=posts
    dashboard_panel_index = reactive(0)  # Cycle dashboard: 0=metrics, 1=war room, 2=feed status
    main_view_mode = reactive("map")  # map, alerts, incidents, or api_tools
    
    def __init__(self, cold_war=False, recency=24):
        super().__init__()
        self._initializing = True
        saved = STATE.settings
        self.cold_war_mode = cold_war
        self.recency_hours = recency
        self.data_age_index = {24: 0, 48: 1, 168: 2}.get(recency, 0)
        self.refresher_task = None
        self.wire = LiveWire()
        self.last_arrivals = []
        self.feed_cache = {}  # Feed name -> (when fetched, parsed items), for slow-moving lists
        self.sound = saved.get("sound", sound.OFF)
        self.show_clocks = saved.get("world_clock", True)
        self.effects_on = bool(saved.get("effects", True))  # Map pulse and the arrival flash
        self.hum_on = bool(saved.get("hum", False))           # Optional quiet ambient hum
        self.kiosk_on = bool(saved.get("kiosk", False))      # Rotate the main view when nobody is using it
        self.kiosk_last_move = time.monotonic()
        self.last_input = time.monotonic()
        self.typing = {}  # Alert key -> when its title started typing into the feed (None until it is first drawn)
        self.main_view_mode = saved.get("main_view") if saved.get("main_view") in ("map", "alerts", "incidents") else "map"
        self.feed_rows = []         # Alerts in the table, in row order
        self.feed_signature = None  # What the table is showing, to skip needless rebuilds
        self.feed_at_top = False    # Return to the first row at the next redraw
        self.marked_row = None      # Row currently drawn as selected
        self.breach_urls = []
        self.feed_at_top = True
        self.incident_list = []         # Incidents in the table, in row order
        self.incident_signature = None
        self.incident_marked = None
        self.theme_mode = saved.get("theme") if saved.get("theme") in PALETTES else DEFAULT_PALETTE
        for p in (*PALETTES.values(), COLD_WAR):
            self.register_theme(TextualTheme(
                name=f"cybrwire-{p.key}", dark=True,
                primary=p.focus, secondary=p.accent, accent=p.accent,
                foreground=p.text, background=p.bg, surface=p.bg, panel=p.surface,
                success=p.good, warning=p.warn, error=p.bad,
            ))
        # Alerts is the default, and anyone from before that gets it once too
        self.filter_type_index = saved.get("filter_type_index", 1) if saved.get("alerts_default") else 1
        self.filter_mode = ["all", "alerts", "posts"][self.filter_type_index]
        self.kind_index = saved.get("kind_index", 0) if 0 <= saved.get("kind_index", 0) < len(CONTENT_KINDS) else 0
        
        self.watchlist = Watchlist(CONFIG.watchlist, STATE.watchlist)
        self.watch_only = bool(saved.get("watch_only", False))
        self.search_query = ""     # Active search; narrows the feed until cleared with Esc
        self.prompt = None         # Text being typed: "search" or None
        self.history_cache = (None, [])  # Last history search: (query, results)
        self.group_dupes = bool(saved.get("group_dupes", True))
        self.groups = group_duplicates([])
        self.groups_key = None
        
        self.feed_failure_counts = {}  # Track consecutive failures per feed
        
        # Redraw only when something changed (data, keys, mouse, timers)
        self.dirty = True
        self.last_full_render = 0.0
        
        # Incidents for the current data window, rebuilt only when inputs change
        self.incidents = []
        self.incidents_key = None
        
        # Threat summary (local keyword analysis) shown under the AI briefing
        self.threat_summary = None
        self.threat_summary_full = ""
        self.threat_summary_timestamp = None
        self.threat_summary_loading = False
        self.threat_summary_pages = []  # Paginated content
        self.feed_status_pages = 1
        self.threat_summary_page = 0  # Current page
        
        # AI analysis (any configured provider)
        CONFIG.load_ai_profiles(STATE.settings.get("ai"))  # What was picked in the app beats any ai: section in YAML
        self.ai_settings = CONFIG.ai
        self.ai_problem = ai.configuration_problem(self.ai_settings)
        # Restore the last briefing so launching the app doesn't cost an AI call
        saved_briefing = STATE.briefing
        self.ai_briefing = saved_briefing.get("text")
        self.ai_briefing_time = datetime.fromisoformat(saved_briefing["time"]) if saved_briefing.get("time") else None
        self.ai_briefing_error = None
        self.ai_briefing_loading = False
        self.alert_explanations = {}  # alert key -> AI explanation text (or error)
        self.explaining = set()       # alert keys with a request in flight
        
        # CVSS lookups (NVD, rate-limited, cached in the app state)
        self.nvd = cve_intel.NvdClient(STATE.cvss, (CONFIG.enrichment.get("nvd") or {}).get("api_key"))
        self.nvd.prune_unscored()
        
        # Doomsday Clock (seconds to midnight), refreshed from thebulletin.org daily
        self.doomsday_seconds = STATE.doomsday.get("seconds", DOOMSDAY_DEFAULT_SECONDS)
        
        # Initialize API Tools panel state
        self.api_tools_last_query = ""  # Last queried indicator
        self.api_tools_last_results = {}  # Results from all providers {provider: EnrichmentData}
        self.api_tools_loading = False  # Is query in progress
        self.api_tools_recent = []      # Indicators looked up this session, newest first
        self.api_tools_last_kind = ""   # ip, hash, domain or url, for the last lookup
        self.api_tools_shown_as = ""    # What was typed, if it was defanged and had to be cleaned up
        self.ioc_rows = []              # Suggestions in the table, in row order
        self.ioc_signature = None
        
        # Initialize next refresh time
        self.next_refresh = datetime.now(timezone.utc) + timedelta(seconds=REFRESH_INTERVAL)
        
        self._initializing = False  # Allow watchers to work now
    
    def save_settings(self):
        """Persist UI choices so the next launch starts the same way"""
        STATE.settings = {
            "recency_hours": self.recency_hours,
            "cold_war": self.cold_war_mode,
            "theme": self.theme_mode,
            "filter_type_index": self.filter_type_index,
            "alerts_default": True,
            "kind_index": self.kind_index,
            "watch_only": self.watch_only,
            "group_dupes": self.group_dupes,
            "notifications_started": STATE.settings.get("notifications_started", False),
            "ai": STATE.settings.get("ai"),
            "sound": self.sound,
            "world_clock": self.show_clocks,
            "effects": self.effects_on,
            "kiosk": self.kiosk_on,
            "hum": self.hum_on,
            "main_view": self.main_view_mode if self.main_view_mode in ("map", "alerts", "incidents") else "alerts",
        }
        STATE.save()
    
    def mark_dirty(self):
        """Schedule a redraw on the next render tick"""
        self.dirty = True
    
    
    
    
    
    
    
    

    # The panels (panel_*.py) reach the app-wide data through these, so they never read module globals
    @property
    def all_alerts(self):
        return alert_queue

    @property
    def recent_breaches(self):
        return breach_list

    @property
    def failed_feed_map(self):
        return failed_feeds

    @property
    def disabled_feed_map(self):
        return disabled_feeds

    @property
    def app_state(self):
        return STATE

    @property
    def app_config(self):
        return CONFIG

    @property
    def palette(self) -> Palette:
        """Colors for everything drawn right now; Cold War overrides the theme"""
        return COLD_WAR if self.cold_war_mode else PALETTES.get(self.theme_mode, PALETTES[DEFAULT_PALETTE])
    
    def watch_cold_war_mode(self, old_value, new_value):
        """Switch the whole UI between Cold War green and the selected theme"""
        if getattr(self, '_initializing', False):
            return
        self.apply_theme()
    
    def watch_panel_focus(self, old_value, new_value):
        """Update border styling when panel focus changes"""
        if getattr(self, '_initializing', False):
            return
        try:
            feeds_container = self.query_one("#feeds-container")
            dashboard = self.query_one("#dashboard")
            
            if new_value == "main":
                feeds_container.add_class("focused")
                dashboard.remove_class("focused")
            else:  # dashboard
                feeds_container.remove_class("focused")
                dashboard.add_class("focused")
        except Exception:
            # Widgets might not exist yet
            pass
    
    def watch_data_age_index(self, old_value, new_value):
        """Refresh footer when data age changes"""
        if getattr(self, '_initializing', False):
            return
        try:
            footer = self.query_one(CybrWireFooter)
            footer.refresh()
        except Exception:
            pass
    
    def watch_filter_type_index(self, old_value, new_value):
        """Refresh footer when filter type changes"""
        if getattr(self, '_initializing', False):
            return
        try:
            footer = self.query_one(CybrWireFooter)
            footer.refresh()
        except Exception:
            pass
    
    def apply_theme(self):
        """Activate the Textual theme for the current palette (header, footer, backgrounds, scrollbars)"""
        p = self.palette
        self.theme = f"cybrwire-{p.key}"
        self.title = f" {p.banner} " if p.banner else self.TITLE
        try:
            header = self.query_one(StyledHeader)
            # A palette banner shows as a reverse-video bar, like a classification marking
            header.styles.background = p.focus if p.banner else None
            header.styles.color = p.bg if p.banner else None
            header.styles.text_style = "bold" if p.banner else None
            header.redraw()
        except Exception:
            pass  # Not mounted yet; on_mount applies the theme again
        self.mark_dirty()
    
    def on_mount(self) -> None:
        """Show loading screen then start app"""
        self.apply_theme()
        self.query_one(WorldClock).display = self.show_clocks
        self.set_interval(0.5, self.map_tick)  # Pulses the map's markers while it is showing
        self.set_interval(2.0, self.mood_tick)  # Eases the threat-level tint of the borders
        self.set_interval(1.0, self.kiosk_tick)  # Rotates the main view in kiosk mode
        self.set_interval(0.1, self.typing_tick)  # Types urgent new alerts into the feed
        self.set_interval(0.2, self.heartbeat_tick)  # The header-corner trace
        if self.hum_on:
            self.set_timer(1.5, lambda: self.set_hum(True) or setattr(self, "hum_on", False))  # Back on after a restart; off if it can't start
        self.push_screen(LoadingScreen(self.palette, lambda: currently_loading, CONFIG.configured_api_names))
        self.refresher_task = asyncio.create_task(self.initial_load())
    
    async def initial_load(self):
        """Initial data load behind the loading screen"""
        try:
            initialize_enrichment(CONFIG.enrichment)
            await asyncio.gather(self.fetch_feeds(), fetch_breaches(), self.refresh_doomsday())
            
            # Let the loading animation finish its sequence
            await asyncio.sleep(3)
            self.pop_screen()
            self.is_loading = False
            
            asyncio.create_task(self._load_threat_summary_async())
            if not self.ai_problem and self.ai_settings.get("auto_briefing"):
                asyncio.create_task(self.generate_ai_briefing())
            asyncio.create_task(self.send_notifications())
            asyncio.create_task(self.refresher())
            self.warn_about_key_storage()
            
            self.update_display()
            self.set_interval(1.0, self.render_tick)
            self.set_interval(0.1, self.wire_tick)
        except Exception as e:
            logging.error(f"Error in initial_load: {e}", exc_info=True)
            raise
    
    async def refresh_doomsday(self):
        """Update the Doomsday Clock from thebulletin.org, at most once a day"""
        checked = STATE.doomsday.get("checked")
        now = datetime.now(timezone.utc)
        if checked and now - datetime.fromisoformat(checked) < DOOMSDAY_CHECK_INTERVAL:
            return
        try:
            self.doomsday_seconds = await fetch_doomsday_seconds()
            STATE.doomsday = {"seconds": self.doomsday_seconds, "checked": now.isoformat()}
            STATE.save()
        except Exception as e:
            logging.warning(f"Could not refresh Doomsday Clock, keeping {self.doomsday_seconds}s: {e}")
    
    def render_tick(self):
        """Redraw when something changed, and every 30s for the refresh countdown"""
        if self.dirty or time.monotonic() - self.last_full_render >= 30:
            self.update_display()
        
    def compose(self) -> ComposeResult:
        """Create child widgets for the app."""
        yield StyledHeader(show_clock=True, icon="◆")
        yield WorldClock(CONFIG.timezone, CONFIG.clocks, id="worldclock")
        yield LiveWirePanel(id="ticker")
        yield Static(id="flash-banner")  # Cold War: FLASH when something urgent arrives
        
        # Always create both layouts, use CSS to control visibility
        with Horizontal(id="main-layout"):
            with Container(id="feeds-container"):
                with Vertical(id="alerts-view", classes="view"):
                    with Horizontal(id="search-row"):
                        yield Static("/ ", id="search-prefix")
                        yield SearchBox(id="search-box", compact=True,
                                        placeholder="Type keywords to search alert titles, descriptions, sources and indicators")
                    yield ViewTable(id="feed-table", cursor_type="row", show_header=False)
                    yield Static(id="alert-preview")
                    with Horizontal(classes="view-actions"):
                        yield CardButton("Open", id="act-open")
                        yield CardButton("CVE card", id="act-cve")
                        yield CardButton("Explain with AI", id="act-explain")
                with Vertical(id="incidents-view", classes="view"):
                    yield ViewTable(id="incident-table", cursor_type="row", show_header=False)
                    with Horizontal(classes="view-actions"):
                        yield CardButton("Open latest report", id="act-open-incident")
                        yield CardButton("CVE card", id="act-cve-incident")
                with Vertical(id="map-panel", classes="view"):
                    yield Static(id="map-main")
                with Vertical(id="api-view", classes="view"):
                    with Horizontal(id="indicator-row"):
                        yield Static("Indicator: ", id="indicator-prefix")
                        yield IndicatorBox(id="indicator-box", compact=True,
                                           placeholder="Paste an IP, file hash, domain or URL, then press Enter")
                        yield Static(id="indicator-kind")
                        yield CardButton("Look up", id="act-lookup")
                    yield Static(id="api-providers")
                    yield Static(id="ioc-heading")
                    yield IocTable(id="ioc-table", cursor_type="row", show_header=False)
                    with VerticalScroll(id="api-results"):
                        yield Static(id="api-content", expand=True)
                    with Horizontal(classes="view-actions"):
                        yield CardButton("Add API keys", id="act-keys")
                        yield CardButton("New lookup", id="act-clear")
            with Vertical(id="dashboard-column"):
                yield DashboardPanel(id="dashboard", expand=True)
                yield PagerBar(id="dashboard-pager")
        
        yield CybrWireFooter()
    
    async def fetch_feeds(self):
        """Fetch data from all sources once"""
        global alert_queue, source_file_stats, failed_feeds, currently_loading
        
        new = []
        source_file_stats = {"curated": 0, "custom": 0, "community": 0}
        failed_feeds = {}

        abusech_key = (CONFIG.enrichment.get("abusech") or {}).get("api_key")
        # ThreatFox needs the abuse.ch Auth-Key; without one it is skipped rather than failing
        all_sources = [s for s in CONFIG.sources if s['name'] not in disabled_feeds and CONFIG.feed_is_ready(s)
                       and (s["type"] not in ("threatfox", "urlhaus") or abusech_key)]
        parsers = {"json": lambda r, n, f: parse_json(r.json(), n, f),
                   "rss": lambda r, n, f: parse_rss(r.text, n, f),
                   "txt": lambda r, n, f: parse_txt(r.text, n, f),
                   "threatfox": lambda r, n, f: parse_threatfox(r.json(), n, f),
                   "urlhaus": lambda r, n, f: parse_urlhaus(r.json(), n, f),
                   "circl": lambda r, n, f: parse_circl(r.json(), n, f),
                   "euvd": lambda r, n, f: parse_euvd(r.json(), n, f),
                   "metasploit": lambda r, n, f: parse_metasploit(r.json(), n, f),
                   "status": lambda r, n, f: parse_status(r.text, n, f)}
        semaphore = asyncio.Semaphore(MAX_CONCURRENT_FEEDS)
        self.wire.begin_sweep(len(all_sources))

        async def fetch_one(c, src):
            global currently_loading
            async with semaphore:
                currently_loading = src['name']
                self.wire.feed_started(src['name'])
                try:
                    # Slow-moving lists only need asking now and then
                    interval = src.get("interval_minutes")
                    cached = self.feed_cache.get(src['name'])
                    if interval and cached and time.monotonic() - cached[0] < interval * 60:
                        return cached[1]
                    result = await fetch_and_parse(c, src)
                    if interval:
                        self.feed_cache[src['name']] = (time.monotonic(), result)
                    return result
                finally:
                    self.wire.feed_done()

        async def fetch_and_parse(c, src):
            if src["type"] == "threatfox":
                r = await c.post(src["url"], json={"query": "get_iocs", "days": 1},
                                 headers={"Auth-Key": abusech_key})
            elif src["type"] == "urlhaus":
                r = await c.get(src["url"], headers={"Auth-Key": abusech_key})
            elif src["type"] == "circl":  # Only recent sightings: the full list runs to tens of thousands
                since = (datetime.now(timezone.utc) - timedelta(days=SIGHTING_DAYS)).date().isoformat()
                r = await c.get(f"{src['url']}&date_from={since}")
            else:
                r = await c.get(src["url"], **CONFIG.feed_request_parts(src))
            r.raise_for_status()
            # Parse in a thread so large feeds don't freeze the UI
            return await asyncio.to_thread(parsers[src["type"]], r, src['name'], src.get("source_file", "curated"))

        async with httpx.AsyncClient(headers=HEADERS, timeout=FEED_TIMEOUT, follow_redirects=True) as c:
            results = await asyncio.gather(*(fetch_one(c, src) for src in all_sources), return_exceptions=True)

        for src, result in zip(all_sources, results):
            src_name = src['name']
            if not isinstance(result, BaseException):
                self.feed_failure_counts.pop(src_name, None)  # Failures must be consecutive
                for item in result:
                    # Parsers that know their content type set it; otherwise the feed's kind applies
                    item.setdefault("kind", src.get("kind", "news"))
                new.extend(result)
                source_file = src.get("source_file", "curated")
                source_file_stats[source_file] = source_file_stats.get(source_file, 0) + len(result)
                continue

            error_msg = redact(str(result)) or type(result).__name__
            self.feed_failure_counts[src_name] = self.feed_failure_counts.get(src_name, 0) + 1
            failure_count = self.feed_failure_counts[src_name]

            if failure_count >= 7:
                disabled_feeds[src_name] = (error_msg, f"Auto-disabled after {failure_count} consecutive failures")
                logging.warning(f"Feed '{src_name}' auto-disabled after {failure_count} failures")
            else:
                failed_feeds[src_name] = (error_msg, failure_count)
        
        # Limit items per source based on age to keep data fresh but allow older items for 7-day view
        # Most RSS feeds provide 10-50 items, so we'll take up to 50 per source
        source_buckets = {}
        for a in new:
            src = a.get("source", "Unknown")
            if src not in source_buckets:
                source_buckets[src] = []
            if len(source_buckets[src]) < 50:
                source_buckets[src].append(a)
        
        # Newest first, with undated items (stamped at fetch time) after dated alerts
        alert_queue = sorted(
            [item for alerts in source_buckets.values() for item in alerts],
            key=lambda x: (not x.get("undated"), x["ts"]),
            reverse=True
        )
        
        currently_loading = None  # Clear loading indicator
        
        # Exploit-likelihood scores for every CVE mentioned (one batched, free request)
        await cve_intel.fetch_epss(m.upper() for a in alert_queue for m in CVE_RE.findall(f"{a['title']} {a['summary']}"))
        
        # After EPSS, because the evidence depends on those scores
        alert_queue = evidence.apply_evidence(alert_queue)
        known = set(STATE.first_seen)
        STATE.record_alerts(alert_queue)
        STATE.save()
        first_seen_now = [a for a in alert_queue if alert_key(a) not in known]
        self.last_arrivals = self.wire.end_sweep(first_seen_now, self.watchlist, self.duplicate_groups().leader_of, time.monotonic())
        await asyncio.to_thread(HISTORY.record, alert_queue)
        self.history_cache = (None, [])
        self.incidents_key = None  # Rebuild incidents for the new data
        self.mark_dirty()
    
    async def send_notifications(self):
        """Tell the configured targets about alerts they haven't heard about yet"""
        settings = CONFIG.notifications
        if not notify.is_configured(settings):
            return
        triggers = settings.get("triggers") or notify.DEFAULT_TRIGGERS
        selected = notify.select_new(alert_queue, STATE.notified, self.watchlist, triggers, self.duplicate_groups().leader_of)
        now = datetime.now(timezone.utc).isoformat()
        if not STATE.settings.get("notifications_started"):
            # First run with notifications on: today's backlog isn't news
            STATE.notified.update({alert_key(a): now for a, _ in selected})
            STATE.settings["notifications_started"] = True
            STATE.save()
            return
        if not selected:
            return
        results = await notify.send(settings, *notify.build_message(selected))
        if any(error is None for error in results.values()):
            STATE.notified.update({alert_key(a): now for a, _ in selected})
            STATE.save()
        else:
            self.notify("Notifications failed: " + ", ".join(f"{k} {v}" for k, v in results.items()), timeout=5)
    
    async def refresher(self):
        """Background task to fetch feeds periodically"""
        while True:
            # Wait for the interval, or wake early when 'r' sets force_event
            try:
                await asyncio.wait_for(force_event.wait(), timeout=REFRESH_INTERVAL)
                force_event.clear()
            except asyncio.TimeoutError:
                pass
            await asyncio.gather(self.fetch_feeds(), fetch_breaches(), self.refresh_doomsday())
            self.announce_arrivals(self.last_arrivals)
            self.arrival_effect(self.last_arrivals)
            await self.send_notifications()
            self.next_refresh = datetime.now(timezone.utc) + timedelta(seconds=REFRESH_INTERVAL)
            self.mark_dirty()
    
    def update_display(self):
        """Update the UI display"""
        if self.is_loading:
            return
        
        self.dirty = False
        self.last_full_render = time.monotonic()
        try:
            self.query_one(CybrWireFooter).refresh()  # Type, filter and count change with the feed
            
            # Update feeds table, incidents panel, or API tools (toggled with key v)
            mode = self.main_view_mode
            self.query_one("#alerts-view").display = mode == "alerts"
            self.query_one("#incidents-view").display = mode == "incidents"
            self.query_one("#api-view").display = mode == "api_tools"
            self.query_one("#map-panel").display = mode == "map"
            if mode == "alerts":
                self.sync_feed_view()
            elif mode == "incidents":
                self.sync_incident_view()
            elif mode == "map":
                self.sync_map_view()
            else:
                self.sync_api_view()
            
            # Update dashboard panel
            try:
                dashboard_widget = self.query_one("#dashboard", Static)
                
                # Always show dashboard
                if self.dashboard_panel_index == 0:
                    # Main metrics dashboard
                    dashboard_content = self.make_dashboard()
                elif self.dashboard_panel_index == 1:
                    # War room panel
                    dashboard_content = self.make_war_room_panel()
                elif self.dashboard_panel_index == 2:
                    dashboard_content = self.make_feed_status_panel()
                else:
                    dashboard_content = self.make_dashboard()
                
                dashboard_widget.update(dashboard_content)
                page, total = self.dashboard_pages()
                extra = ("New briefing", self.action_ai_refresh) if self.dashboard_panel_index == 1 else None
                self.query_one("#dashboard-pager", PagerBar).show(page, total, extra)
                dashboard_widget.refresh()
            except Exception as e:
                logging.error(f"Error updating dashboard: {e}")
                import traceback
                logging.error(traceback.format_exc())
            
        except Exception as e:
            logging.error(f"Error updating display: {e}")
            import traceback
            logging.error(traceback.format_exc())
    
    def wire_tick(self):
        """Keep the Live Wire current. It only redraws when what it shows has changed."""
        clock = time.monotonic()
        self.wire.tick(clock, lambda: wire_items(alert_queue, self.watchlist, self.duplicate_groups().leader_of))
        if self.wire.expire_fresh(clock):
            self.mark_dirty()
        try:
            self.query_one(LiveWirePanel).redraw(clock)
        except NoMatches:
            pass  # A card is open
    
    def failed_feed_count(self):
        return len(failed_feeds)
    
    def sound_label(self):
        return sound.label(self.sound)
    
    def action_toggle_clocks(self):
        """Show or hide the world clock line"""
        self.show_clocks = not self.show_clocks
        self.query_one(WorldClock).display = self.show_clocks
        self.save_settings()
        self.notify(f"World clock: {'on' if self.show_clocks else 'off'}", timeout=2)

    def action_cycle_sound(self):
        """Off, or one of the alert sounds. Each one plays when chosen, so you can hear it."""
        self.sound = sound.next_tone(self.sound)
        self.save_settings()
        self.notify(f"Alert sound: {sound.label(self.sound)}", timeout=2)
        self.play_sound(self.sound)
    
    def action_jump_to_wire(self):
        """Show what's on the Live Wire in the feed"""
        shown = self.wire.shown
        if not shown:
            return
        if shown.item.search:  # A campaign: every claim by that group
            self.finish_typing()
            self.main_view_mode = "alerts"
            self.panel_focus = "main"
            self.query_one("#search-box", SearchBox).value = shown.item.search
            self.search_query = shown.item.search
            self.feed_at_top = True
            self.update_display()
            return
        self.jump_to_alert(shown.item.alert)
    
    def jump_to_alert(self, alert):
        """Select an alert in the feed, widening the Data Age or clearing filters only as needed"""
        self.finish_typing()
        self.main_view_mode = "alerts"
        self.panel_focus = "main"
        key = alert_key(alert)
        
        def row_of():
            return next((i for i, a in enumerate(self.filtered_alerts()) if alert_key(a) == key), None)
        
        alert_hours = (datetime.now(timezone.utc) - alert["ts"]).total_seconds() / 3600
        if alert_hours >= self.recency_hours:
            for index, hours in enumerate((24, 48, 168)):
                if alert_hours < hours:
                    self.data_age_index, self.recency_hours = index, hours
                    break
        if row_of() is None:
            self.search_query = ""
            self.query_one("#search-box", SearchBox).value = ""
            self.watch_only = False
            self.kind_index = 0
        if row_of() is None:
            self.filter_type_index = 0
            self.filter_mode = "all"
        row = row_of()
        self.update_display()
        if row is None:
            self.notify("That alert is older than the Data Age window", timeout=4)
            return
        self.query_one("#feed-table", ViewTable).move_cursor(row=row, animate=False, scroll=True)
    
    def announce_arrivals(self, arrivals):
        """One sound per check at most, and only for what's worth interrupting someone for"""
        if self.sound != sound.OFF and any((a.get("evidence") and a["evidence"].urgent) or self.watchlist.hits(a) for a in arrivals):
            self.play_sound(self.sound)
    
    def is_alert(self, item):
        """Something happening that you may need to act on, rather than general reading"""
        return evidence.is_alert(item, self.watchlist.hits(item))
    
    METRICS_WIDTH = 19  # Dashboard label plus its count
    AUTO_FOCUS = ""  # Keys go through on_key; only the search box ever takes focus
    NARROW_FEED = 84  # Table width below which dates shorten
    FEED_TITLE_COLUMN = 3
    PREVIEW_LINES = 8  # Lines reserved under the alert table for the selected-alert preview
    
    def filtered_alerts(self):
        """Alerts in the current time window, feed source and alert-type filter.
        A search looks through everything: older items, indicators and the saved history."""
        searching = bool(self.search_query)
        if searching:
            alerts = [a for a in alert_queue if matches_search(a, self.search_query)]
            archived = self.history_matches({alert_key(a) for a in alert_queue})
            if archived:
                alerts = sorted(alerts + archived, key=lambda a: a["ts"], reverse=True)
        else:
            cutoff_time = datetime.now(timezone.utc) - timedelta(hours=self.recency_hours)
            alerts = [a for a in alert_queue if a["ts"] >= cutoff_time]
        kind = self.active_kind
        if kind != "all":
            alerts = [a for a in alerts if a.get("kind") == kind]
        elif not searching:
            alerts = [a for a in alerts if a.get("kind") != "indicators"]
        if self.watch_only:
            alerts = [a for a in alerts if self.watchlist.hits(a)]
        # Search and an explicit content type look past the default Alerts filter, or they'd seem broken
        if self.filter_mode == "alerts" and not searching and kind == "all":
            alerts = [a for a in alerts if self.is_alert(a)]
        elif self.filter_mode == "posts":
            alerts = [a for a in alerts if not self.is_alert(a)]
        if self.group_dupes:
            # A report stays visible if its group's lead report was filtered out
            leader_of = self.duplicate_groups().leader_of
            shown = {alert_key(a) for a in alerts}
            alerts = [a for a in alerts if leader_of.get(alert_key(a)) not in shown]
        return alerts
    
    def duplicate_groups(self):
        """Duplicate stories in the loaded alerts, regrouped only when they change"""
        key = (id(alert_queue), len(alert_queue))
        if key != self.groups_key:
            self.groups = group_duplicates(alert_queue)
            self.groups_key = key
        return self.groups
    
    def history_matches(self, loaded_keys):
        """Saved alerts matching the search that aren't loaded any more"""
        if self.history_cache[0] != self.search_query:
            self.history_cache = (self.search_query, HISTORY.search(self.search_query))
        return [a for a in self.history_cache[1] if alert_key(a) not in loaded_keys]
    
    def selected_incident(self):
        try:
            row = self.query_one("#incident-table", ViewTable).cursor_row
        except NoMatches:
            return None
        return self.incident_list[row] if 0 <= row < len(self.incident_list) else None
    
    def selected_alert(self):
        try:
            row = self.query_one("#feed-table", ViewTable).cursor_row
        except NoMatches:
            return None
        return self.feed_rows[row] if 0 <= row < len(self.feed_rows) else None
    
    def cve_scores(self, cve, scores_only=False):
        """'CVE-x KEV CVSS 9.8 EPSS 12.3%' with each score colored by how bad it is"""
        p = self.palette
        text = Text() if scores_only else Text(cve, style=f"bold {p.text}")
        if cve in KEV_CATALOG and not scores_only:
            text.append(" ")
            text.append(" KEV ", style=f"bold {p.bg} on {p.bad}")
        cvss = self.nvd.get(cve)
        if cvss and cvss.get("score") is not None:
            score = cvss["score"]
            text.append(f"  CVSS {score:.1f}", style=f"bold {p.bad if score >= 9 else p.warn if score >= 7 else p.text}")
        elif cvss:
            text.append("  CVSS not yet scored", style=p.muted)
        elif cve in self.nvd.pending:
            text.append("  CVSS …", style=p.muted)
        if cve in cve_intel.EPSS:
            prob = cve_intel.EPSS[cve][0] * 100
            text.append(f"  EPSS {prob:.1f}%" if prob < 10 else f"  EPSS {prob:.0f}%",
                        style=f"bold {p.bad if prob >= 10 else p.warn if prob >= 1 else p.muted}")
        return text
    
    async def _fetch_cvss(self, cves):
        for cve in cves:
            if await self.nvd.fetch(cve):
                self.mark_dirty()
        STATE.save()
    
    @staticmethod
    def alert_cves(alert):
        """CVE IDs named in an alert, in order of appearance"""
        return list(dict.fromkeys(m.upper() for m in CVE_RE.findall(f"{alert['title']} {alert.get('summary', '')}")))
    
    def alerts_mentioning(self, cve):
        """Every loaded alert that names this CVE, for the CVE card"""
        return [a for a in alert_queue if cve in self.alert_cves(a)]
    
    async def fetch_cve_detail(self, cve):
        """Everything the CVE card shows that isn't loaded yet"""
        await asyncio.gather(self.nvd.fetch(cve, detail=True), cve_intel.fetch_epss([cve]))
        STATE.save()
        self.mark_dirty()
    
    def action_toggle_effects(self):
        """The map pulse and the arrival flash, both at once"""
        self.effects_on = not self.effects_on
        self.save_settings()
        self.notify(f"Effects {'on' if self.effects_on else 'off'}", timeout=2)
        self.update_display()

    def play_sound(self, name):
        """On a local speaker, or sent to the page when served in a browser"""
        if name == sound.OFF or name not in sound.TONES:
            return
        if sound.in_browser():
            write = getattr(getattr(self, "_driver", None), "write_meta", None)
            if write:
                write({"type": web_sound.MESSAGE, "name": "bell" if name == sound.TERMINAL_BELL else name})
            return
        sound.play(name, self.bell)

    def set_hum(self, on):
        """Start or stop the ambient hum, in the browser or on a local speaker. False if it could not start."""
        if sound.in_browser():
            write = getattr(getattr(self, "_driver", None), "write_meta", None)
            if write:
                write({"type": web_sound.MESSAGE, "hum": bool(on)})
            return bool(write)
        if on:
            return sound.HUM.start()
        sound.HUM.stop()
        return True

    def action_toggle_hum(self):
        """A very quiet ambient hum (separate from the alert sound)"""
        want = not self.hum_on
        if want and not self.set_hum(True):
            self.notify("No audio player found for the hum (pw-play, paplay or aplay)", timeout=4)
            return
        if not want:
            self.set_hum(False)
        self.hum_on = want
        self.save_settings()
        self.notify(f"Ambient hum {'on' if want else 'off'}", timeout=2)

    def action_toggle_kiosk(self):
        """Kiosk mode: the main view rotates between the map, alerts and incidents when nobody is using the app"""
        self.kiosk_on = not self.kiosk_on
        self.kiosk_last_move = time.monotonic()
        self.save_settings()
        self.notify("Kiosk mode on: the view rotates every 30 seconds. Any key pauses it for 2 minutes" if self.kiosk_on
                    else "Kiosk mode off", timeout=4)
        self.update_display()

    def action_show_map(self):
        """Full-window threat map"""
        if not self.is_loading and not isinstance(self.screen, MapCard):
            self.push_screen(MapCard())

    def action_open_cve_card(self):
        """Open the CVE card for the highlighted alert or incident"""
        cves = []
        if self.main_view_mode == "alerts":
            alert = self.selected_alert()
            if not alert:
                self.notify("Select an alert with ↑/↓ first", timeout=2)
                return
            cves = self.alert_cves(alert)
        elif self.main_view_mode == "incidents" and self.selected_incident():
            inc = self.selected_incident()
            cves = [inc.value] if inc.kind == "cve" else list(dict.fromkeys(c for a in inc.alerts for c in self.alert_cves(a)))
        elif self.main_view_mode == "incidents":
            self.notify("Select an incident with ↑/↓ first", timeout=2)
            return
        else:
            return
        if cves:
            self.push_screen(CveCard(cves))
        else:
            self.notify("No CVE named in this item", timeout=2)
    
    
    def hint_bar(self, hints):
        """'key description' pairs with keys in the accent color"""
        p = self.palette
        text = Text()
        if self.kiosk_on:
            hints = [*hints, ("k", "kiosk on")]
        for i, (key, desc) in enumerate(hints):
            if i:
                text.append("   ")
            text.append(key, style=f"bold {p.accent}")
            text.append(f" {desc}", style=p.muted)
        return text
    
    def feed_columns(self, indicators_view, width):
        """(label, width) per feed column; the title or indicator takes what's left"""
        date_width = 7 if self.palette.military_time else 6 if width < self.NARROW_FEED else 10
        cols = [("SEEN", date_width), ("AGE", 3)]
        if indicators_view:
            cols += [("TYPE", 5), ("INDICATOR", 0), ("THREAT", 18), ("SOURCE", 18)]
        else:
            cols += [("", 12), ("", 0)]
        used = sum(w for _, w in cols) + 2 * len(cols)  # Each cell has one space of padding either side
        return [(label, w or max(10, width - used - 1)) for label, w in cols]  # -1 for the scrollbar
    
    def feed_title_cell(self, a, selected):
        """The cell that changes with selection: NEW badge and title, or the indicator"""
        p = self.palette
        urgent = a["severity"] in ("critical", "zeroday")
        title_style = f"bold {p.focus}" if selected and p.monochrome else f"bold {p.text}" if urgent or selected else p.text
        watched = bool(self.watchlist.hits(a))
        title = Text(no_wrap=True, overflow="ellipsis")
        if self.active_kind == "indicators":
            title.append(("★ " if watched else "") + (a.get("ioc") or a["title"]), style=title_style)
            return title
        if watched:
            title.append("★ ", style=f"bold {p.warn}")
        others = self.duplicate_groups().others.get(alert_key(a), []) if self.group_dupes else []
        if others:
            title.append(f"+{len(others)} ", style=f"bold {p.accent}")
        if self.wire.is_fresh(a):
            title.append(" LIVE ", style=f"bold {p.bg} on {p.focus}")
            title.append(" ")
        elif STATE.is_new(a):
            title.append(" NEW ", style=f"bold {p.bg} on {p.accent}")
            title.append(" ")
        title.append(self.typed_title(a), style=title_style)
        if selected and p.monochrome:
            title.append(" █", style=f"blink {p.focus}")  # teletype cursor
        return title
    
    def feed_row(self, a, narrow):
        p = self.palette
        sev = a["severity"]
        short_date = f"{a['ts']:%d %b}" if narrow and not p.military_time else p.stamp(a["ts"])
        cells = [Text(short_date, style=p.muted),
                 Text("—" if a.get("undated") else age(a["ts"]), style=p.muted, justify="right")]
        if self.active_kind == "indicators":
            return cells + [Text((a.get("ioc_type") or "").upper(), style=f"bold {p.accent}"),
                            self.feed_title_cell(a, False),
                            Text(a.get("threat") or "", style=p.text, no_wrap=True, overflow="ellipsis"),
                            Text(a["source"], style=p.muted, no_wrap=True, overflow="ellipsis")]
        urgent = sev in ("critical", "zeroday")
        # Cold War keeps its message precedence words; other themes say how strong the evidence is
        ev = a.get("evidence")
        label = ev.tier if ev and not p.monochrome else p.severity_name(sev)
        return cells + [Text(f" {label} " if urgent else label, style=p.badge(sev)), self.feed_title_cell(a, False)]
    
    def empty_feed_reason(self):
        if self.watch_only and not self.watchlist.terms:
            return "Your watchlist is empty: press W to add a vendor, product or keyword"
        if self.watch_only:
            return "No watchlist hits under these filters: press w to show everything"
        if self.search_query:
            return "Nothing matches this search under the f and 4 filters"
        if self.filter_mode == "alerts" and self.active_kind == "all":
            return "Nothing with evidence behind it in this window: press f to see everything, or d for a longer window"
        return "Nothing matches the current filters"
    
    def sync_feed_view(self):
        """Bring the alert table, search box, preview and frame up to date"""
        p = self.palette
        table = self.query_one("#feed-table", ViewTable)
        view = self.query_one("#alerts-view")
        self.query_one("#search-row").display = bool(self.prompt or self.search_query)
        
        indicators_view = self.active_kind == "indicators"
        width = table.size.width or max(40, self.size.width * 3 // 4 - 6)
        narrow = width < self.NARROW_FEED
        filtered_alerts = self.filtered_alerts()
        previous = self.selected_alert()
        rows = [self.feed_row(a, narrow) for a in filtered_alerts]
        if not rows:
            reason = [Text("NO ALERTS", style=p.warn), Text(self.empty_feed_reason(), style=p.muted)]
            rows = [[Text(""), Text(""), *reason, *[Text("")] * (2 if indicators_view else 0)]]
        
        # Rebuilding every row is wasted work if nothing visible changed, and would lose the scroll position
        signature = (p.key, indicators_view, width, tuple(tuple(c.plain for c in row) for row in rows))
        old_row, old_scroll = table.cursor_row, table.scroll_y
        self.feed_rows = filtered_alerts
        rebuilt = signature != self.feed_signature
        if rebuilt:
            self.feed_signature = signature
            self.marked_row = None
            table.clear(columns=True)
            table.show_header = indicators_view
            for label, column_width in self.feed_columns(indicators_view, width):
                table.add_column(label, width=column_width)
            table.add_rows(rows)
        table.show_cursor = bool(filtered_alerts)
        
        # Stay on the same alert, at the same height on screen, when rows arrive above it
        keys = {alert_key(a): i for i, a in enumerate(filtered_alerts)}
        row = 0 if self.feed_at_top else keys.get(alert_key(previous), old_row) if previous else old_row
        row = max(0, min(row, len(rows) - 1))
        at_top, self.feed_at_top = self.feed_at_top, False
        scroll = 0 if at_top else max(0, row - (old_row - old_scroll))
        table.move_cursor(row=row, animate=False, scroll=False)
        if rebuilt or at_top:
            # Never touch the scroll otherwise: an arrow key's own scrolling may still be under way
            visible = max(1, table.size.height - (1 if indicators_view else 0))
            scroll = max(scroll, row - visible + 1)
            table.call_after_refresh(table.scroll_to, y=min(scroll, row), animate=False)
        self.mark_selected_row(row)
        self.update_preview()
        
        rem = int((self.next_refresh - datetime.now(timezone.utc)).total_seconds())
        uptime = datetime.now(timezone.utc) - start_time
        status = Text(f" refresh in {max(rem, 0) // 60 + 1}m · up {int(uptime.total_seconds() // 3600)}h"
                      f"{int(uptime.total_seconds() % 3600 // 60):02d}m   ", style=p.muted)
        if self.prompt:
            hints = [("Enter", "keep"), ("Esc", "clear")]
        else:
            hints = [("↑↓", "select"), ("Enter", "open"), ("i", "CVE"), ("a", "explain"), ("←→", "page")]
            if self.search_query:
                hints = [("/", "edit"), ("Esc", "clear")] + hints
        status.append_text(self.hint_bar(hints))
        status.append(" ")
        
        kind_label = "" if self.active_kind == "all" else f" · {CONTENT_KINDS[self.kind_index][1].upper()}"
        watch_label = " · WATCHLIST" if self.watch_only else ""
        title_text, border = self.frame(f"GLOBAL THREAT FEED{kind_label}{watch_label} ({len(filtered_alerts)})", self.panel_focus == "main")
        view.border_title = title_text
        view.border_subtitle = status
        view.styles.border = ("round", border)
    
    def mark_selected_row(self, row):
        """Selected rows get a brighter title, and the teletype cursor in Cold War"""
        if row == self.marked_row or not self.feed_rows:
            return
        table = self.query_one("#feed-table", ViewTable)
        if self.marked_row is not None and self.marked_row < len(self.feed_rows):
            table.update_cell_at(Coordinate(self.marked_row, self.FEED_TITLE_COLUMN), self.feed_title_cell(self.feed_rows[self.marked_row], False))
        if row < len(self.feed_rows):
            table.update_cell_at(Coordinate(row, self.FEED_TITLE_COLUMN), self.feed_title_cell(self.feed_rows[row], True))
        self.marked_row = row
    
    def update_preview(self):
        self.query_one("#alert-preview", Static).update(
            Panel(self.make_alert_preview(self.selected_alert()), border_style=self.palette.border, box=box.ROUNDED,
                  padding=(0, 1), height=self.PREVIEW_LINES))
    
    def on_data_table_row_highlighted(self, event):
        if event.data_table.id == "feed-table":
            self.mark_selected_row(event.cursor_row)
            self.update_preview()
        elif event.data_table.id == "incident-table":
            self.mark_selected_incident(event.cursor_row)
    
    def on_data_table_row_selected(self, event):
        """Clicking the selected row opens it"""
        if event.data_table.id in ("feed-table", "incident-table"):
            self.action_open_selected_link()
    
    def show_feed_from_top(self):
        """Back to the first page of the alerts view after the filters change"""
        self.main_view_mode = "alerts"
        self.feed_at_top = True
    
    def action_start_search(self):
        """Search everything loaded, filtering as you type. In API Tools, / goes to its box instead."""
        if self.main_view_mode == "api_tools" and enrichment_engine.providers:
            self.focus_indicator_box()
            self.update_display()
            return
        self.show_feed_from_top()
        self.query_one("#search-row").display = True
        box = self.query_one("#search-box", SearchBox)
        box.value = self.search_query
        box.action_end()
        box.focus()
        self.prompt = "search"
        self.update_display()
    
    def action_edit_watchlist(self):
        """See every watchlist term, add or remove them"""
        self.show_feed_from_top()
        self.push_screen(WatchCard(), lambda _: self.update_display())
    
    def action_manage_keys(self):
        """Enter, test and secure API keys"""
        self.show_feed_from_top()
        self.push_screen(KeyCard(), lambda _: self.update_display())
    
    @property
    def key_config(self):
        return CONFIG
    
    def save_ai_profiles(self):
        """Remember the key card's AI choices, and put them to use"""
        STATE.settings["ai"] = {"active": CONFIG.active_ai_profile, "profiles": CONFIG.ai_profiles}
        STATE.save()
        self.ai_problem = ai.configuration_problem(self.ai_settings)
        self.ai_briefing_error = None
        self.mark_dirty()
    
    def set_ai_profile(self, index, provider, model, base_url):
        CONFIG.set_ai_profile(index, provider, model, base_url)
        self.save_ai_profiles()
    
    def activate_ai_profile(self, index):
        CONFIG.activate_ai_profile(index)
        self.save_ai_profiles()
    
    def dashboard_pages(self):
        """(current page, page count) of the right panel"""
        if self.dashboard_panel_index == 1:
            return self.threat_summary_page, max(1, len(self.threat_summary_pages))
        if self.dashboard_panel_index == 2:
            return self.dashboard_page_offset, self.feed_status_pages
        return 0, 1
    
    def page_dashboard(self, delta):
        """Turn the right panel's page, from a key, the pager or the mouse wheel"""
        page, total = self.dashboard_pages()
        page = max(0, min(page + delta, total - 1))
        if self.dashboard_panel_index == 1:
            self.threat_summary_page = page
        elif self.dashboard_panel_index == 2:
            self.dashboard_page_offset = page
        self.update_display()
    
    def on_button_pressed(self, event):
        """Mouse access to what the keys do in the main views"""
        actions = {"act-open": self.action_open_selected_link, "act-open-incident": self.action_open_selected_link,
                   "act-cve": self.action_open_cve_card, "act-cve-incident": self.action_open_cve_card,
                   "act-explain": self.action_explain_alert,
                   "act-lookup": lambda: self.run_api_lookup(self.query_one("#indicator-box", IndicatorBox).value.strip()),
                   "act-keys": self.action_manage_keys, "act-clear": self.clear_api_results}
        action = actions.get(event.button.id)
        if action:
            self.finish_typing()
            action()
    
    def key_changed(self, slot_id):
        """Put a key changed in the card to use right away, without a restart"""
        slot = SLOTS_BY_ID[slot_id]
        if slot.section == "ai":
            self.ai_problem = ai.configuration_problem(self.ai_settings)
        elif slot.feed:
            force_event.set()  # A feed that was waiting for its key can load now
        elif slot_id == "nvd_api_key":
            self.nvd.api_key = CONFIG.key_value(slot_id)
        elif slot_id in ENRICHMENT_KEYS:
            enrichment_engine.providers.pop(ENRICHMENT_KEYS[slot_id][0], None)
            initialize_enrichment(CONFIG.enrichment)
            if slot_id == "abuse_ch_api_key":  # This key also switches two feeds on or off
                force_event.set()
    
    def warn_about_key_storage(self):
        """Keys outside the keychain deserve a visible mention at launch"""
        store = CONFIG.keys
        movable = store.movable()
        if movable:
            self.notify(f"{len(movable)} API keys need securing. Press K, then m", severity="warning", timeout=10)
        elif FILE in CONFIG.key_sources.values():
            self.notify(f"No keychain ({store.problem}). Keys are in {SECRETS_FILE}: your user only, not encrypted",
                        severity="warning", timeout=10)
        if store.old_copy_exists:
            self.notify(f"{OLD_COPY} may hold plaintext keys. Press K for details, then delete it", severity="warning", timeout=10)
    
    def save_watchlist(self):
        STATE.watchlist = list(self.watchlist.added)
        STATE.save()
    
    def watch_hit_counts(self):
        """Term -> how many loaded alerts it matches, for the watchlist card"""
        counts = Counter()
        for a in alert_queue:
            if a.get("kind") != "indicators":
                counts.update(self.watchlist.hits(a))
        return counts
    
    def action_toggle_grouping(self):
        """Collapse the same story from several feeds into one row, or list every report"""
        self.group_dupes = not self.group_dupes
        self.feed_at_top = True
        self.save_settings()
        self.notify("Duplicate reports " + ("grouped" if self.group_dupes else "shown separately"), timeout=2)
        self.update_display()
    
    def action_toggle_watch_only(self):
        """Show only watchlist hits, or everything; an empty watchlist asks for a term first"""
        if not self.watchlist.terms:
            self.watch_only = True
            self.action_edit_watchlist()
            return
        self.watch_only = not self.watch_only
        self.show_feed_from_top()
        self.save_settings()
        self.update_display()
    
    def finish_typing(self):
        self.prompt = None
        self.set_focus(None)
    
    def clear_search(self):
        self.search_query = ""
        self.query_one("#search-box", SearchBox).value = ""
        self.finish_typing()
        self.show_feed_from_top()
        self.update_display()
    
    def on_input_changed(self, event):
        """A search filters the feed as it changes"""
        if event.input.id == "indicator-box":
            self.sync_api_view()  # The type label and provider list follow what is typed
            return
        if event.input.id == "search-box" and event.value.strip() != self.search_query:
            self.search_query = event.value.strip()
            self.feed_at_top = True
            self.update_display()
    
    def on_input_submitted(self, event):
        if event.input.id == "search-box":
            self.finish_typing()
            self.feed_at_top = True  # Enter again opens the top result
            self.update_display()
        elif event.input.id == "indicator-box":
            if not event.value.strip() and self.idle_api():
                self.run_selected_ioc()  # Enter on an empty box tries the highlighted suggestion
            else:
                self.run_api_lookup(event.value.strip())
    
    def check_action(self, action, parameters):
        """Single-key commands are off while typing, so 'q' in a search doesn't quit"""
        return not self.prompt
    
    def frame(self, title, focused):
        """Title and border style for a panel; only the focused panel is highlighted"""
        p = self.palette
        title = p.title(title)
        if focused:
            focus = self.mood(p.focus)  # Tinted toward amber and red as the threat level rises
            return Text(f" {title} ", style=f"bold {p.bg} on {focus}"), focus
        return Text(f" {title} ", style=f"bold {p.muted}"), p.border
    
    def bar(self, pct, color, width=HEAT_BAR_WIDTH):
        """Horizontal meter: filled part in color, remainder muted"""
        filled = int(round(max(0, min(100, pct)) / 100 * width))
        meter = Text("█" * filled, style=color)
        meter.append("░" * (width - filled), style=self.palette.surface if not self.palette.monochrome else self.palette.muted)
        return meter
    
    
    
    
    
    
    
    
    def action_refresh(self):
        """Force refresh feeds"""
        force_event.set()
    
    def action_show_help(self):
        """Show help screen"""
        self.push_screen(HelpScreen(self.palette))
    
    
    
    
    
    def action_cycle_data_age(self):
        """Cycle data age window: 24h → 48h → 7d → 24h"""
        time_windows = [24, 48, 168]  # 24h, 48h, 7d (168 hours)
        self.data_age_index = (self.data_age_index + 1) % len(time_windows)
        self.recency_hours = time_windows[self.data_age_index]
        self.feed_at_top = True
        self.save_settings()
        self.call_later(self.update_display)
    
    def action_cycle_filter_type(self):
        """Cycle alert type filter: All → Alerts Only → Posts Only → All"""
        filter_modes = ["all", "alerts", "posts"]
        self.filter_type_index = (self.filter_type_index + 1) % len(filter_modes)
        self.filter_mode = filter_modes[self.filter_type_index]
        self.feed_at_top = True
        self.save_settings()
        self.call_later(self.update_display)
    
    def action_toggle_cold_war(self):
        """Toggle cold war mode"""
        self.cold_war_mode = not self.cold_war_mode
        self.save_settings()
        self.call_later(self.update_display)
    
    @property
    def active_kind(self) -> str:
        return CONTENT_KINDS[self.kind_index][0]
    
    def action_cycle_feeds(self):
        """Cycle content types: All → Advisories → News & Research → Ransomware → Indicators → Outages"""
        self.kind_index = (self.kind_index + 1) % len(CONTENT_KINDS)
        self.feed_at_top = True
        if self.main_view_mode != "alerts":
            self.main_view_mode = "alerts"
        self.save_settings()
        self.notify(f"Showing: {CONTENT_KINDS[self.kind_index][1]}", timeout=2)
        self.call_later(self.update_display)
    def action_re_enable_feeds(self):
        """Re-enable all disabled feeds and reset failure counts"""
        global disabled_feeds
        
        if not disabled_feeds:
            return
        
        num_re_enabled = len(disabled_feeds)
        disabled_feeds.clear()
        self.feed_failure_counts.clear()
        self.dashboard_page_offset = 0
        self.call_later(self.update_display)
    
    def action_cycle_feed_view(self):
        """Cycle between alerts, incidents, and API tools views in main feed panel"""
        # Cycle: alerts -> incidents -> api_tools -> alerts
        views = ["alerts", "incidents", "api_tools", "map"]
        current_idx = views.index(self.main_view_mode) if self.main_view_mode in views else 0
        self.main_view_mode = views[(current_idx + 1) % len(views)]
        # Don't reset offsets, preserve position in each view
        self.call_later(self.update_display)
    
    BRIEFING_SYSTEM = (
        "You are a senior threat intelligence analyst writing a short briefing for a security team, "
        "based only on the alerts provided. Write plain text with no markdown. Use exactly these section "
        "headings, each in capitals followed by a colon on its own line: BOTTOM LINE, PRIORITY ACTIONS, "
        "ACTIVE THREATS, NOTABLE VULNERABILITIES, WATCH LIST. Under BOTTOM LINE write two or three sentences. "
        "Under the other headings write short lines starting with '- '. Name specific CVE IDs, products, "
        "threat actors and ransomware groups from the alerts, and say which items are confirmed exploited. "
        "Do not invent facts that are not in the alerts. Keep the whole briefing under 400 words."
    )
    EXPLAIN_SYSTEM = (
        "You explain a single security alert to a busy security analyst. Using only the alert text, "
        "write two or three plain sentences with no markdown: what happened, who or what is affected, "
        "and the most useful next step. If the alert text is too thin to say, say so briefly."
    )
    
    
    
    
    def action_explain_alert(self):
        alert = self.selected_alert() if self.main_view_mode == "alerts" else None
        if not alert:
            self.notify("Select an alert with ↑/↓ first", timeout=2)
        elif self.ai_problem:
            self.notify(self.ai_problem, timeout=4)
        else:
            asyncio.create_task(self.explain_alert(alert))
    
    def action_ai_refresh(self):
        """Regenerate the AI briefing and show the War Room panel (g key)"""
        self.dashboard_panel_index = 1
        asyncio.create_task(self.generate_ai_briefing())
        asyncio.create_task(self._load_threat_summary_async())
        self.mark_dirty()
    
    
    
    
    def action_toggle_view(self):
        """Toggle view in the focused panel - alerts/incidents/api_tools on left, dashboard views on right"""
        if self.panel_focus == "main":
            # Cycle alerts/incidents/api_tools in left panel
            views = ["alerts", "incidents", "api_tools", "map"]
            current_idx = views.index(self.main_view_mode) if self.main_view_mode in views else 0
            self.main_view_mode = views[(current_idx + 1) % len(views)]
            self.save_settings()
            self.finish_typing()
            self.update_display()
            if self.main_view_mode == "api_tools":
                self.focus_indicator_box()
        else:
            # Cycle through all dashboard views in right panel (0-5: metrics, war room, AI correlation, AI risk ranking, enrichment, failed feeds)
            self.dashboard_panel_index = (self.dashboard_panel_index + 1) % 3
            self.dashboard_page_offset = 0
#            logging.info(f"Dashboard view cycled to: {self.dashboard_panel_index}")
            self.update_display()
    

    def action_toggle_panel_focus(self):
        """Switch focus between main panel and dashboard panel"""
        self.panel_focus = "dashboard" if self.panel_focus == "main" else "main"
#        logging.info(f"Panel focus switched to: {self.panel_focus}")
        self.call_later(self.update_display)
    
    

    def action_open_selected_link(self):
        """Open the highlighted alert, or the latest report for the highlighted incident"""
        if self.main_view_mode == "alerts":
            alert = self.selected_alert()
            if alert and alert.get("kind") == "indicators":
                self.lookup_indicator(alert)
                return
            if not alert:
                self.notify("Select an alert with ↑/↓ first", timeout=2)
            elif alert.get("url"):
                open_link(self, alert["url"])
                STATE.mark_read(alert)
                for other in self.duplicate_groups().others.get(alert_key(alert), []):
                    STATE.mark_read(other)
                STATE.save()
                self.notify("Opening alert in browser...")
            else:
                self.notify("No link for this alert (phishing URLs are never opened)", timeout=3)
            self.mark_dirty()
        elif self.main_view_mode == "incidents":
            inc = self.selected_incident()
            if inc:
                if inc.url:
                    open_link(self, inc.url)
                    self.notify("Opening latest report in browser...")
            else:
                self.notify("Select an incident with ↑/↓ first", timeout=2)

    def on_key(self, event: events.Key) -> None:
        """Handle key events - Tab, view toggle, and arrow key pagination"""
        if isinstance(self.screen, ModalScreen):
            return  # The CVE card handles its own keys
        
        if self.prompt == "search":
            if event.key == "escape":
                event.prevent_default()
                self.clear_search()
            elif event.key in ("up", "down"):
                event.prevent_default()  # Arrow keys move from typing into the results
                self.finish_typing()
                self.update_display()
            elif event.key == "tab":
                event.prevent_default()
            return  # Everything else belongs to the search box
        
        if self.prompt == "indicator":
            results = self.query_one("#api-results")
            if event.key == "escape":
                event.prevent_default()
                if self.api_tools_last_query:
                    self.clear_api_results()  # With an answer showing, Esc goes back to the suggestions
                else:
                    self.query_one("#indicator-box", IndicatorBox).value = ""
                    self.finish_typing()
                    self.update_display()
            elif event.key == "tab":
                event.prevent_default()
                self.finish_typing()
                self.action_toggle_panel_focus()
            elif event.key in ("up", "down", "pageup", "pagedown") and self.idle_api():
                event.prevent_default()
                table = self.query_one("#ioc-table", IocTable)  # Arrows pick a suggestion while nothing is shown
                {"up": table.action_cursor_up, "down": table.action_cursor_down,
                 "pageup": table.action_page_up, "pagedown": table.action_page_down}[event.key]()
            elif event.key in ("up", "pageup"):
                event.prevent_default()
                results.scroll_up() if event.key == "up" else results.scroll_page_up()
            elif event.key in ("down", "pagedown"):
                event.prevent_default()
                results.scroll_down() if event.key == "down" else results.scroll_page_down()
            return  # Everything else belongs to the indicator box
        
        if event.key == "escape" and self.search_query and self.main_view_mode == "alerts":
            event.prevent_default()
            self.clear_search()
            return
        
        if event.key == "a" and self.main_view_mode == "alerts":
            event.prevent_default()
            self.action_explain_alert()
            return
        
        # Handle Enter key: open the highlighted alert/incident URL in alerts or incidents view
        if event.key == "enter" and self.main_view_mode in ["alerts", "incidents"]:
            event.prevent_default()
            self.action_open_selected_link()
            return
        
        if event.key == "escape" and self.main_view_mode == "api_tools" and self.api_tools_last_query:
            event.prevent_default()
            self.clear_api_results()
            return

        if event.key == "enter" and self.main_view_mode == "api_tools":
            event.prevent_default()
            if self.idle_api() and self.ioc_rows:
                self.run_selected_ioc()
            else:
                self.focus_indicator_box()
                self.update_display()
            return
        
        # Normal key handling
        if event.key == "tab":
            event.prevent_default()
            self.action_toggle_panel_focus()
        elif event.key in ("up", "down", "pageup", "pagedown"):
            event.prevent_default()
            table = self.active_table()
            if table:
                {"up": table.action_cursor_up, "down": table.action_cursor_down,
                 "pageup": table.action_page_up, "pagedown": table.action_page_down}[event.key]()
            else:
                results = self.query_one("#api-results")
                {"up": results.scroll_up, "down": results.scroll_down,
                 "pageup": results.scroll_page_up, "pagedown": results.scroll_page_down}[event.key]()
        elif event.key == "left":
            event.prevent_default()
            self.action_focused_prev_page()
        elif event.key == "right":
            event.prevent_default()
            self.action_focused_next_page()
    
    def active_table(self):
        """The row list in the current main view, if it has one"""
        tables = {"alerts": "#feed-table", "incidents": "#incident-table"}
        if self.main_view_mode == "api_tools" and self.idle_api():
            tables["api_tools"] = "#ioc-table"
        selector = tables.get(self.main_view_mode)
        return self.query_one(selector, ViewTable) if selector else None
    
    def action_focused_next_page(self):
        """Next page in the focused panel (main or dashboard)"""
        if self.panel_focus == "main":
            table = self.active_table()
            if table:
                table.action_page_down()
            else:
                self.query_one("#api-results").scroll_page_down()
        else:  # dashboard focus
            self.page_dashboard(1)
        self.call_later(self.update_display)
    
    def action_focused_prev_page(self):
        """Previous page in the focused panel (main or dashboard)"""
        if self.panel_focus == "main":
            table = self.active_table()
            if table:
                table.action_page_up()
            else:
                self.query_one("#api-results").scroll_page_up()
        else:  # dashboard focus
            self.page_dashboard(-1)
        self.call_later(self.update_display)
    def action_panel_next_page(self):
        """Next page in main feed panel (alerts/incidents) - DEPRECATED, use action_focused_next_page"""
        self.action_focused_next_page()
    
    def action_panel_prev_page(self):
        """Previous page in main feed panel (alerts/incidents) - DEPRECATED, use action_focused_prev_page"""
        self.action_focused_prev_page()
    
    def action_dashboard_next_page(self):
        """Next page in dashboard panel - DEPRECATED, use action_focused_next_page"""
        self.dashboard_page_offset += 1
        self.call_later(self.update_display)
    
    def action_dashboard_prev_page(self):
        """Previous page in dashboard panel - DEPRECATED, use action_focused_prev_page"""
        self.dashboard_page_offset = max(0, self.dashboard_page_offset - 1)
        self.call_later(self.update_display)
    
    def set_theme_by_key(self, key):
        """Switch to a named theme (and out of Cold War mode, which has its own key)"""
        if key not in PALETTES:
            return
        self.theme_mode = key
        if self.cold_war_mode:
            self.cold_war_mode = False
        self.apply_theme()
        self.save_settings()
        self.call_later(self.update_display)

    def action_cycle_theme(self):
        """Cycle through the color themes (Cold War is separate, on 'c')"""
        keys = list(PALETTES)
        current_idx = keys.index(self.theme_mode) if self.theme_mode in keys else 0
        self.set_theme_by_key(keys[(current_idx + 1) % len(keys)])
        self.notify(f"Theme: {self.palette.name}", timeout=2)

    def action_theme_picker(self):
        """Pick a theme from a list, previewed live"""
        if not self.is_loading and not isinstance(self.screen, ThemeCard):
            self.push_screen(ThemeCard())
    
    def on_click(self, event) -> None:
        """Clicking a panel selects it, and right-clicking it also does what v does there"""
        if isinstance(self.screen, ModalScreen):
            return
        node = getattr(event, "widget", None)
        while node is not None and node.id not in ("dashboard-column", "feeds-container"):
            node = node.parent
        if node is None:
            return
        self.panel_focus = "dashboard" if node.id == "dashboard-column" else "main"
        if event.button == 3:
            self.finish_typing()
            self.action_toggle_view()
            return
        if self.prompt and node.id == "dashboard-column":
            self.finish_typing()
        self.mark_dirty()

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="CybrWire - terminal threat intelligence dashboard")
    parser.add_argument("--setup", action="store_true", help="choose data age and display mode again")
    parser.add_argument("--digest", nargs="?", const=24, type=int, metavar="HOURS",
                        help="print a plain-text summary of the last HOURS (default 24) and exit")
    parser.add_argument("--test-notify", action="store_true", help="send a test message to the configured notification targets and exit")
    parser.add_argument("--version", action="version", version=f"CybrWire {__version__}")
    args = parser.parse_args()
    
    if args.digest is not None:
        asyncio.run(run_digest(args.digest))
        return
    if args.test_notify:
        asyncio.run(run_test_notify())
        return
    
    saved = STATE.settings
    if "web_driver" in os.environ.get("TEXTUAL_DRIVER", ""):
        # Served in a browser: there is no terminal for the plain-text questions, so use the saved or default choices
        recency, cold_war = saved.get("recency_hours", 24), saved.get("cold_war", False)
    elif saved and not args.setup:
        recency = saved.get("recency_hours", 24)
        cold_war = saved.get("cold_war", False)
    else:
        recency, cold_war = startup_prompts()
    
    app = CybrWireApp(cold_war=cold_war, recency=recency)
    try:
        app.run()
    finally:
        app.save_settings()

async def run_digest(hours):
    """Fetch the feeds once and print a summary, leaving the app's NEW badges as they were"""
    if STATE.previous_launch:
        STATE.launch_time = STATE.previous_launch
    app = CybrWireApp()
    await app.fetch_feeds()
    print(build_digest(alert_queue, hours, app.watchlist, KEV_CATALOG, failed_feeds))

async def run_test_notify():
    settings = CONFIG.notifications
    if not notify.is_configured(settings):
        print("No notification targets set. Press K in the app to add one, or set CYBRWIRE_NTFY_URL.")
        return
    results = await notify.send(settings, "CybrWire test", "Notifications are working.")
    for name, error in results.items():
        print(f"{name}: {error or 'delivered'}")

def startup_prompts():
    """Title screen and first-run questions; returns (recency_hours, cold_war)"""
    console.clear()
    ascii_art = [
        ("╔════════════════════════════════════════════════════════════════════════════════════════════════════════╗", "#00ffff"),
        ("║                                                                                                        ║", "#0099ff"),
        ("║  ------------ ---      --- -----------  -----------  ---      --- --------  -----------  ------------  ║", "#6666ff"),
        ("║  ************  ***    ***  ***********  ***********  ***  **  *** ********  ***********  ************  ║", "#ff00ff"),
        ("║  ---            ---  ---   ----       - ----    ---  ---  --  ---   ----    ----    ---  ----          ║", "#00ffff"),
        ("║  ***             ******    ***********  *********    ***  **  ***   ****    *********    ************  ║", "#0099ff"),
        ("║  ---              ----     -----------  ---------    ---  --  ---   ----    ---------    ------------  ║", "#6666ff"),
        ("║  ***              ****     ****       * ****  ****   ************   ****    ****  ****   ****          ║", "#ff00ff"),
        ("║  ------------     ----     -----------  ----   ----   ----------  --------  ----   ----  ------------  ║", "#00ffff"),
        ("║  ************     ****     ***********  ****    ****   ********   ********  ****    **** ************  ║", "#0099ff"),
        ("║                                                                                                        ║", "#6666ff"),
        (boxed(EDITION), "#ff00ff"),
        ("╚════════════════════════════════════════════════════════════════════════════════════════════════════════╝", "#ff00ff"),
        ("                            By: GitHub/QIO1984 // The Hacker known as MADNOTE", "#00ffff"),
    ]
    
    for line, color in ascii_art:
        console.print(f"[bold {color}]{line}[/]")
    
    console.print()
    console.print("                                          [bold #ff00ff]#Is this the big one...?[/bold #ff00ff]")
    console.print()
    
    # Condensed info section
    console.print(" [bold cyan]Quick Start:[/]")
    console.print("   • Real-time threat intelligence dashboard with auto-refresh every 5 minutes")
    console.print("   • Use [bold]Tab[/] to switch panels, [bold]V[/] to switch views, [bold]↑↓←→[/] to navigate, and [bold]h[/] for full help")
    console.print()
    
    console.print(" [bold dim]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/]")
    
    # Data age selection
    console.print(" [bold cyan]STEP 1: Select Initial Data Age Window[/]")
    console.print("   [bold white]1[/] = Last 24 hours [dim](default)[/dim]")
    console.print("   [bold white]2[/] = Last 48 hours")
    console.print("   [bold white]3[/] = Last 7 days")
    console.print()
    console.print(" [bold cyan]Enter choice (1-3) or press Enter for default:[/] ", end="")
    
    recency = 24
    choice = input().strip()
    if choice == "2":
        recency = 48
    elif choice == "3":
        recency = 168
    
    console.print()
    console.print(" [bold dim]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/]")
    
    # Display mode selection
    console.print()
    console.print(" [bold cyan]STEP 2: Select Initial Display Mode[/]")
    console.print("   [bold white]1[/] = Normal Mode [dim](colorful, default)[/dim]")
    console.print("   [bold white]2[/] = Cold War Mode [dim](authentic green terminal)[/dim]")
    console.print()
    console.print(" [bold cyan]Enter choice (1-2) or press Enter for default:[/] ", end="")
    
    cold_war = False
    choice = input().strip()
    if choice == "2":
        cold_war = True
    
    console.print()
    console.print(" [bold dim]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/]")
    console.print()
    console.print(" [dim]Loading CybrWire... (choices are saved; run with --setup to change them)[/]")
    console.print()
    
    console.clear()
    return recency, cold_war

if __name__ == "__main__":
    main()
