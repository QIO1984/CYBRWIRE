#!/usr/bin/env python3
import asyncio
import feedparser
import httpx
import json
import re
import time
import os
import sys
import yaml
from datetime import datetime, timedelta, timezone
from rich.console import Console, Group
from rich.table import Table
from rich.text import Text
from rich.theme import Theme
from rich.panel import Panel
from rich import box
from collections import deque
import logging
import webbrowser

# Textual imports
from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, Static, Label, RichLog
from textual.containers import Container, ScrollableContainer, Vertical, Horizontal, VerticalScroll
from textual.reactive import reactive
from textual import events
from textual.screen import Screen

# Setup logging
logging.basicConfig(
    filename=os.path.expanduser("~/.cybrwire_debug.log"),
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

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

HEADERS = {"User-Agent": "C Y B R W I R E 1.0 // Legendary Edition"}
MAX_TITLE_LEN = 90
MAX_SUMMARY_LEN = 140
HEAT_BAR_WIDTH = 33
REFRESH_INTERVAL = 300

# Fallback sources if YAML files can't be loaded
FALLBACK_SOURCES = [
    {"name": "CISA KEV", "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "type": "json", "source_file": "curated"},
    {"name": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/", "type": "rss", "source_file": "curated"},
    {"name": "TheHackerNews", "url": "https://feeds.feedburner.com/TheHackersNews", "type": "rss", "source_file": "curated"},
    {"name": "Krebs", "url": "https://krebsonsecurity.com/feed/", "type": "rss", "source_file": "curated"},
    {"name": "VulDB", "url": "https://vuldb.com/?rss.recent", "type": "rss", "source_file": "curated"},
    {"name": "ZDI Published", "url": "https://www.zerodayinitiative.com/rss/published/", "type": "rss", "source_file": "curated"},
    {"name": "ZDI Upcoming", "url": "https://www.zerodayinitiative.com/rss/upcoming/", "type": "rss", "source_file": "curated"},
    {"name": "Sophos Threat", "url": "https://news.sophos.com/en-us/category/threat-research/feed/", "type": "rss", "source_file": "curated"},
    {"name": "DShield Attackers", "url": "https://feeds.dshield.org/top10.txt", "type": "txt", "source_file": "curated"},
    {"name": "DShield Block", "url": "https://feeds.dshield.org/block.txt", "type": "txt", "source_file": "curated"},
    {"name": "Kaspersky Securelist", "url": "https://securelist.com/feed/", "type": "rss", "source_file": "curated"},
    {"name": "Dark Reading", "url": "https://www.darkreading.com/rss.xml", "type": "rss", "source_file": "curated"},
    {"name": "SANS ISC Diary", "url": "https://isc.sans.edu/rssfeed.xml", "type": "rss", "source_file": "curated"},
    {"name": "Microsoft MSRC", "url": "https://msrc.microsoft.com/blog/rss", "type": "rss", "source_file": "curated"},
    {"name": "Cisco Talos", "url": "https://blog.talosintelligence.com/feed/", "type": "rss", "source_file": "curated"},
]

def load_sources():
    """Load sources from YAML files (curated, custom, community)"""
    sources = []
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    yaml_files = [
        (os.path.join(script_dir, "cybrwire.yaml"), "curated"),
        (os.path.join(script_dir, "usrwire.yaml"), "custom"),
        (os.path.join(script_dir, "comwire.yaml"), "community"),
    ]
    
    for yaml_path, category in yaml_files:
        try:
            if os.path.exists(yaml_path):
                with open(yaml_path, 'r') as f:
                    data = yaml.safe_load(f) or {}
                    # Get sources from the category key
                    for src_key, src_list in data.items():
                        if isinstance(src_list, list):
                            for src in src_list:
                                src["source_file"] = src_key  # Tag with source category
                                sources.append(src)
                    logging.info(f"Loaded {len(sources)} sources from {yaml_path}")
        except Exception as e:
            logging.error(f"Failed to load {yaml_path}: {e}")
    
    # Use fallback if no sources loaded
    if not sources:
        logging.warning("No YAML sources loaded, using fallback sources")
        sources = FALLBACK_SOURCES
    
    return sources

def get_active_sources(feed_source="all"):
    """Filter sources based on active feed source type"""
    all_sources = load_sources()
    if feed_source == "all":
        return all_sources
    else:
        # Filter by source_file (curated, custom, or community)
        return [s for s in all_sources if s.get("source_file") == feed_source]

SOURCES = load_sources()

# Global state
alert_queue = []
alert_history = deque(maxlen=100)
breach_list = []  # Store recent breaches
source_cache = {}
source_file_stats = {"curated": 0, "custom": 0, "community": 0}  # Track alerts by source file
failed_feeds = {}  # Track failed/unavailable feeds {source_name: error_message}
currently_loading = None  # Track which feed is currently loading for display on loading screen
start_time = datetime.now(timezone.utc)
ticker_offset = 0
ticker_counter = 0
border_color = "bright_magenta"
last_critical = None
force_event = asyncio.Event()
active_feed_source = "all"  # Track which feed source is active: "curated", "custom", "community", or "all"

def parse_cisa(data, source_name, source_file):
    items = []
    for v in data.get("vulnerabilities", []):
        date_added = v.get("dateAdded", "")
        try:
            ts = datetime.fromisoformat(date_added + "T00:00:00+00:00") if date_added else datetime.now(timezone.utc)
        except Exception:
            ts = datetime.now(timezone.utc)
        items.append({
            "title": f"KEV ACTIVE → {v['cveID']}",
            "summary": v.get("shortDescription", "")[:MAX_SUMMARY_LEN],
            "published": ts.strftime("%a, %d %b"),
            "severity": "critical",
            "source": source_name,
            "source_file": source_file,
            "url": f"https://nvd.nist.gov/vuln/detail/{v['cveID']}",
            "ts": ts
        })
    return items

def parse_rss(text, source_name, source_file):
    f = feedparser.parse(text)
    items = []
    for e in f.entries:
        pub = e.get("published") or e.get("updated") or ""
        try:
            if "Z" in pub:
                ts = datetime.fromisoformat(pub.replace("Z", "+00:00"))
            else:
                p = feedparser._parse_date(pub)
                ts = datetime(*p[:6], tzinfo=timezone.utc) if p else datetime.now(timezone.utc)
        except Exception:
            ts = datetime.now(timezone.utc)
        title = e.title[:MAX_TITLE_LEN]
        raw_summary = e.get("summary") or e.get("description") or ""
        summary = re.sub(r'<[^>]*>', '', raw_summary)[:MAX_SUMMARY_LEN]
        link = e.get("link", "")
        lower = (title + summary).lower()
        sev = ("ransomware" if any(k in lower for k in ["ransom","lockbit","conti","blackcat","akira","clop"])
               else "apt" if any(k in lower for k in ["apt41","apt28","lazarus","iran","china","russia","dprk"])
               else "zeroday" if any(k in lower for k in ["wormable","0day","zero-day","in the wild","rce","actively exploited"])
               else "exploit" if any(k in lower for k in ["exploit","poc"])
               else "info")
        items.append({"title": title, "summary": summary, "published": ts.strftime("%a, %d %b"), 
                      "severity": sev, "source": source_name, "source_file": source_file, "url": link, "ts": ts})
    return items

def parse_txt(text, source_name, source_file):
    lines = [line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#")]
    items = []
    for line in lines[:20]:  # Limit IPs to 20 since there can be thousands
        parts = line.split()
        if len(parts) >= 3:
            ip_net = parts[0]
            attacks = parts[1]
            items.append({"title": f"TOP MALICIOUS IP: {ip_net} ({attacks} attacks)", 
                         "summary": "DShield top attacker", 
                         "published": datetime.now(timezone.utc).strftime("%a, %d %b"), 
                         "severity": "exploit", 
                         "source": source_name,
                         "source_file": source_file,
                         "url": f"https://www.dshield.org/ipinfo.html?ip={ip_net.split('/')[0]}",
                         "ts": datetime.now(timezone.utc)})
    return items

async def fetch_breaches():
    """Fetch recent breaches from HaveIBeenPwned"""
    global breach_list
    try:
        async with httpx.AsyncClient(headers={"User-Agent": "CybrWire"}, timeout=10) as c:
            r = await c.get("https://haveibeenpwned.com/api/v3/breaches")
            breaches = r.json()
            # Get the 7 most recently added breaches (sorted by AddedDate, not BreachDate)
            breach_list = sorted(breaches, key=lambda x: x.get("AddedDate", ""), reverse=True)[:7]
            logging.info(f"Fetched {len(breach_list)} recent breaches")
    except Exception as e:
        logging.error(f"Failed to fetch breaches: {e}")

class LoadingScreen(Screen):
    """Loading screen with animated ASCII art"""
    
    def __init__(self, cold_war_mode=False):
        super().__init__()
        self.cold_war_mode = cold_war_mode
        self.loading_step = 0
        self.feed_animation_step = 0
        self.messages = [
            "INITIALIZING...",
            "TAPPING WIRES...",
            "CONNECTIONS ESTABLISHED...",
            "PULLING LATEST...",
            "GENERATING ALERTS...",
            "STAND BY..."
        ]
        self.feed_spinner = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    
    def compose(self) -> ComposeResult:
        yield Static(id="loading-content")
    
    def on_mount(self) -> None:
        self.update_loading()
        self.set_interval(0.5, self.animate_loading)
    
    def animate_loading(self):
        self.loading_step += 1
        if self.loading_step >= len(self.messages):
            self.loading_step = len(self.messages) - 1
        self.feed_animation_step = (self.feed_animation_step + 1) % len(self.feed_spinner)
        self.update_loading()
    
    def update_loading(self):
        # ASCII art with gradient colors (or all green in cold war mode)
        if self.cold_war_mode:
            ascii_art = [
                ("╔════════════════════════════════════════════════════════════════════════════════════════════════════════╗", "green"),
                ("║                                                                                                        ║", "green"),
                ("║  ------------ ---      --- -----------  -----------  ---      --- --------  -----------  ------------  ║", "green"),
                ("║  ************  ***    ***  ***********  ***********  ***  **  *** ********  ***********  ************  ║", "green"),
                ("║  ---            ---  ---   ----       - ----    ---  ---  --  ---   ----    ----    ---  ----          ║", "green"),
                ("║  ***             ******    ***********  *********    ***  **  ***   ****    *********    ************  ║", "green"),
                ("║  ---              ----     -----------  ---------    ---  --  ---   ----    ---------    ------------  ║", "green"),
                ("║  ***              ****     ****       * ****  ****   ************   ****    ****  ****   ****          ║", "green"),
                ("║  ------------     ----     -----------  ----   ----   ----------  --------  ----   ----  ------------  ║", "green"),
                ("║  ************     ****     ***********  ****    ****   ********   ********  ****    **** ************  ║", "green"),
                ("║                                                                                                        ║", "green"),
                ("║                                 v1.0 LEGENDARY // EDITION // *COLD*WAR*MODE*                           ║", "green"),
                ("╚════════════════════════════════════════════════════════════════════════════════════════════════════════╝", "green"),
                ("                              By: GitHub/QIO1984 // The Hacker known as MADNOTE", "green"),
            ]
        else:
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
                ("║                                       v1.0 LEGENDARY // EDITION                                        ║", "#ff00ff"),
                ("╚════════════════════════════════════════════════════════════════════════════════════════════════════════╝", "#ff00ff"),
                ("                            By: GitHub/QIO1984 // The Hacker known as MADNOTE", "#00ffff"),
            ]
        
        art_text = "\n".join([f"[bold {color}]{line}[/]" for line, color in ascii_art])
        
        # Show messages up to current step
        displayed = "\n".join([f"[bold #00BB00]{msg}[/]" for msg in self.messages[:self.loading_step]])
        current = f"[bold blink #00BB00]{self.messages[self.loading_step]}[/]" if self.loading_step < len(self.messages) else ""
        
        # Show currently loading feed if available
        global currently_loading
        feed_status = ""
        if currently_loading and self.loading_step >= len(self.messages) - 1:
            spinner = self.feed_spinner[self.feed_animation_step]
            feed_status = f"\n[bold #00BB00]{spinner} FETCHING: {currently_loading[:60]}[/]"
        
        content = f"{art_text}\n\n{displayed}\n{current}{feed_status}"
        self.query_one("#loading-content", Static).update(content)

class StyledHeader(Header):
    """Custom header that supports cold war mode styling"""
    def render(self) -> str:
        app = self.app
        header_str = super().render()
        # If app has cold_war_mode, we'll style it via the watcher instead
        return header_str

class CybrWireApp(App):
    """Textual-based CybrWire threat intelligence dashboard"""
    
    CSS = """
    Screen {
        background: black;
    }
    
    Header {
        background: black;
        color: white;
    }
    
    .cold-war Header {
        background: black;
        color: #00BB00;
    }
    
    Footer {
        background: #1a1a1a !important;
    }
    
    Footer * {
        color: #55bbdd !important;
    }
    
    Footer Key {
        background: #333333 !important;
        color: #ffff00 !important;
    }
    
    Footer KeyPanel {
        background: #1a1a1a !important;
    }
    
    Footer .footer--description {
        color: #55bbdd !important;
    }
    
    Footer .footer--key {
        color: #ffff00 !important;
        background: #333333 !important;
    }
    
    Footer .footer--highlight {
        background: #444444 !important;
        color: #ffff00 !important;
    }
    
    Footer .footer--highlight-key {
        background: #444444 !important;
        color: #ffff00 !important;
    }
    
    /* Cold War Mode Styles */
    .cold-war Footer * {
        color: #00ff00 !important;
    }
    
    .cold-war Footer .footer--description {
        color: #00ff00 !important;
    }
    
    #ticker {
        height: 3;
        background: black;
        color: #00ff00;
    }
    
    .cold-war #ticker {
        color: #00ff00;
    }
    
    #main-layout {
        background: black;
        border: none;
    }
    
    #feeds-container {
        width: 3fr;
        height: 100%;
        background: black;
        overflow-y: auto;
    }
    
    #feeds-container:hover {
        background: #111111;
    }
    
    #feeds {
        width: 100%;
        background: black;
    }
    
    #dashboard {
        width: 1fr;
        height: 100%;
        background: black;
        color: white;
    }
    
    #loading-content {
        background: black;
        color: white;
        padding: 2;
    }
    """
    
    THEME_COLORS = {
        "textual-ansi": {
            "background": "#000000",
            "background-hover": "#1a1a1a"
        },
        "textual-dark": {
            "background": "#1e3050",
            "background-hover": "#2e4060"
        },
        "textual-light": {
            "background": "#d5e0f0",
            "background-hover": "#e8f0ff"
        },
        "nord": {
            "background": "#4c5a70",
            "background-hover": "#5e6b82"
        },
        "gruvbox": {
            "background": "#504540",
            "background-hover": "#655550"
        },
        "monokai": {
            "background": "#403f35",
            "background-hover": "#555448"
        },
        "dracula": {
            "background": "#3d4158",
            "background-hover": "#525670"
        },
        "solarized-light": {
            "background": "#f0e8c8",
            "background-hover": "#fff8e0"
        },
        "solarized-dark": {
            "background": "#0a5060",
            "background-hover": "#0f6575"
        },
        "tokyo-night": {
            "background": "#2a3355",
            "background-hover": "#3a4365"
        }
    }
    
    TITLE = " C Y B R W I R E"
    
    BINDINGS = [
        ("r", "refresh", "Force Refresh"),
        ("1", "set_window_24h", "24h Window"),
        ("2", "set_window_48h", "48h Window"),
        ("3", "set_window_7d", "7d Window"),
        ("4", "cycle_feeds", "Cycle Feeds"),
        ("8", "show_failed_feeds", "Cycle Panels"),
        ("9", "panel_next_page", "Panel Page +"),
        ("0", "panel_prev_page", "Panel Page -"),
        ("a", "filter_alerts", "Alerts Only"),
        ("p", "filter_posts", "Posts Only"),
        ("x", "filter_all", "Show All"),
        ("c", "toggle_cold_war", "Toggle Cold War Mode"),
        ("t", "cycle_theme", "Cycle Theme"),
        ("shift+b", "open_breach", "Open Top Breach"),
        ("up", "page_up", "Page Up"),
        ("down", "page_down", "Page Down"),
        ("q", "quit", "Quit"),
    ]
    
    recency_hours = reactive(24)
    cold_war_mode = reactive(False)
    next_refresh = reactive(datetime.now(timezone.utc))
    is_loading = reactive(True)
    feed_page_offset = reactive(0)
    hover_row = reactive(-1)
    filter_mode = reactive("all")  # all, alerts, posts
    theme_mode = reactive("default")  # default, dark, blue, purple, matrix
    feed_source_index = reactive(0)  # Cycle: 0=all, 1=curated, 2=custom, 3=community
    dashboard_panel_index = reactive(0)  # Cycle through dashboard panels (0=metrics, 1=failed feeds, etc.)
    panel_page_offset = reactive(0)  # Page offset within current panel for pagination
    
    def __init__(self, cold_war=False, recency=24):
        super().__init__()
        self._initializing = True  # Flag to prevent watcher calls during init
        self.cold_war_mode = cold_war
        self.recency_hours = recency
        self.refresher_task = None
        self.alert_urls = []  # Store URLs for clicking
        self.breach_urls = []  # Store breach URLs for clicking
        self.feed_page_offset = 0
        self.hover_row = -1
        self.rows_per_page = 20  # Default, will be calculated based on screen size
        self.filter_mode = "all"
        self.theme_mode = "textual-ansi"  # Black theme as default
        
        # Set footer color based on cold war mode
        self.footer_color = "#00BB00" if self.cold_war_mode else "#55bbdd"
        
        # Initialize next refresh time
        self.next_refresh = datetime.now(timezone.utc) + timedelta(seconds=REFRESH_INTERVAL)
        
        # Add cold-war class if in cold war mode
        if self.cold_war_mode:
            self.add_class("cold-war")
        
        self._initializing = False  # Allow watchers to work now
    
    def watch_cold_war_mode(self, old_value, new_value):
        """Update footer color when cold war mode changes"""
        if getattr(self, '_initializing', False):
            return
        self.footer_color = "#00BB00" if new_value else "#55bbdd"
        if new_value:
            self.add_class("cold-war")
        else:
            self.remove_class("cold-war")
    
    def apply_theme(self):
        """Apply current theme colors to CSS and Textual theme"""
        # Set Textual's built-in theme for header/footer (only for supported themes)
        # Textual only supports a subset of these themes natively
        textual_supported = [
            "textual-ansi", "textual-dark", "textual-light",
            "nord", "gruvbox", "monokai", "dracula",
            "solarized-light", "solarized-dark", "tokyo-night"
        ]
        
        if self.theme_mode in textual_supported:
            try:
                self.theme = self.theme_mode
            except Exception:
                self.theme = "textual-dark"
        else:
            # For unsupported themes, use textual-dark as base
            self.theme = "textual-dark"
        
        # Get custom background colors for our theme
        colors = self.THEME_COLORS.get(self.theme_mode, self.THEME_COLORS["textual-dark"])
        
        # Update widget styles programmatically
        try:
            # Update screen background
            self.screen.styles.background = colors["background"]
            
            # Update ticker
            ticker = self.query_one("#ticker", Static)
            ticker.styles.background = colors["background"]
            
            # Update feeds container
            feeds_container = self.query_one("#feeds-container")
            feeds_container.styles.background = colors["background"]
            
            # Update feeds
            feeds = self.query_one("#feeds", Static)
            feeds.styles.background = colors["background"]
            
            # Update dashboard
            dashboard = self.query_one("#dashboard", Static)
            dashboard.styles.background = colors["background"]
        except Exception:
            # Widgets might not exist yet on first call
            pass
        
    def on_mount(self) -> None:
        """Show loading screen then start app"""
        # Apply initial theme
        self.apply_theme()
        
        # Show loading screen
        self.push_screen(LoadingScreen(self.cold_war_mode))
        
        # Start background refresh
        self.refresher_task = asyncio.create_task(self.initial_load())
    
    async def initial_load(self):
        """Initial data load with loading screen"""
        global alert_queue, alert_history
        
        # Wait for first data fetch
        await self.fetch_feeds()
        await fetch_breaches()
        
        # Populate initial history for last 5 hours with current count
        # This gives immediate velocity data instead of waiting 5 hours
        now = datetime.now(timezone.utc)
        current_count = len(alert_queue)
        for i in range(5, 0, -1):
            timestamp = now - timedelta(hours=i)
            alert_history.append((timestamp, current_count))
        
        logging.info(f"Initial load complete, alert_queue has {len(alert_queue)} items")
        
        # Wait minimum time for loading screen effect
        await asyncio.sleep(3)
        
        # Switch to main screen
        self.pop_screen()
        self.is_loading = False
        
        # Force an immediate update
        self.call_later(self.update_display)
        
        # Start refresh loop
        asyncio.create_task(self.refresher())
        
        # Start UI updates
        self.set_interval(0.5, self.update_display)
        self.set_interval(0.7, self.animate_ticker)
        
    def compose(self) -> ComposeResult:
        """Create child widgets for the app."""
        yield StyledHeader(show_clock=True)
        yield Static(id="ticker")
        
        # Always create both layouts, use CSS to control visibility
        with Horizontal(id="main-layout"):
            with VerticalScroll(id="feeds-container"):
                yield Static(id="feeds", expand=True)
            yield Static(id="dashboard", expand=True)
        
        yield Footer()
    
    async def fetch_feeds(self):
        """Fetch data from all sources once"""
        global alert_queue, alert_history, source_cache, source_file_stats, active_feed_source, failed_feeds, currently_loading
        
        logging.info(f"=== FETCH_FEEDS STARTED: active_feed_source = {active_feed_source} ===")
        new = []
        source_file_stats = {"curated": 0, "custom": 0, "community": 0}  # Reset stats
        failed_feeds = {}  # Reset failed feeds
        
        # ALWAYS fetch ALL sources regardless of active_feed_source
        # This caches everything so switching sources is instant
        all_sources = get_active_sources("all")
        logging.info(f"Getting {len(all_sources)} sources (fetching ALL to cache)")
        
        async with httpx.AsyncClient(headers=HEADERS, timeout=30, follow_redirects=True) as c:
            for src in all_sources:
                try:
                    currently_loading = src["name"]  # Update global for loading screen
                    r = await c.get(src["url"])
                    r.raise_for_status()
                    
                    source_file = src.get("source_file", "curated")
                    if src["type"] == "json":
                        parsed = parse_cisa(r.json(), src["name"], source_file)
                    elif src["type"] == "rss":
                        parsed = parse_rss(r.text, src["name"], source_file)
                    elif src["type"] == "txt":
                        parsed = parse_txt(r.text, src["name"], source_file)
                    
                    new.extend(parsed)
                    source_file_stats[source_file] = source_file_stats.get(source_file, 0) + len(parsed)
                    logging.info(f"Successfully fetched {len(parsed)} items from {src['name']}")
                except Exception as e:
                    error_msg = str(e)
                    failed_feeds[src['name']] = error_msg
                    logging.error(f"Feed source {src['name']} failed: {e}")
        
        # Limit items per source based on age to keep data fresh but allow older items for 7-day view
        # Most RSS feeds provide 10-50 items, so we'll take up to 50 per source
        source_buckets = {}
        for a in new:
            src = a.get("source", "Unknown")
            if src not in source_buckets:
                source_buckets[src] = []
            if len(source_buckets[src]) < 50:
                source_buckets[src].append(a)
        
        alert_queue = sorted(
            [item for alerts in source_buckets.values() for item in alerts],
            key=lambda x: x.get("ts", datetime.min.replace(tzinfo=timezone.utc)),
            reverse=True
        )
        
        currently_loading = None  # Clear loading indicator
        logging.info(f"Total alerts in queue: {len(alert_queue)} (Feed source: {active_feed_source})")
    
    async def refresher(self):
        """Background task to fetch feeds periodically"""
        while True:
            # Wait for timeout or force event
            try:
                await asyncio.wait_for(force_event.wait(), timeout=REFRESH_INTERVAL)
                # Force refresh triggered - don't track in history
                force_event.clear()
                await self.fetch_feeds()
                await fetch_breaches()
                self.is_loading = False  # Clear loading flag after fetch
                logging.info("Force refresh completed")
            except asyncio.TimeoutError:
                # Normal automatic refresh - track in history
                await self.fetch_feeds()
                await fetch_breaches()
                alert_history.append((datetime.now(timezone.utc), len(alert_queue)))
                self.is_loading = False  # Clear loading flag after fetch
                logging.info("Automatic refresh completed")
            
            self.next_refresh = datetime.now(timezone.utc) + timedelta(seconds=REFRESH_INTERVAL)
    
    def update_display(self):
        """Update the UI display"""
        if self.is_loading:
            return
        
        try:
            logging.debug(f"Update display called, alert_queue has {len(alert_queue)} items")
            
            # Update ticker
            ticker_widget = self.query_one("#ticker", Static)
            ticker_content = self.make_ticker()
            ticker_widget.update(ticker_content)
            logging.debug("Ticker updated")
            
            # Update feeds table
            feeds_widget = self.query_one("#feeds", Static)
            feeds_content = self.make_feeds_table()
            feeds_widget.update(feeds_content)
            # Force the widget to update its virtual size for scrolling
            feeds_widget.refresh(layout=True)
            logging.debug("Feeds updated")
            
            # Update dashboard
            try:
                dashboard_widget = self.query_one("#dashboard", Static)
                
                # Cycle through dashboard panels
                if self.dashboard_panel_index == 0:
                    # Main metrics dashboard
                    dashboard_content = self.make_dashboard()
                elif self.dashboard_panel_index == 1:
                    # Failed feeds panel with pagination
                    global failed_feeds
                    if not failed_feeds:
                        failed_msg = "✓ All feeds loaded successfully!"
                        # Green in cold war mode, green otherwise (always positive)
                        failed_style = "bold #00BB00"
                        title_style = "#00BB00"
                        dashboard_content = Panel(
                            Text(failed_msg, style=failed_style),
                            title="FEED STATUS (Press 8 to cycle, 9/0 for pages)",
                            border_style=title_style,
                            padding=(1, 2)
                        )
                    else:
                        # Paginate failed feeds
                        feeds_per_page = 10
                        sorted_feeds = sorted(failed_feeds.items())
                        total_pages = (len(sorted_feeds) + feeds_per_page - 1) // feeds_per_page
                        
                        # Clamp page offset
                        self.panel_page_offset = max(0, min(self.panel_page_offset, total_pages - 1))
                        
                        start_idx = self.panel_page_offset * feeds_per_page
                        end_idx = start_idx + feeds_per_page
                        page_feeds = sorted_feeds[start_idx:end_idx]
                        
                        failed_msg = "⚠ FAILED FEEDS:\n\n"
                        for feed_name, error_msg in page_feeds:
                            # Truncate error messages
                            error_short = error_msg[:60] + "..." if len(error_msg) > 60 else error_msg
                            failed_msg += f"• {feed_name}\n  {error_short}\n"
                        
                        # Green in cold war mode (everything green), Red in normal mode (warning)
                        if self.cold_war_mode:
                            failed_style = "bold #00BB00"
                            border_color = "#00BB00"
                        else:
                            failed_style = "bold #ff6666"
                            border_color = "#ff6666"
                        
                        failed_text = Text(failed_msg, style=failed_style)
                        dashboard_content = Panel(
                            failed_text,
                            title=f"FEED STATUS - Page {self.panel_page_offset + 1}/{total_pages} (Press 8 to cycle, 9/0 for pages)",
                            border_style=border_color,
                            padding=(1, 2)
                        )
                else:
                    dashboard_content = self.make_dashboard()
                
                logging.debug(f"Dashboard content type: {type(dashboard_content)}, length: {len(str(dashboard_content)) if dashboard_content else 0}")
                dashboard_widget.update(dashboard_content)
                dashboard_widget.refresh()
                logging.debug("Dashboard updated")
            except Exception as e:
                logging.error(f"Error updating dashboard: {e}")
                import traceback
                logging.error(traceback.format_exc())
            
        except Exception as e:
            logging.error(f"Error updating display: {e}")
            import traceback
            logging.error(traceback.format_exc())
    
    def animate_ticker(self):
        """Animate the ticker"""
        global ticker_offset, ticker_counter
        ticker_counter = (ticker_counter + 1) % 1000
        ticker_offset = ticker_counter % 100
    
    def make_ticker(self):
        """Create ticker display"""
        now = datetime.now(timezone.utc)
        cutoff_time = now - timedelta(hours=self.recency_hours)
        
        # Build ticker content
        ticker_parts = []
        
        # Malicious IPs
        malicious_ips = []
        for a in alert_queue:
            if "TOP MALICIOUS IP" in a.get("title", ""):
                ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', a.get("title", ""))
                if ip_match:
                    malicious_ips.append(ip_match.group(1))
        if malicious_ips:
            ticker_parts.append(f"Top Malicious IPs: {', '.join(malicious_ips[:3])}")
        
        # Zero-day alerts
        zeroday_alerts = [a for a in alert_queue if a["severity"] == "zeroday" and a.get("ts", now) >= cutoff_time]
        if zeroday_alerts:
            ticker_parts.append(" // ".join([f'Zero-Day: "{a["title"][:50]}"' for a in zeroday_alerts[:2]]))
        else:
            ticker_parts.append("Zero-Day: No alerts")
        
        # Ransomware alerts
        ransomware_alerts = [a for a in alert_queue if a["severity"] == "ransomware" and a.get("ts", now) >= cutoff_time]
        if ransomware_alerts:
            ticker_parts.append(" // ".join([f'Ransomware: "{a["title"][:50]}"' for a in ransomware_alerts[:2]]))
        else:
            ticker_parts.append("Ransomware: No alerts")
        
        ticker_core = "  //  ".join(ticker_parts)
        if not ticker_core.strip():
            ticker_core = "--- NO CRITICAL THREATS DETECTED ---"
        
        # Make seamless wrap
        visible_width = self.size.width
        ticker_str = (ticker_core + "   ") * 3
        offset = ticker_offset % len(ticker_core + "   ")
        ticker_color = "#00BB00"
        ticker_display = Text(ticker_str[offset:offset + visible_width], style=f"bold {ticker_color} on black")
        
        return Panel(ticker_display, title="LIVE THREAT TAPE", 
                    border_style="#00BB00" if self.cold_war_mode else "#55bbdd", padding=0)
    
    def is_alert(self, item):
        """Classify item as alert vs blog post"""
        # Simple rule: INFO = blog post, everything else = alert
        return item["severity"] != "info"
    
    def make_feeds_table(self):
        """Create feeds table with pagination"""
        logging.debug(f"make_feeds_table: alert_queue has {len(alert_queue)} items")
        now = datetime.now(timezone.utc)
        cutoff_time = now - timedelta(hours=self.recency_hours)
        logging.debug(f"make_feeds_table: cutoff_time={cutoff_time}, now={now}, recency_hours={self.recency_hours}")
        
        # Calculate available height for feeds based on actual container size
        # Get the feeds container widget to determine actual available space
        try:
            feeds_widget = self.query_one("#feeds-container")
            # Container height minus panel borders (top+bottom=2), title (1), subtitle (1), padding (2)
            available_height = max(10, feeds_widget.size.height - 6)
        except Exception:
            # Fallback if widget not yet sized
            available_height = max(10, self.size.height - 12)
        
        self.rows_per_page = max(10, available_height)
        
        # Debug: check first few alerts
        if alert_queue:
            for i, a in enumerate(list(alert_queue)[:3]):
                alert_ts = a.get("ts", now)
                logging.debug(f"Alert {i}: ts={alert_ts}, cutoff={cutoff_time}, passes_filter={alert_ts >= cutoff_time}, title={a.get('title', 'NO TITLE')[:40]}")
        
        table = Table(box=box.DOUBLE, show_header=False, padding=(0,1), expand=True, border_style="#4499bb" if not self.cold_war_mode else "#00BB00")
        
        # Responsive column widths
        if self.size.width < 100:
            table.add_column(width=7, justify="right")
            table.add_column(width=8)
        else:
            table.add_column(width=9, justify="right")
            table.add_column(width=10)
        table.add_column()
        
        # Filter alerts within time window
        time_filtered = [a for a in alert_queue if a.get("ts", now) >= cutoff_time]
        
        # Apply feed source filter (only show data from selected sources)
        global active_feed_source
        if active_feed_source == "all":
            source_filtered = time_filtered
        else:
            source_filtered = [a for a in time_filtered if a.get("source_file") == active_feed_source]
        
        # Apply content filter
        if self.filter_mode == "alerts":
            filtered_alerts = [a for a in source_filtered if self.is_alert(a)]
        elif self.filter_mode == "posts":
            filtered_alerts = [a for a in source_filtered if not self.is_alert(a)]
        else:  # "all"
            filtered_alerts = source_filtered
        
        total_pages = max(1, (len(filtered_alerts) + self.rows_per_page - 1) // self.rows_per_page)
        
        # Clamp page offset
        max_offset = (total_pages - 1) * self.rows_per_page
        self.feed_page_offset = max(0, min(self.feed_page_offset, max_offset))
        
        # Get current page of alerts
        start_idx = self.feed_page_offset
        end_idx = start_idx + self.rows_per_page
        page_alerts = filtered_alerts[start_idx:end_idx]
        
        rows_added = 0
        self.alert_urls = []  # Reset URLs list
        
        for row_idx, a in enumerate(page_alerts):
            # Muted cybrwire.py theme colors (increased saturation)
            severity_colors = {
                "critical": "bold white on #dd4444",         # More saturated red
                "zeroday": "bold black on #e6d144",         # More saturated yellow
                "ransomware": "bold black on #dd4488",      # More saturated hot pink with black text
                "apt": "bold black on #b866cc",             # Warmer purple (more red) with black text
                "exploit": "bold #dd5555",                   # More saturated bright red
                "info": "#55bbdd"                            # More saturated cyan
            }
            
            sev = a["severity"]
            
            # Check if this row is hovered
            is_hovered = (row_idx == self.hover_row)
            
            if self.cold_war_mode:
                if is_hovered:
                    title_style = "bold white on #004400"  # Green hover background
                    severity_style = "bold white on #004400"
                    date_style = "bold white on #004400"
                else:
                    title_style = "#00BB00"
                    severity_style = "#00BB00"
                    date_style = "#00BB00"
                    # Add green accent for alerts
                    if self.is_alert(a):
                        title_style += " on #001100"
                        severity_style += " on #001100"
                        date_style += " on #001100"
            else:
                # Apply hover effect - make text white and add background
                if is_hovered:
                    title_style = "bold white on #333333"
                    severity_style = "bold white on #333333"
                    date_style = "bold white on #333333"
                else:
                    title_style = severity_colors.get(sev, "white")
                    severity_style = severity_colors.get(sev, "white")
                    date_style = "#55bbdd"  # Muted cyan for dates
            
            # Create colored text
            title_text = Text(a["title"][:MAX_TITLE_LEN], style=title_style)
            
            # Store URL for this row
            self.alert_urls.append(a.get("url", ""))
            
            table.add_row(
                Text(a["published"], style=date_style),
                Text(a["severity"].upper(), style=severity_style), 
                title_text
            )
            rows_added += 1
        
        logging.debug(f"make_feeds_table: added {rows_added} rows from page {self.feed_page_offset // self.rows_per_page + 1}/{total_pages}")
        
        if rows_added == 0:
            table.add_row("", Text("NO ALERTS", style="yellow"), Text("Loading feeds...", style="dim"))
        
        filtered_count = len(filtered_alerts)
        rem = int((self.next_refresh - datetime.now(timezone.utc)).total_seconds())
        m, s = divmod(max(rem, 0), 60)
        uptime = str(datetime.now(timezone.utc) - start_time).split('.')[0]
        
        # Add pagination info to status
        current_page = self.feed_page_offset // self.rows_per_page + 1
        
        # Filter mode indicator
        filter_text = {"all": "All", "alerts": "Alerts", "posts": "Posts"}[self.filter_mode]
        filter_color = "bold green" if self.cold_war_mode else ("bold cyan" if self.filter_mode == "all" else "bold yellow")
        
        status = Text()
        status.append(f"{datetime.now(timezone.utc):%H:%M:%S} UTC", "bold green" if self.cold_war_mode else "bold white")
        status.append(f" — {filtered_count} {filter_text.lower()}", "bold green" if self.cold_war_mode else "bold cyan")
        if total_pages > 1:
            status.append(f" — Page {current_page}/{total_pages}", "bold green" if self.cold_war_mode else "bold yellow")
        status.append(f" — Filter: {filter_text}", filter_color)
        status.append(f" — Next: {m:02d}:{s:02d}", "bold green" if self.cold_war_mode else "bold bright_red")
        status.append(f" — Uptime: {uptime}", "bold green" if self.cold_war_mode else "bold white")
        
        return Panel(table, 
                    title=f"[bold reverse #00ff00 on black]  C Y B R W I R E 1.0 // LEGENDARY EDITION{' // *COLD*WAR*MODE*' if self.cold_war_mode else ''}  [/]",
                    subtitle=status,
                    border_style="#00ff00" if self.cold_war_mode else "#44ccaa",
                    padding=(1,2))
    
    def make_dashboard(self):
        """Create dashboard panel with all metrics"""
        global active_feed_source
        now = datetime.now(timezone.utc)
        cutoff_time = now - timedelta(hours=self.recency_hours)
        
        # Filter to active feed source first
        if active_feed_source == "all":
            source_filtered_queue = alert_queue
        else:
            source_filtered_queue = [a for a in alert_queue if a.get("source_file") == active_feed_source]
        
        # Calculate all metrics from filtered queue
        critical_count = len([a for a in source_filtered_queue if a["severity"] == "critical" and a.get("ts", now) >= cutoff_time])
        zeroday_count = len([a for a in source_filtered_queue if a["severity"] == "zeroday" and a.get("ts", now) >= cutoff_time])
        ransomware_count = len([a for a in source_filtered_queue if a["severity"] == "ransomware" and a.get("ts", now) >= cutoff_time])
        apt_count = len([a for a in source_filtered_queue if a["severity"] == "apt" and a.get("ts", now) >= cutoff_time])
        exploit_count = len([a for a in source_filtered_queue if a["severity"] == "exploit" and a.get("ts", now) >= cutoff_time])
        filtered_count = len([a for a in source_filtered_queue if a.get("ts", now) >= cutoff_time])
        new_count = len([a for a in source_filtered_queue if (now - a.get("ts", now)).total_seconds() < 3600 and a.get("ts", now) >= cutoff_time])
        ioc_count = len([a for a in source_filtered_queue if ("IP" in a["title"] or "Hash" in a["title"] or "URL" in a["title"]) and a.get("ts", now) >= cutoff_time])
        
        # Rate calculation
        hour_ago = now - timedelta(hours=1)
        rate = sum(1 for ts, _ in alert_history if ts > hour_ago)
        
        # Build metrics table
        metrics_table = Table(show_header=False, box=None, expand=True)
        metrics_table.add_column(justify="left", no_wrap=True, ratio=1)
        metrics_table.add_column(justify="left", no_wrap=True, ratio=1)
        
        metrics_list = [
            ("Total Alerts", filtered_count, "#55bbdd"),
            ("Critical/KEV", critical_count, "#dd4444"),
            ("Zero-Day", zeroday_count, "#e6d144"),
            ("Ransomware", ransomware_count, "#dd4488"),
            ("APT Activity", apt_count, "#b866cc"),
            ("Exploits/POC", exploit_count, "#dd5555"),
            ("IOCs Detected", ioc_count, "#dd5555"),
            ("Incoming (1h)", new_count, "#66dd66"),
            ("Alerts/Hour", f"{rate}/hr", "#66dd66"),
        ]
        
        # Right column - TOP SOURCES with feed selection indicators
        source_counts = {"curated": 0, "custom": 0, "community": 0}
        for a in alert_queue:
            if a.get("ts", datetime.now(timezone.utc)) >= datetime.now(timezone.utc) - timedelta(hours=self.recency_hours):
                src_file = a.get("source_file", "curated")
                source_counts[src_file] = source_counts.get(src_file, 0) + 1
        
        total_filtered_for_sources = sum(source_counts.values())
        sources_right = []
        header = Text("TOP SOURCES", style="#00ff00 bold" if self.cold_war_mode else "#55bbdd bold")
        sources_right.append(header)
        
        if total_filtered_for_sources > 0:
            bar_width = 12
            curated_pct = (source_counts.get("curated", 0) / total_filtered_for_sources * 100)
            custom_pct = (source_counts.get("custom", 0) / total_filtered_for_sources * 100)
            community_pct = (source_counts.get("community", 0) / total_filtered_for_sources * 100)
            
            # Curated - with indicator
            curated_indicator = "● " if active_feed_source == "curated" else "○ "
            curated_bar = "█" * int(curated_pct / (100 / bar_width)) + "░" * (bar_width - int(curated_pct / (100 / bar_width)))
            s = Text(curated_indicator + "Curated", style="#00ff00 bold" if self.cold_war_mode else "#66cc66 bold")
            sources_right.append(s)
            bar_text = Text()
            bar_text.append(f"[{curated_bar}] {int(curated_pct)}%", style="#00ff00" if self.cold_war_mode else "#66cc66")
            sources_right.append(bar_text)
            
            # Custom - with indicator
            custom_indicator = "● " if active_feed_source == "custom" else "○ "
            custom_bar = "█" * int(custom_pct / (100 / bar_width)) + "░" * (bar_width - int(custom_pct / (100 / bar_width)))
            s = Text(custom_indicator + "Custom", style="#00ff00 bold" if self.cold_war_mode else "#9966ff bold")
            sources_right.append(s)
            bar_text = Text()
            bar_text.append(f"[{custom_bar}] {int(custom_pct)}%", style="#00ff00" if self.cold_war_mode else "#9966ff")
            sources_right.append(bar_text)
            
            # Community - with indicator
            community_indicator = "● " if active_feed_source == "community" else "○ "
            community_bar = "█" * int(community_pct / (100 / bar_width)) + "░" * (bar_width - int(community_pct / (100 / bar_width)))
            s = Text(community_indicator + "Community", style="#00ff00 bold" if self.cold_war_mode else "#66ccff bold")
            sources_right.append(s)
            bar_text = Text()
            bar_text.append(f"[{community_bar}] {int(community_pct)}%", style="#00ff00" if self.cold_war_mode else "#66ccff")
            sources_right.append(bar_text)
            
            # ALL option - with indicator
            all_indicator = "● " if active_feed_source == "all" else "○ "
            s = Text(all_indicator + "All", style="#00ff00 bold" if self.cold_war_mode else "#dddd66 bold")
            sources_right.append(s)
        
        # Add rows with both columns
        rows = max(len(metrics_list), len(sources_right))
        for i in range(rows):
            if i < len(metrics_list):
                lbl, val, style = metrics_list[i]
                left_cell = Text()
                left_cell.append(f"{lbl:12} : ", style="#00ff00" if self.cold_war_mode else style)
                left_cell.append(str(val), style="#00ff00" if self.cold_war_mode else style)
            else:
                left_cell = Text("")
            
            right_cell = sources_right[i] if i < len(sources_right) else Text("")
            metrics_table.add_row(left_cell, right_cell)
        
        # Heat calculations
        total_threats = critical_count + zeroday_count + ransomware_count + apt_count + exploit_count
        heat_pct = (total_threats / max(filtered_count, 1)) * 100 if filtered_count > 0 else 0
        ransomware_pct = (ransomware_count / max(filtered_count, 1)) * 100 if filtered_count > 0 else 0
        apt_pct = (apt_count / max(filtered_count, 1)) * 100 if filtered_count > 0 else 0
        zeroday_pct = (zeroday_count / max(filtered_count, 1)) * 100 if filtered_count > 0 else 0
        exploit_pct = (exploit_count / max(filtered_count, 1)) * 100 if filtered_count > 0 else 0
        
        # Weighted threat score: prioritize severity and exploitability
        # Zero-days (5x), Critical/KEV (4x), Ransomware & APT (3x), Exploits (2x)
        weighted_threats = (
            critical_count * 4 +
            zeroday_count * 5 +
            ransomware_count * 3 +
            apt_count * 3 +
            exploit_count * 2
        )
        # Normalize to 0-100% based on maximum possible threat value
        max_threat_value = filtered_count * 17 if filtered_count > 0 else 1
        master_pct = min(100, (weighted_threats / max_threat_value) * 100) if filtered_count > 0 else 0
        
        # Cap percentages early for style determination
        capped_heat = min(100, heat_pct)
        capped_ransomware = min(100, ransomware_pct)
        capped_apt = min(100, apt_pct)
        capped_zeroday = min(100, zeroday_pct)
        capped_exploit = min(100, exploit_pct)
        capped_master = min(100, master_pct)
        
        # Determine Heat Level style (responsive) - based on capped percentage
        if capped_heat < 20:
            heat_style = "#66cc66"
        elif capped_heat < 50:
            heat_style = "#e6d144"
        elif capped_heat < 80:
            heat_style = "#dd5555"
        else:
            heat_style = "bold reverse #dd4444"
        
        # Determine DEFCON level
        if master_pct < 20:
            defcon = 5
            defcon_style = "#66cc66"
        elif master_pct < 40:
            defcon = 4
            defcon_style = "#e6d144"
        elif master_pct < 60:
            defcon = 3
            defcon_style = "#e6b944"
        elif master_pct < 80:
            defcon = 2
            defcon_style = "#dd5555"
        else:
            defcon = 1
            defcon_style = "bold reverse #dd4444"
        
        # Get time since last zero-day
        last_zeroday_time = min((a.get("ts", now) for a in alert_queue if a["severity"] == "zeroday" and a.get("ts", now) >= cutoff_time), default=now)
        time_since_zeroday = str(now - last_zeroday_time).split('.')[0]
        
        # Build heat bars (already capped above)
        indent = " " * 2
        heat_bar = "█" * int(capped_heat / 3) + "░" * (HEAT_BAR_WIDTH - int(capped_heat / 3))
        ransomware_bar = "█" * int(capped_ransomware / 3) + "░" * (HEAT_BAR_WIDTH - int(capped_ransomware / 3))
        apt_bar = "█" * int(capped_apt / 3) + "░" * (HEAT_BAR_WIDTH - int(capped_apt / 3))
        zeroday_bar = "█" * int(capped_zeroday / 3) + "░" * (HEAT_BAR_WIDTH - int(capped_zeroday / 3))
        exploit_bar = "█" * int(capped_exploit / 3) + "░" * (HEAT_BAR_WIDTH - int(capped_exploit / 3))
        defcon_bar = "█" * int(capped_master / 3) + "░" * (HEAT_BAR_WIDTH - int(capped_master / 3))
        doomsday_pct = 90
        doomsday_bar = "█" * int(doomsday_pct / 3) + "░" * (HEAT_BAR_WIDTH - int(doomsday_pct / 3))
        
        heat_info = ""
        heat_info += f"\n[{'#00ff00' if self.cold_war_mode else heat_style}]{indent}[bold]Heat Level (High-Threat %)[/bold]:\n{indent}[{'#00ff00' if self.cold_war_mode else heat_style}]{heat_bar}[/] {int(capped_heat)}%[/]\n"
        heat_info += f"[{'#00ff00' if self.cold_war_mode else '#dd4488'}]{indent}[bold]Ransomware Heat[/bold]:\n{indent}[{'#00ff00' if self.cold_war_mode else '#dd4488'}]{ransomware_bar}[/] {int(capped_ransomware)}%[/]\n"
        heat_info += f"[{'#00ff00' if self.cold_war_mode else '#b866cc'}]{indent}[bold]APT Heat[/bold]:\n{indent}[{'#00ff00' if self.cold_war_mode else '#b866cc'}]{apt_bar}[/] {int(capped_apt)}%[/]\n"
        heat_info += f"[{'#00ff00' if self.cold_war_mode else '#e6d144'}]{indent}[bold]Zero-Day Heat (Last: {time_since_zeroday} ago)[/bold]:\n{indent}[{'#00ff00' if self.cold_war_mode else '#e6d144'}]{zeroday_bar}[/] {int(capped_zeroday)}%[/]\n"
        heat_info += f"[{'#00ff00' if self.cold_war_mode else '#dd5555'}]{indent}[bold]Exploit Heat[/bold]:\n{indent}[{'#00ff00' if self.cold_war_mode else '#dd5555'}]{exploit_bar}[/] {int(capped_exploit)}%[/]\n"
        heat_info += f"[{'#00ff00' if self.cold_war_mode else 'bold #dd4444'}]{indent}[bold]Doomsday Clock (89s to Midnight)[/bold]:\n{indent}[{'#00ff00' if self.cold_war_mode else 'bold #dd4444'}]{doomsday_bar}[/][/]\n"
        heat_info += f"[{'#00ff00' if self.cold_war_mode else defcon_style}]{indent}[bold]Cyber DEFCON Level (DEFCON {defcon})[/bold]:\n{indent}[{'#00ff00' if self.cold_war_mode else defcon_style}]{defcon_bar}[/] {int(capped_master)}%[/]\n\n"
        
        # PwnList section with padding
        heat_info += f"[{'#00ff00' if self.cold_war_mode else '#dd4444'}]{indent}[bold]PwnList[/bold]:[/]\n"
        
        breach_colors = ["#ff6666", "#ff9966", "#ffcc66", "#66ff66", "#66ccff", "#cc99ff", "#99ffff"]
        self.breach_urls = []
        
        for idx, breach in enumerate(breach_list):
            breach_name = breach.get('Title', 'Unknown')
            # Truncate long breach names to fit on one line - be more aggressive
            if len(breach_name) > 20:
                breach_name = breach_name[:17] + "..."
            # Use AddedDate (when added to HIBP) instead of BreachDate (when breach occurred)
            added_date = breach.get('AddedDate', 'Unknown')
            # Shorten date to just MM-DD for space
            if len(added_date) >= 10:
                added_date = added_date[5:10]  # Get MM-DD from YYYY-MM-DD
            breach_count = breach.get('PwnCount', 0)
            
            # Format count nicely
            if breach_count > 1000000:
                count_str = f"{breach_count/1000000:.1f}M"
            elif breach_count > 1000:
                count_str = f"{breach_count/1000:.1f}K"
            else:
                count_str = str(breach_count)
            
            color = "#00ff00" if self.cold_war_mode else breach_colors[idx % len(breach_colors)]
            breach_url = f"https://haveibeenpwned.com/?q={breach_name.replace(' ', '+')}"
            self.breach_urls.append(breach_url)
            
            heat_info += f"{indent}[{color}]{breach_name}[/] [{color}]{added_date}[/] [{color}]•[/] [{color}]{count_str}[/]\n"
        
        if not breach_list:
            heat_info += f"{indent}[dim]Fetching breach data...[/dim]\n"
        
        # Dominant Threat - which threat type is dominating
        threat_types = {
            "Ransomware": ransomware_count,
            "APT": apt_count,
            "Zero-Day": zeroday_count,
            "Exploitation": exploit_count,
            "Critical": critical_count,
        }
        if total_threats > 0:
            dominant_type = max(threat_types.items(), key=lambda x: x[1])
            dominant_name, dominant_count = dominant_type
            dominant_pct = (dominant_count / total_threats) * 100 if total_threats > 0 else 0
            
            # Determine color and icon based on type
            threat_map = {
                "Ransomware": ("#ff0066", "🔓"),
                "APT": ("#800080", "🕵️"),
                "Zero-Day": ("#e6d144", "⚡"),
                "Exploitation": ("#dd5555", "💥"),
                "Critical": ("#dd4444", "🚨"),
            }
            threat_color, threat_icon = threat_map.get(dominant_name, ("#66ccff", "⚙️"))
            
            # In cold war mode, don't show colored icons
            if self.cold_war_mode:
                threat_color = "#00ff00"
                threat_icon = ""
            
            threat_label = f"DOMINANT THREAT: {dominant_name.upper()} WAVE"
            heat_info += f"\n[{threat_color}]{indent}[bold]{threat_label}[/bold] {threat_icon}[/]\n"
        
        # Alert Velocity - forecast based on trend
        now = datetime.now(timezone.utc)
        last_hour = now - timedelta(hours=1)
        last_2hrs = now - timedelta(hours=2)
        
        alerts_last_hour = sum(1 for ts, _ in alert_history if ts > last_hour)
        alerts_prev_hour = sum(1 for ts, _ in alert_history if last_2hrs < ts <= last_hour)
        
        if alerts_last_hour > 0 and alerts_prev_hour > 0:
            velocity = alerts_last_hour / alerts_prev_hour
            if velocity > 1.5:
                velocity_status = "SPIKING"
                velocity_icon = "🔥" if not self.cold_war_mode else ""
                velocity_color = "bold #dd4444"
            elif velocity > 1.2:
                velocity_status = "INCREASING"
                velocity_icon = "📈" if not self.cold_war_mode else ""
                velocity_color = "#dd5555"
            elif velocity < 0.7:
                velocity_status = "COOLING"
                velocity_icon = "✓" if not self.cold_war_mode else ""
                velocity_color = "#66cc66"
            else:
                velocity_status = "STEADY"
                velocity_icon = "→" if not self.cold_war_mode else ""
                velocity_color = "#e6d144"
        else:
            velocity_status = "CALIBRATING"
            velocity_icon = ""
            velocity_color = "dim white"
        
        if self.cold_war_mode:
            velocity_color = "#00ff00"
        
        velocity_label = f"ALERT VELOCITY: {velocity_status} {velocity_icon}".strip()
        heat_info += f"[{velocity_color}]{indent}[bold]{velocity_label}[/bold][/]\n"
        
        # Top Attack Vector - most common attack method in current alerts
        vector_keywords = {
            "Malware": 0,
            "Ransomware": 0,
            "Web": 0,
            "Exploit": 0,
            "Phishing": 0,
            "Email": 0,
        }
        for alert in alert_queue:
            title_lower = alert.get("title", "").lower()
            for vector in vector_keywords:
                if vector.lower() in title_lower:
                    vector_keywords[vector] += 1
        
        if any(vector_keywords.values()):
            top_vector = max(vector_keywords.items(), key=lambda x: x[1])
            vector_name, vector_count = top_vector
            vector_pct = (vector_count / max(filtered_count, 1)) * 100
            vector_color = "#66ccff" if not self.cold_war_mode else "#00ff00"
            heat_info += f"[{vector_color}]{indent}[bold]PRIMARY VECTOR: {vector_name.upper()} ({int(vector_pct)}%)[/bold][/]\n"
        
        # Geographic Hotspot - infer from threat types and sources
        # Simplified: infer from dominant threat types which regions are likely active
        geo_map = {
            "Ransomware": ("Eastern Europe", "#ff0066"),
            "APT": ("China/Russia", "#800080"),
            "Zero-Day": ("Global", "#e6d144"),
            "Exploitation": ("Global", "#dd5555"),
            "Phishing": ("Global", "#66ccff"),
        }
        
        if total_threats > 0:
            dominant_type = max(threat_types.items(), key=lambda x: x[1])
            geo_region, geo_color = geo_map.get(dominant_type[0], ("Unknown", "#555555"))
            if self.cold_war_mode:
                geo_color = "#00ff00"
            heat_info += f"[{geo_color}]{indent}[bold]HOTSPOT: {geo_region}[/bold][/]\n"
        
        return Panel(Group(metrics_table, Text.from_markup(heat_info)),
                    title="WAR ROOM DASHBOARD",
                    border_style="#00ff00" if self.cold_war_mode else "#5588dd",
                    padding=(0,1))
    
    def action_refresh(self):
        """Force refresh feeds"""
        force_event.set()
    
    def action_set_window_24h(self):
        """Set 24 hour window"""
        self.recency_hours = 24
    
    def action_set_window_48h(self):
        """Set 48 hour window"""
        self.recency_hours = 48
    
    def action_set_window_7d(self):
        """Set 7 day window"""
        self.recency_hours = 168
    
    def action_open_browser(self):
        """Open top alert in browser"""
        if alert_queue:
            webbrowser.open(alert_queue[0]['url'])
    
    def action_open_breach(self):
        """Open top breach in browser"""
        if breach_list:
            breach_url = f"https://haveibeenpwned.com/api/v3/breaches?breach={breach_list[0]['Name']}"
            webbrowser.open(f"https://haveibeenpwned.com/?q={breach_list[0]['Title'].replace(' ', '+')}")
    
    def action_filter_alerts(self):
        """Show only alerts (threats/vulnerabilities)"""
        self.filter_mode = "alerts"
        self.feed_page_offset = 0  # Reset to first page
        self.call_later(self.update_display)
    
    def action_filter_posts(self):
        """Show only blog posts/articles"""
        self.filter_mode = "posts"
        self.feed_page_offset = 0  # Reset to first page
        self.call_later(self.update_display)
    
    def action_filter_all(self):
        """Show all content"""
        self.filter_mode = "all"
        self.feed_page_offset = 0  # Reset to first page
        self.call_later(self.update_display)
    
    def action_toggle_cold_war(self):
        """Toggle cold war mode"""
        self.cold_war_mode = not self.cold_war_mode
        self.call_later(self.update_display)
    
    def action_cycle_feeds(self):
        """Cycle through feed sources: all → curated → custom → community → all"""
        global active_feed_source
        sources = ["all", "curated", "custom", "community"]
        self.feed_source_index = (self.feed_source_index + 1) % len(sources)
        active_feed_source = sources[self.feed_source_index]
        logging.info(f"CYCLE FEEDS: Switched to {active_feed_source.upper()}")
        self.feed_page_offset = 0
        self.call_later(self.update_display)
    
    def action_show_failed_feeds(self):
        """Cycle through dashboard panels"""
        # 0 = Main metrics, 1 = Failed feeds
        self.dashboard_panel_index = (self.dashboard_panel_index + 1) % 2
        self.panel_page_offset = 0  # Reset page when switching panels
        self.call_later(self.update_display)
    
    def action_panel_next_page(self):
        """Next page in current panel"""
        self.panel_page_offset += 1
        self.call_later(self.update_display)
    
    def action_panel_prev_page(self):
        """Previous page in current panel"""
        self.panel_page_offset = max(0, self.panel_page_offset - 1)
        self.call_later(self.update_display)
    
    def action_cycle_theme(self):
        """Cycle through available themes"""
        themes = [
            "textual-ansi", "textual-dark", "textual-light",
            "nord", "gruvbox", "monokai", "dracula",
            "solarized-light", "solarized-dark", "tokyo-night"
        ]
        current_idx = themes.index(self.theme_mode) if self.theme_mode in themes else 0
        self.theme_mode = themes[(current_idx + 1) % len(themes)]
        self.apply_theme()
        self.call_later(self.update_display)
    
    def action_page_up(self):
        """Move to previous page of feeds"""
        self.feed_page_offset = max(0, self.feed_page_offset - self.rows_per_page)
        self.call_later(self.update_display)
    
    def action_page_down(self):
        """Move to next page of feeds"""
        # Calculate filtered alerts count
        now = datetime.now(timezone.utc)
        cutoff_time = now - timedelta(hours=self.recency_hours)
        filtered_count = len([a for a in alert_queue if a.get("ts", now) >= cutoff_time])
        max_offset = max(0, filtered_count - self.rows_per_page)
        self.feed_page_offset = min(self.feed_page_offset + self.rows_per_page, max_offset)
        self.call_later(self.update_display)
    
    def on_mouse_move(self, event) -> None:
        """Track mouse movement over feeds to highlight rows"""
        # Check if mouse is over the feeds widget
        try:
            feeds_widget = self.query_one("#feeds", Static)
            # Get the widget's region
            if feeds_widget.region.contains(event.screen_x, event.screen_y):
                # Calculate which row is being hovered
                # Panel has: border (1) + title line (1) + top padding (1) = 3 lines offset
                relative_y = event.screen_y - feeds_widget.region.y - 3
                if relative_y >= 0:
                    new_hover = relative_y
                    if new_hover != self.hover_row:
                        self.hover_row = new_hover
                        self.call_later(self.update_display)
            else:
                if self.hover_row != -1:
                    self.hover_row = -1
                    self.call_later(self.update_display)
        except Exception:
            pass
    
    def on_click(self, event) -> None:
        """Handle clicks on the feeds area to open URLs"""
        # Check if click is on the feeds widget
        if event.widget.id == "feeds":
            # Try to estimate which row was clicked based on Y position
            # This is approximate since we don't have exact row boundaries
            # Panel has padding, table has padding, so offset by ~3 lines for title/border
            click_y = event.y
            # Account for panel border and title (roughly 3 lines)
            row_index = max(0, click_y - 3)
            
            if 0 <= row_index < len(self.alert_urls):
                url = self.alert_urls[row_index]
                if url:
                    webbrowser.open(url)
                    logging.info(f"Opened URL: {url}")
        
        # Check if click is on the dashboard widget (for breach links)
        elif event.widget.id == "dashboard":
            click_y = event.y
            # Approximate offset for the breaches section (roughly at top after title)
            breach_index = max(0, click_y - 10)
            
            if 0 <= breach_index < len(self.breach_urls):
                url = self.breach_urls[breach_index]
                if url:
                    webbrowser.open(url)
                    logging.info(f"Opened breach URL: {url}")

def main():
    """Main entry point"""
    # Print title screen
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
        ("║                                       v1.0 LEGENDARY // EDITION                                        ║", "#ff00ff"),
        ("╚════════════════════════════════════════════════════════════════════════════════════════════════════════╝", "#ff00ff"),
        ("                            By: GitHub/QIO1984 // The Hacker known as MADNOTE", "#00ffff"),
    ]
    
    for line, color in ascii_art:
        console.print(f"[bold {color}]{line}[/]")
    
    console.print()
    console.print("                                          [bold #ff00ff]#Is this the big one...?[/bold #ff00ff]")
    console.print()
    
    # Metric explanations
    console.print(" [bold cyan]Metric Bar Explanations:[/]")
    console.print("  [green]Heat Level[/] = % of all alerts classified as high-threat (critical, zero-day, ransomware, APT, exploit)")
    console.print("  [#ff0066]Ransomware Heat[/] = % of ransomware-related alerts")
    console.print("  [#800080]APT Heat[/] = % of APT/nation-state activity alerts")
    console.print("  [bright_yellow]Zero-Day Heat[/] = % of unpatched vulnerability exploits")
    console.print("  [bright_red]Exploit Heat[/] = % of publicly exploitable vulnerabilities (POC available)")
    console.print("  [bold red]Doomsday Clock[/] = Symbolic threat timeline (always at 89 seconds to midnight)")
    console.print("  [bold cyan]Cyber DEFCON[/] = Weighted threat score (zero-day×5, critical×4, ransomware/APT×3, exploit×2) normalized 0-100% (5=Safe, 1=Critical)")
    console.print("  [bright_magenta]Threat Velocity[/] = Alerts per hour over last 5 hours (shows activity trends)")
    console.print()
    
    # Data source info
    console.print("  [bold cyan]Data Sources:[/] [white]Aggregates real-time threat feeds from multiple cybersecurity sources[/]")
    console.print("  [bold cyan]Severity Levels:[/] [white]Critical (red), High (orange), Medium (yellow), Low (white)[/]")
    console.print("  [bold cyan]Auto-refresh:[/] [white]System updates every 60 seconds with live threat intelligence[/]")
    console.print()
    
    # Runtime controls
    console.print(" [bold dim]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/]")
    console.print(" [bold cyan]Runtime Controls:[/]")
    console.print("   [bold white]1/2/3[/] = Time   [bold white]a/p/x[/] = Filter   [bold white]t[/] = Theme   [bold white]↑/↓[/] = Page   [bold white]r[/] = Refresh   [bold white]b[/] = Open   [bold white]q[/] = Quit")
    console.print(" [dim]Tip: Press 't' to cycle through 10 themes (Black/Dark/Light/Nord/Gruvbox/Monokai/Dracula/Solarized/Tokyo Night)[/]")
    console.print()
    
    console.print(" [bold dim]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/]")
    # Menu options
    console.print(" [bold cyan]Select Data Age Window:[/]")
    console.print("   [bold white]1[/] = Last 24 hours (default)")
    console.print("   [bold white]2[/] = Last 48 hours")
    console.print("   [bold white]3[/] = Last 7 days")
    console.print()
    console.print(" [bold cyan]Enter Choice:[/] ", end="")
    
    recency = 24
    choice = input().strip()
    if choice == "2":
        recency = 48
    elif choice == "3":
        recency = 168
    
    console.print()
    console.print(" [bold cyan]Select Display Mode:[/]")
    console.print("   [bold white]1[/] = [#00ffff]W[/#00ffff] [#0099ff]I[/#0099ff] [#6666ff]R[/#6666ff] [#ff00ff]E[/#ff00ff] [#ff0099]R[/#ff0099] [#ff6666]U[/#ff6666] [#ffaa00]N[/#ffaa00] [#ffff00]N[/#ffff00] [#00BB00]E[/#00BB00] [#00ffaa]R[/#00ffaa]")
    console.print("   [bold white]2[/] = [bold #00BB00]*COLD*WAR*MODE*[/]")
    console.print()
    console.print(" [bold cyan]Enter Choice:[/] ", end="")
    
    cold_war = False
    choice = input().strip()
    if choice == "2":
        cold_war = True
    
    console.clear()
    
    app = CybrWireApp(cold_war=cold_war, recency=recency)
    app.run()

if __name__ == "__main__":
    main()
