#!/usr/bin/env python3
import argparse
import asyncio
import time
import httpx
import logging
import re
import os
import sys
import textwrap
import webbrowser
from datetime import datetime, timedelta, timezone
from typing import Dict, Any
from rich.console import Console, Group
from rich.table import Table
from rich.text import Text
from rich.theme import Theme
from rich.panel import Panel
from rich import box
from collections import Counter
from enrichment import enrichment_engine, initialize_enrichment
import ai
from config import load_config
from feeds import MAX_TITLE_LEN, KEV_CATALOG, parse_json, parse_rss, parse_txt, fetch_doomsday_seconds
from incidents import build_incidents, age, KIND_LABELS, SEVERITY_RANK
from state import AppState, alert_key
from textual.app import App, Screen, ComposeResult
from textual.widgets import Static, Header
from textual.containers import Container, Horizontal, VerticalScroll
from textual.reactive import reactive
from textual import events

# Log to a file - writing to stderr would draw over the TUI
logging.basicConfig(
    level=logging.WARNING,
    format='%(asctime)s %(levelname)s %(name)s: %(message)s',
    filename=os.path.join(os.path.dirname(os.path.abspath(__file__)), "cybrwire.log"),
)
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

HEADERS = {"User-Agent": "C Y B R W I R E // v1.0 LEGENDARY EDITION"}
HEAT_BAR_WIDTH = 33
REFRESH_INTERVAL = 300
DOOMSDAY_DEFAULT_SECONDS = 85  # Setting announced January 2026; refreshed from thebulletin.org at runtime
DOOMSDAY_CHECK_INTERVAL = timedelta(days=1)
FEED_TIMEOUT = 15          # Seconds before giving up on a single feed
MAX_CONCURRENT_FEEDS = 8   # Higher values can overwhelm local DNS resolvers

CONFIG = load_config()
STATE = AppState()


# Global state
alert_queue = []
breach_list = []
source_file_stats = {"curated": 0, "custom": 0, "community": 0}
failed_feeds = {}  # Tracks current cycle failures: {feed_name: (error_msg, failure_count)}
disabled_feeds = {}  # Tracks disabled feeds: {feed_name: (error_msg, disable_reason)}
currently_loading = None
incidents_cache = []
start_time = datetime.now(timezone.utc)
ticker_offset = 0

IOC_TITLE_PREFIXES = ("TOP MALICIOUS IP", "MALWARE URL", "PHISHING URL")
RANSOM_VICTIM_RE = re.compile(r"^RANSOMWARE VICTIM: .* \(([^)]+)\)(?: \[([A-Z]{2})\])?")
COUNTRY_NAMES = {
    "US": "United States", "CA": "Canada", "GB": "United Kingdom", "DE": "Germany", "FR": "France",
    "IT": "Italy", "ES": "Spain", "NL": "Netherlands", "BE": "Belgium", "CH": "Switzerland", "AT": "Austria",
    "AU": "Australia", "BR": "Brazil", "MX": "Mexico", "IN": "India", "JP": "Japan", "KR": "South Korea",
    "TW": "Taiwan", "CN": "China", "SG": "Singapore", "ZA": "South Africa", "SE": "Sweden", "PL": "Poland",
}
force_event = asyncio.Event()
active_feed_source = "all"


async def fetch_breaches():
    """Fetch recent breaches from HaveIBeenPwned"""
    global breach_list
    try:
        async with httpx.AsyncClient(headers={"User-Agent": "CybrWire"}, timeout=10) as c:
            r = await c.get("https://haveibeenpwned.com/api/v3/breaches")
            breaches = r.json()
            # Get the 7 most recently added breaches (sorted by AddedDate, not BreachDate)
            breach_list = sorted(breaches, key=lambda x: x.get("AddedDate", ""), reverse=True)[:7]
    except Exception as e:
        logging.error(f"Failed to fetch breaches: {e}")

class HelpScreen(Screen):
    """Comprehensive help screen with scrollable content"""
    
    BINDINGS = [
        ("escape", "close_help", "Close"),
        ("q", "close_help", "Quit"),
    ]
    
    def __init__(self, cold_war_mode=False):
        super().__init__()
        self.cold_war_mode = cold_war_mode
    
    def compose(self) -> ComposeResult:
        yield ScrollableContainer(Static(id="help-content"))
    
    def on_mount(self) -> None:
        self.update_help()
    
    def action_close_help(self) -> None:
        """Close the help screen"""
        self.app.pop_screen()
    
    def update_help(self):
        """Update help content display"""
        help_text = Text()
        color = "#00ff00" if self.cold_war_mode else "#55bbdd"
        accent = "#00ff00" if self.cold_war_mode else "#9966ff"
        critical = "#dd4444"
        
        # Header
        help_text.append("\n", style=color)
        help_text.append("═" * 100 + "\n", style=color)
        help_text.append(" " * 30 + "C Y B R W I R E  1.0  H E L P  S C R E E N\n", style=f"bold {color}")
        help_text.append("═" * 100 + "\n\n", style=color)
        help_text.append("Press ESC or 'Q' to close help\n\n", style="dim yellow")
        
        # NAVIGATION & CONTROLS
        help_text.append("┌─ NAVIGATION & CONTROLS " + "─" * 72 + "┐\n", style=accent)
        help_text.append("│\n", style=accent)
        help_text.append("│  [GENERAL]\n", style=f"bold {accent}")
        help_text.append("│    ↑/↓           Select an alert or incident (the alert preview shows its summary)\n", style=color)
        help_text.append("│    Click         Select a row; click it again to open it\n", style=color)
        help_text.append("│    ← →           Change pages in paginated views (Feed, Incidents, War Room)\n", style=color)
        help_text.append("│    Enter         Open the selected alert (or an incident's latest report) in your browser\n", style=color)
        help_text.append("│    A             Explain the selected alert with AI (shown in the preview pane)\n", style=color)
        help_text.append("│    Tab           Switch between left panel (alerts) and right panel (dashboard)\n", style=color)
        help_text.append("│    V             Toggle between Alerts, Incidents, and API Tools views\n", style=color)
        help_text.append("│\n", style=accent)
        help_text.append("│  [VIEW PANELS]\n", style=f"bold {accent}")
        help_text.append("│    V             Cycle through focused dashboard panels:\n", style=color)
        help_text.append("│                  0 = Dashboard metrics\n", style=color)
        help_text.append("│                  1 = War Room (AI briefing + local keyword analysis)\n", style=color)
        help_text.append("│                  2 = Feed Status (Failed/Disabled Feeds)\n", style=color)
        help_text.append("│\n", style=accent)
        help_text.append("└" + "─" * 98 + "┘\n\n", style=accent)
        
        # DATA FILTERING & SOURCES
        help_text.append("┌─ DATA FILTERING & SOURCE MANAGEMENT " + "─" * 58 + "┐\n", style=accent)
        help_text.append("│\n", style=accent)
        help_text.append("│  [TIME WINDOWS] (Press 'D' to cycle)\n", style=f"bold {accent}")
        help_text.append("│    24h (default) - Last 24 hours of alerts\n", style=color)
        help_text.append("│    48h           - Last 48 hours (2 days) of alerts\n", style=color)
        help_text.append("│    7d            - Last 7 days of alerts (includes older IOCs)\n", style=color)
        help_text.append("│\n", style=accent)
        help_text.append("│  [ALERT TYPE FILTER] (Press 'F' to cycle)\n", style=f"bold {accent}")
        help_text.append("│    All           - Both alerts AND blog posts\n", style=color)
        help_text.append("│    Alerts        - Critical/structured threat data only (excludes informational)\n", style=color)
        help_text.append("│    Posts         - Blog posts and advisories only\n", style=color)
        help_text.append("│\n", style=accent)
        help_text.append("│  [FEED SOURCES] (Press '4' to cycle)\n", style=f"bold {accent}")
        help_text.append("│    Curated       - Hand-selected threat intelligence (premium quality)\n", style=color)
        help_text.append("│    Custom        - User-configured feeds\n", style=color)
        help_text.append("│    Community     - Open-source and community feeds\n", style=color)
        help_text.append("│    All (default) - All sources combined\n", style=color)
        help_text.append("│\n", style=accent)
        help_text.append("│  [FEED MANAGEMENT] (Press 'E' to re-enable)\n", style=f"bold {accent}")
        help_text.append("│    Auto-Disable  - Feeds that fail 7 consecutive times are auto-disabled\n", style=color)
        help_text.append("│    Re-enable     - Press 'E' to re-enable all disabled feeds at once\n", style=color)
        help_text.append("│    Feed Status   - Tab to dashboard, then V to reach the Feed Status panel\n", style=color)
        help_text.append("│\n", style=accent)
        help_text.append("└" + "─" * 98 + "┘\n\n", style=accent)
        
        # METRICS BAR EXPLANATION
        help_text.append("┌─ METRICS DASHBOARD (Left Side Metrics) " + "─" * 53 + "┐\n", style=accent)
        help_text.append("│\n", style=accent)
        help_text.append("│  [KEY METRICS]\n", style=f"bold {accent}")
        help_text.append("│    Total Alerts      - Combined count of all alerts across time window and filters\n", style=color)
        help_text.append("│    Critical/KEV      - CVEs in CISA's Known Exploited Vulnerabilities catalog\n", style=color)
        help_text.append("│    Zero-Day          - Previously unknown vulnerabilities with no public patch\n", style=color)
        help_text.append("│    Ransomware        - Ransomware families and related incidents\n", style=color)
        help_text.append("│    APT Activity      - Advanced Persistent Threat (nation-state) campaigns\n", style=color)
        help_text.append("│    Exploits/POC      - Public exploits or proof-of-concept code released\n", style=color)
        help_text.append("│    IOCs Detected     - IP addresses, file hashes, or suspicious domains\n", style=color)
        help_text.append("│    Incoming (1h)     - New alerts arriving in the last 60 minutes\n", style=color)
        help_text.append("│    Avg/Hour          - Average alerts per hour across the data window\n", style=color)
        help_text.append("│\n", style=accent)
        help_text.append("│  [HEAT LEVELS]\n", style=f"bold {accent}")
        help_text.append("│    Heat Level        - % of total alerts that are high-threat (critical+severe)\n", style=color)
        help_text.append("│    Ransomware Heat   - % of ransomware threats (rising = ransomware wave)\n", style=color)
        help_text.append("│    APT Heat          - % of APT activity (rising = targeted campaigns)\n", style=color)
        help_text.append("│    Zero-Day Heat     - % of zero-day vulns (rising = day-zero activity spike)\n", style=color)
        help_text.append("│    Exploit Heat      - % with public exploits (rising = mass exploitation risk)\n", style=color)
        help_text.append("│\n", style=accent)
        help_text.append("│  [THREAT SCORING]\n", style=f"bold {accent}")
        help_text.append("│    Cyber DEFCON      - Overall threat level (1=CRITICAL, 5=SAFE)\n", style=color)
        help_text.append("│                        Weighted: Zero-days(5x) + Critical(4x) + Ransomware/APT(3x) + Exploits(2x)\n", style=color)
        help_text.append("│    Doomsday Clock    - Bulletin of the Atomic Scientists setting, checked daily\n", style=color)
        help_text.append("│\n", style=accent)
        help_text.append("└" + "─" * 98 + "┘\n\n", style=accent)
        
        # SOURCES BAR EXPLANATION
        help_text.append("┌─ TOP SOURCES BREAKDOWN (Right Side) " + "─" * 58 + "┐\n", style=accent)
        help_text.append("│\n", style=accent)
        help_text.append("│  [SOURCE SELECTION]\n", style=f"bold {accent}")
        help_text.append("│    ● (filled dot)    - Currently selected source\n", style=color)
        help_text.append("│    ○ (empty circle)  - Unselected source (shows %% even if not selected)\n", style=color)
        help_text.append("│\n", style=accent)
        help_text.append("│  [SOURCE BREAKDOWN]\n", style=f"bold {accent}")
        help_text.append("│    Curated %         - % of alerts from curated (premium) feeds\n", style=color)
        help_text.append("│    Custom %          - % of alerts from user-configured feeds\n", style=color)
        help_text.append("│    Community %       - % of alerts from open-source community feeds\n", style=color)
        help_text.append("│\n", style=accent)
        help_text.append("│  [SOURCE LOGIC]\n", style=f"bold {accent}")
        help_text.append("│    Press '4' to cycle between 'All' and individual source filters\n", style=color)
        help_text.append("│    When filtered to one source, only that source's alerts display\n", style=color)
        help_text.append("│    The percentages update dynamically based on filtered data\n", style=color)
        help_text.append("│\n", style=accent)
        help_text.append("└" + "─" * 98 + "┘\n\n", style=accent)
        
        # THREAT ANALYSIS (WAR ROOM)
        help_text.append("┌─ WAR ROOM: AI THREAT BRIEFING " + "─" * 62 + "┐\n", style=accent)
        help_text.append("│\n", style=accent)
        help_text.append("│  [WHAT IT IS]\n", style=f"bold {accent}")
        help_text.append("│    A briefing written by your chosen AI provider from the alerts in the current window:\n", style=color)
        help_text.append("│    bottom line, priority actions, active threats, notable vulnerabilities, watch list\n", style=color)
        help_text.append("│    Below it, a local keyword analysis (top CVEs, software, actors, sectors) that needs no AI\n", style=color)
        help_text.append("│\n", style=accent)
        help_text.append("│  [HOW TO USE]\n", style=f"bold {accent}")
        help_text.append("│    G             Generate or refresh the briefing (also jumps to the War Room panel)\n", style=color)
        help_text.append("│    Tab, then V   Reach the War Room panel manually; ← → to page through it\n", style=color)
        help_text.append("│\n", style=accent)
        help_text.append("│  [PROVIDERS] (ai: section of cybrwire_local.yaml)\n", style=f"bold {accent}")
        help_text.append("│    anthropic, gemini, openai, openrouter, ollama (local), openai_compatible\n", style=color)
        help_text.append("│    Older configs with only enrichment.gemini_api_key keep working\n", style=color)
        help_text.append("│\n", style=accent)
        help_text.append("└" + "─" * 98 + "┘\n\n", style=accent)
        
        # API TOOLS & ENRICHMENT
        help_text.append("┌─ API TOOLS: IOC ENRICHMENT " + "─" * 66 + "┐\n", style=accent)
        help_text.append("│\n", style=accent)
        help_text.append("│  [AVAILABLE PROVIDERS]\n", style=f"bold {accent}")
        help_text.append("│    AbuseIPDB        - IP reputation and abuse history\n", style=color)
        help_text.append("│    VirusTotal       - Hash analysis, URL scanning, domain intelligence\n", style=color)
        help_text.append("│    Pulsedive        - Threat intel on IPs, domains, hashes, URLs\n", style=color)
        help_text.append("│    Abuse.ch         - Malware hash and phishing URL databases\n", style=color)
        help_text.append("│\n", style=accent)
        help_text.append("│  [HOW TO USE]\n", style=f"bold {accent}")
        help_text.append("│    Press 'V' to switch to API Tools view\n", style=color)
        help_text.append("│    Type indicator: IP address, file hash (MD5/SHA1/SHA256), domain, or URL\n", style=color)
        help_text.append("│    Press Enter to submit query (Ctrl+Shift+V pastes)\n", style=color)
        help_text.append("│    Results show threat intel from configured providers\n", style=color)
        help_text.append("│\n", style=accent)
        help_text.append("│  [CONFIGURATION]\n", style=f"bold {accent}")
        help_text.append("│    Production: Add API keys to usrwire.yaml (enrichment section)\n", style=color)
        help_text.append("│    Local Dev: Add API keys to cybrwire_local.yaml (enrichment section)\n", style=color)
        help_text.append("│    Free tier accounts have limited indicator coverage\n", style=color)
        help_text.append("│\n", style=accent)
        help_text.append("└" + "─" * 98 + "┘\n\n", style=accent)
        
        # INCIDENTS & DETAIL VIEW
        help_text.append("┌─ INCIDENTS & DETAIL VIEW " + "─" * 68 + "┐\n", style=accent)
        help_text.append("│\n", style=accent)
        help_text.append("│  Press 'V' to toggle between Alerts, Incidents, and API Tools views\n", style=color)
        help_text.append("│\n", style=accent)
        help_text.append("│  [WHEN AN INCIDENT IS CREATED]\n", style=f"bold {accent}")
        help_text.append("│    The same CVE, IP or file hash is reported by two or more different sources,\n", style=color)
        help_text.append("│    or a named threat actor / ransomware group appears in two or more alerts\n", style=color)
        help_text.append("│\n", style=accent)
        help_text.append("│  [WHAT EACH INCIDENT SHOWS]\n", style=f"bold {accent}")
        help_text.append("│    Header           Severity, indicator, CISA KEV status, source and alert counts\n", style=color)
        help_text.append("│    Headline         The most descriptive alert title\n", style=color)
        help_text.append("│    What             KEV description or the most detailed summary available\n", style=color)
        help_text.append("│    Why grouped      Which sources reported the indicator\n", style=color)
        help_text.append("│    Timeline         When it was first and most recently reported, and by whom\n", style=color)
        help_text.append("│    Related          Other incidents that share alerts with this one\n", style=color)
        help_text.append("│    • lines          The two most recent alerts\n", style=color)
        help_text.append("│\n", style=accent)
        help_text.append("└" + "─" * 98 + "┘\n\n", style=accent)
        
        # DISPLAY MODES
        help_text.append("┌─ DISPLAY MODES " + "─" * 80 + "┐\n", style=accent)
        help_text.append("│\n", style=accent)
        help_text.append("│  [NORMAL MODE] (default)\n", style=f"bold {accent}")
        help_text.append("│    Colorful display with theme cycling (press 'T')\n", style=color)
        help_text.append("│    Themes: textual-ansi, textual-dark, textual-light, nord, gruvbox, monokai, etc\n", style=color)
        help_text.append("│\n", style=accent)
        help_text.append("│  [COLD WAR MODE] (Press 'C' to toggle)\n", style=f"bold {accent}")
        help_text.append("│    Classic green-on-black terminal aesthetic (Matrix-style)\n", style=color)
        help_text.append("│    All text changes to pure #00FF00 green\n", style=color)
        help_text.append("│    Eliminates color variations - focuses on content\n", style=color)
        help_text.append("│\n", style=accent)
        help_text.append("└" + "─" * 98 + "┘\n\n", style=accent)
        
        # KEYBOARD SHORTCUTS
        help_text.append("┌─ ALL KEYBOARD SHORTCUTS " + "─" * 70 + "┐\n", style=accent)
        help_text.append("│\n", style=accent)
        help_text.append("│  R              Force Refresh - Fetch alerts immediately (don't wait for timer)\n", style=color)
        help_text.append("│  D              Cycle Data Age - Switch between 24h / 48h / 7d windows\n", style=color)
        help_text.append("│  F              Cycle Alert Type - Switch between All / Alerts / Posts\n", style=color)
        help_text.append("│  4              Cycle Feed Source - Switch between Curated / Custom / Community / All\n", style=color)
        help_text.append("│  Tab            Switch Panel Focus - Toggle between left and right panels\n", style=color)
        help_text.append("│  V              Toggle View in Focused Panel - Switch between Alerts / Incidents / API Tools\n", style=color)
        help_text.append("│  E              Re-enable Feeds - Re-enable all auto-disabled feeds\n", style=color)
        help_text.append("│  C              Toggle Cold War Mode - Switch between colorful and green-only\n", style=color)
        help_text.append("│  G              AI Briefing - Generate a fresh briefing in the War Room\n", style=color)
        help_text.append("│  A              Explain Alert - AI explanation of the selected alert\n", style=color)
        help_text.append("│  T              Cycle Theme - Switch color themes (normal mode only)\n", style=color)
        help_text.append("│  H              Show This Help - Display help screen\n", style=color)
        help_text.append("│  Q / Esc        Quit / Close Help - Exit application or close help screen\n", style=color)
        help_text.append("│\n", style=accent)
        help_text.append("└" + "─" * 98 + "┘\n\n", style=accent)
        
        # TIPS & FEATURES
        help_text.append("┌─ TIPS & FEATURES " + "─" * 77 + "┐\n", style=accent)
        help_text.append("│\n", style=accent)
        help_text.append("│  PAGINATION        - Most views support pagination with ← → arrow keys\n", style=color)
        help_text.append("│  INCIDENTS VIEW    - Correlates alerts by CVE, IP, hash and threat actor\n", style=color)
        help_text.append("│  LIVE TICKER       - Shows critical threats scrolling at the top (updates live)\n", style=color)
        help_text.append("│  BREACH DATABASE   - Shows latest data breaches from Have I Been Pwned (HIBP)\n", style=color)
        help_text.append("│  VELOCITY TRACKING - Compares alerts in the last 24h with the 24h before\n", style=color)
        help_text.append("│  ATTACK VECTORS    - Identifies most common attack methods in current data\n", style=color)
        help_text.append("│  RANSOMWARE HOTSPOT- Most-hit victim country and group (Ransomware.live)\n", style=color)
        help_text.append("│  NEW BADGES        - Alerts first seen since your last launch, until you open them\n", style=color)
        help_text.append("│  SAVED SETTINGS    - Theme, filters and modes persist; run with --setup to re-pick\n", style=color)
        help_text.append("│\n", style=accent)
        help_text.append("│  PRO TIP: Use keyboard shortcuts to quickly switch between filters and views\n", style="bold yellow")
        help_text.append("│           Example: D (switch time) → F (filter) → V (view) → Tab (Switch Panel Focus)\n", style="dim yellow")
        help_text.append("│\n", style=accent)
        help_text.append("└" + "─" * 98 + "┘\n\n", style=accent)
        
        # Footer
        help_text.append("═" * 100 + "\n", style=color)
        help_text.append("Press ESC or 'Q' to close  |  Scroll with Space/Page Down  |  More: https://github.com/QIO1984\n", style="dim white")
        help_text.append("═" * 100 + "\n", style=color)
        
        # Update the static widget
        try:
            content_widget = self.query_one("#help-content", Static)
            content_widget.update(help_text)
        except Exception:
            pass

class ScrollableContainer(Container):
    """Scrollable container for help screen"""
    
    DEFAULT_CSS = """
    ScrollableContainer {
        background: black;
        height: 100%;
        overflow-y: auto;
    }
    """

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
            "CHECKING APIS...",
            "CONNECTIONS ESTABLISHED...",
            "PULLING LATEST...",
            "GENERATING ALERTS...",
            "STAND BY..."
        ]
        self.feed_spinner = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        self.completed_messages = []  # Track completed messages for stacking
        self.configured_apis = CONFIG.configured_api_names  # Shown under "CHECKING APIS..."
    
    def compose(self) -> ComposeResult:
        yield Static(id="loading-content")
    
    def on_mount(self) -> None:
        self.update_loading()
        self.set_interval(1.0, self.animate_loading)
    
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
        
        # Build stacked messages - completed messages stay static, current message blinks
        message_lines = []
        
        for i, msg in enumerate(self.messages[:self.loading_step]):
            message_lines.append(f"[bold #00FF00]  {msg}[/]")
            # If this is the "CHECKING APIS..." message and we have APIs, show them on the next line
            if i == 2 and self.configured_apis:  # Index 2 is "CHECKING APIS..."
                apis_str = " • ".join(self.configured_apis)
                message_lines.append(f"[bold #00FF00]    → {apis_str}[/]")
        
        if self.loading_step < len(self.messages):
            current_msg = self.messages[self.loading_step]
            if self.loading_step == len(self.messages) - 1:
                spinner = self.feed_spinner[self.feed_animation_step]
                global currently_loading
                feed_name = currently_loading if currently_loading else "INITIALIZING"
                if self.feed_animation_step % 2 == 0:
                    message_lines.append(f"[bold #00FF00]{spinner} {current_msg} - {feed_name[:40]}[/]")
                else:
                    message_lines.append(f"[dim #006600]{spinner} {current_msg} - {feed_name[:40]}[/]")
            else:
                if self.feed_animation_step % 2 == 0:
                    message_lines.append(f"[bold #00FF00]{current_msg}[/]")
                else:
                    message_lines.append(f"[dim #006600]{current_msg}[/]")
                if current_msg == "CHECKING APIS..." and self.configured_apis:
                    apis_str = " • ".join(self.configured_apis)
                    message_lines.append(f"[bold #00FF00]    → {apis_str}[/]")
        
        messages_text = "\n".join(message_lines) if message_lines else ""
        
        # Build content - ASCII art + stacked messages
        content = f"{art_text}\n\n{messages_text}"
        self.query_one("#loading-content", Static).update(content)

class StyledHeader(Header):
    """Custom header that supports cold war mode styling"""
    def render(self) -> str:
        app = self.app
        header_str = super().render()
        # If app has cold_war_mode, we'll style it via the watcher instead
        return header_str

class CybrWireFooter(Static):
    """Custom footer that shows dynamic state indicators for data age and filter type"""
    
    def render(self) -> Text:
        """Build and render footer text with dynamic state indicators"""
        app = self.app
        
        # Get current state strings
        time_windows = ["24h", "48h", "7d"]
        filter_types = ["All", "Alerts", "Posts"]
        
        data_age_label = time_windows[app.data_age_index]
        filter_label = filter_types[app.filter_type_index]
        
        # Count alerts for the current filter
        now = datetime.now(timezone.utc)
        cutoff_time = now - timedelta(hours=app.recency_hours)
        time_filtered = [a for a in alert_queue if a.get("ts", now) >= cutoff_time]
        
        # Apply content filter to get count
        if app.filter_type_index == 1:  # alerts only
            count = len([a for a in time_filtered if a["severity"] != "info"])
        elif app.filter_type_index == 2:  # posts only
            count = len([a for a in time_filtered if a["severity"] == "info"])
        else:  # all
            count = len(time_filtered)
        
        # Build custom footer text with proper styling
        footer_text = Text()
        
        # Determine color based on cold war mode
        key_color = "bold #00ff00" if app.cold_war_mode else "bold yellow"
        desc_color = "#00ff00" if app.cold_war_mode else "#55bbdd"
        
        # Force Refresh
        footer_text.append("r ", style=key_color)
        footer_text.append("Refresh  ", style=desc_color)
        
        # Data Age with value
        footer_text.append("d ", style=key_color)
        footer_text.append(f"Data Age: {data_age_label}  ", style=desc_color)
        
        # Filter with type and count
        footer_text.append("f filter ", style=key_color)
        footer_text.append(f"{filter_label} - ({count})  ", style=desc_color)
        
        # Cycle Feeds
        footer_text.append("4 ", style=key_color)
        footer_text.append("Feeds  ", style=desc_color)
        
        # Switch Panel
        footer_text.append("tab ", style=key_color)
        footer_text.append("Switch Panel  ", style=desc_color)
        
        # Toggle View
        footer_text.append("v ", style=key_color)
        footer_text.append("View  ", style=desc_color)
        
        # Cold War Mode
        footer_text.append("c ", style=key_color)
        footer_text.append("CW Mode  ", style=desc_color)
        
        # Cycle Theme
        footer_text.append("t ", style=key_color)
        footer_text.append("Background  ", style=desc_color)
        
        # Help
        footer_text.append("h ", style=key_color)
        footer_text.append("Help  ", style=desc_color)
        
        # Quit
        footer_text.append("q ", style=key_color)
        footer_text.append("Quit", style=desc_color)
        
        return footer_text

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
        color: #00FF00;
    }
    
    CybrWireFooter {
        background: $boost;
        color: $text;
        height: 1;
    }
    
    .cold-war CybrWireFooter {
        background: $boost;
        color: #00ff00;
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
    
    TITLE = " C Y B R W I R E // v1.0 LEGENDARY EDITION "
    
    BINDINGS = [
        ("r", "refresh", "Force Refresh"),
        ("d", "cycle_data_age", "Data Age"),
        ("f", "cycle_filter_type", "Alert Type"),
        ("4", "cycle_feeds", "Cycle Feeds"),
        ("tab", "toggle_panel_focus", "Switch Panel"),
        ("v", "toggle_view", "Toggle View"),
        ("e", "re_enable_feeds", "Re-enable Feeds"),
        ("c", "toggle_cold_war", "Cold War Mode"),
        ("g", "ai_refresh", "AI Briefing"),
        ("t", "cycle_theme", "Cycle Theme"),
        ("h", "show_help", "Help"),
        ("q", "quit", "Quit"),
    ]
    
    recency_hours = reactive(24)
    cold_war_mode = reactive(False)
    next_refresh = reactive(datetime.now(timezone.utc))
    is_loading = reactive(True)
    feed_page_offset = reactive(0)  # Pagination for alerts feed panel
    incident_page_offset = reactive(0)  # Pagination for incidents panel
    dashboard_page_offset = reactive(0)  # Pagination for dashboard panel
    panel_focus = reactive("main")  # "main" or "dashboard" - which panel gets paged by arrows
    hover_row = reactive(-1)
    filter_mode = reactive("all")  # all, alerts, posts
    theme_mode = reactive("default")  # default, dark, blue, purple, matrix
    feed_source_index = reactive(0)  # Cycle: 0=all, 1=curated, 2=custom, 3=community
    data_age_index = reactive(0)  # Cycle: 0=24h, 1=48h, 2=7d
    filter_type_index = reactive(0)  # Cycle: 0=all, 1=alerts, 2=posts
    dashboard_panel_index = reactive(0)  # Cycle dashboard: 0=metrics, 1=failed feeds
    main_view_mode = reactive("alerts")  # alerts, incidents, or api_tools
    
    def __init__(self, cold_war=False, recency=24):
        super().__init__()
        self._initializing = True
        saved = STATE.settings
        self.cold_war_mode = cold_war
        self.recency_hours = recency
        self.data_age_index = {24: 0, 48: 1, 168: 2}.get(recency, 0)
        self.refresher_task = None
        self.alert_urls = []
        self.page_alerts = []  # Alerts shown on the current feed page, in row order
        self.breach_urls = []
        self.feed_page_offset = 0
        self.incident_page_offset = 0
        self.hover_row = -1
        self.rows_per_page = 20
        self.theme_mode = saved.get("theme", "textual-ansi")
        self.filter_type_index = saved.get("filter_type_index", 0)
        self.filter_mode = ["all", "alerts", "posts"][self.filter_type_index]
        self.feed_source_index = saved.get("feed_source_index", 0)
        global active_feed_source
        active_feed_source = ["all", "curated", "custom", "community"][self.feed_source_index]
        
        self.feed_failure_counts = {}  # Track consecutive failures per feed
        
        # Redraw only when something changed (data, keys, mouse, timers)
        self.dirty = True
        self.last_full_render = 0.0
        
        # Incidents for the current data window, rebuilt only when inputs change
        self.incidents = []
        self.incidents_key = None
        self.incident_rows = []  # (incident, first line, last line) for the current page
        
        # Threat summary (local keyword analysis) shown under the AI briefing
        self.threat_summary = None
        self.threat_summary_full = ""
        self.threat_summary_timestamp = None
        self.threat_summary_loading = False
        self.threat_summary_pages = []  # Paginated content
        self.threat_summary_page = 0  # Current page
        
        # AI analysis (any configured provider)
        self.ai_settings = CONFIG.ai
        self.ai_problem = ai.configuration_problem(self.ai_settings)
        self.ai_briefing = None
        self.ai_briefing_time = None
        self.ai_briefing_error = None
        self.ai_briefing_loading = False
        self.alert_explanations = {}  # alert key -> AI explanation text (or error)
        self.explaining = set()       # alert keys with a request in flight
        
        # Doomsday Clock (seconds to midnight), refreshed from thebulletin.org daily
        self.doomsday_seconds = STATE.doomsday.get("seconds", DOOMSDAY_DEFAULT_SECONDS)
        
        # Initialize API Tools panel state
        self.api_tools_input_buffer = ""  # User input for IOC query
        self.api_tools_last_query = ""  # Last queried indicator
        self.api_tools_last_results = {}  # Results from all providers {provider: EnrichmentData}
        self.api_tools_loading = False  # Is query in progress
        self.api_tools_input_mode = True  # Always in input mode in this panel
        
        # Set footer color based on cold war mode
        self.footer_color = "#00FF00" if self.cold_war_mode else "#55bbdd"
        
        # Initialize next refresh time
        self.next_refresh = datetime.now(timezone.utc) + timedelta(seconds=REFRESH_INTERVAL)
        
        if self.cold_war_mode:
            self.add_class("cold-war")
        
        self._initializing = False  # Allow watchers to work now
    
    def save_settings(self):
        """Persist UI choices so the next launch starts the same way"""
        STATE.settings = {
            "recency_hours": self.recency_hours,
            "cold_war": self.cold_war_mode,
            "theme": self.theme_mode,
            "filter_type_index": self.filter_type_index,
            "feed_source_index": self.feed_source_index,
        }
        STATE.save()
    
    def mark_dirty(self):
        """Schedule a redraw on the next render tick"""
        self.dirty = True
    
    def analyze_top_cves(self, alerts):
        """Extract and rank top 10 CVEs by frequency"""
        import re
        cve_counts = {}
        for alert in alerts:
            title = alert.get('title', '').upper()
            matches = re.findall(r'CVE-\d{4}-\d{4,5}', title)
            for cve in matches:
                cve_counts[cve] = cve_counts.get(cve, 0) + 1
        
        return sorted(cve_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    
    def analyze_threat_actors(self, alerts):
        """Extract threat actor names from alert titles with improved accuracy"""
        import re
        threat_actors = {}
        
        # Real threat actor patterns with word boundaries to prevent false matches
        actor_patterns = [
            r'\bAPT\d+\b', r'\bFIN\d+\b', r'\bHAFNIUM\b', r'\bWIZARD SPIDER\b', 
            r'\bLAZARUS\b', r'\bCARBANAK\b', r'\bEMOTET\b', r'\bCONTI\b', r'\bLOCKBIT\b',
            r'\bBLACKCAT\b', r'\bALPHV\b', r'\bPLAY\b', r'\bCLOP\b', r'\bSCATTERED SPIDER\b',
            r'\bGAMAREDON\b', r'\bSANDWORM\b', r'\bFANCY BEAR\b', r'\bCOZY BEAR\b',
            r'\bTURLA\b', r'\bEQUATION GROUP\b'
        ]
        
        # Framework/taxonomy keywords to exclude (false positives)
        exclude_keywords = ['MITRE', 'TACTICS', 'TECHNIQUES', 'FRAMEWORK', 'MATRIX', 'ATT&CK']
        
        for alert in alerts:
            title = alert.get('title', '').upper()
            
            # Skip alerts that mention framework/taxonomy references
            if any(keyword in title for keyword in exclude_keywords):
                continue
            
            for pattern in actor_patterns:
                matches = re.findall(pattern, title, re.IGNORECASE)
                for match in matches:
                    actor_key = match.upper()
                    threat_actors[actor_key] = threat_actors.get(actor_key, 0) + 1
        
        return sorted(threat_actors.items(), key=lambda x: x[1], reverse=True)[:10]
    
    def analyze_attack_surface(self, alerts):
        """Parse alert titles for affected software/products"""
        software_keywords = {
            'Apache': ['APACHE', 'HTTP SERVER'],
            'Windows': ['WINDOWS', 'WIN32', 'SMB'],
            'Linux': ['LINUX', 'KERNEL'],
            'Exchange': ['EXCHANGE', 'OUTLOOK'],
            'Oracle': ['ORACLE', 'DATABASE'],
            'SQL Server': ['SQL SERVER', 'MSSQL'],
            'Adobe': ['ADOBE', 'PDF', 'ACROBAT'],
            'Chrome': ['CHROME', 'CHROMIUM'],
            'Firefox': ['FIREFOX', 'MOZILLA'],
            'SSH': ['SSH', 'OPENSSH'],
            'Kubernetes': ['KUBERNETES', 'K8S'],
            'Docker': ['DOCKER', 'CONTAINER'],
            'AWS': ['AWS', 'AMAZON'],
            'Azure': ['AZURE', 'MICROSOFT CLOUD'],
            'Jenkins': ['JENKINS', 'CI/CD'],
            'Nginx': ['NGINX', 'WEB SERVER'],
            'OpenSSL': ['OPENSSL', 'SSL/TLS'],
            'Java': ['JAVA', 'JVM'],
            'Python': ['PYTHON', 'PIP'],
            'Node.js': ['NODE', 'NODEJS'],
            'PHP': ['PHP', 'LARAVEL'],
            'WordPress': ['WORDPRESS', 'WP'],
            'Drupal': ['DRUPAL', 'CMS'],
            'Salesforce': ['SALESFORCE', 'CRMSYSTEM'],
            'SAP': ['SAP', 'ERP'],
            'Cisco': ['CISCO', 'NETWORKING'],
            'Fortinet': ['FORTINET', 'FORTIGATE'],
            'Palo Alto': ['PALO ALTO', 'FIREWALL'],
        }
        
        affected = {}
        for alert in alerts:
            title = alert.get('title', '').upper()
            for software, keywords in software_keywords.items():
                for keyword in keywords:
                    if keyword in title:
                        affected[software] = affected.get(software, 0) + 1
                        break
        
        return sorted(affected.items(), key=lambda x: x[1], reverse=True)[:15]
    
    def analyze_vulnerability_chains(self, alerts):
        """Detect potential CVE chains (multiple CVEs in 24h window)"""
        import re
        from collections import defaultdict
        
        chains = defaultdict(list)
        for alert in alerts:
            title = alert.get('title', '').upper()
            cves = re.findall(r'CVE-\d{4}-\d{4,5}', title)
            if len(cves) > 1:
                key = f"{len(cves)}-chain"
                chains[key].append((title[:60], cves))
        
        return list(chains.items())[:5]  # Top 5 chain types
    
    def analyze_exploit_maturity(self, alerts):
        """Track exploit progression from disclosure to weaponization"""
        maturity_stages = {
            'in-the-wild': [],
            'poc-available': [],
            'exploited': [],
            'active': [],
        }
        
        for alert in alerts:
            title = alert.get('title', '').upper()
            summary = alert.get('summary', '').upper()
            combined = f"{title} {summary}"
            
            if any(x in combined for x in ['IN-THE-WILD', 'IN THE WILD', 'WILD EXPLOITATION']):
                maturity_stages['in-the-wild'].append(alert)
            elif any(x in combined for x in ['POC', 'PROOF OF CONCEPT', 'EXPLOIT AVAILABLE']):
                maturity_stages['poc-available'].append(alert)
            elif any(x in combined for x in ['EXPLOITED', 'ACTIVE EXPLOITATION', 'ACTIVELY EXPLOITED']):
                maturity_stages['exploited'].append(alert)
            elif any(x in combined for x in ['ACTIVE', 'CRITICAL', 'URGENT']):
                maturity_stages['active'].append(alert)
        
        return {k: len(v) for k, v in maturity_stages.items()}
    
    def analyze_industry_targeting(self, alerts):
        """Detect industry/sector targeting patterns"""
        sectors = {
            'Healthcare': ['HEALTHCARE', 'HOSPITAL', 'MEDICAL', 'PHARMA', 'HEALTHCARE SECTOR'],
            'Finance': ['FINANCE', 'BANK', 'BANKING', 'FINTECH', 'CRYPTOCURRENCY'],
            'Manufacturing': ['MANUFACTURING', 'INDUSTRIAL', 'OT', 'SCADA', 'ICS'],
            'Government': ['GOVERNMENT', 'FEDERAL', 'AGENCY', 'DEFENSE', 'MILITARY'],
            'Education': ['EDUCATION', 'UNIVERSITY', 'SCHOOL', 'ACADEMIC'],
            'Retail': ['RETAIL', 'E-COMMERCE', 'SHOPPING', 'ONLINE STORE'],
            'Telecom': ['TELECOM', 'TELECOMMUNICATIONS', 'ISP', 'CARRIER'],
            'Energy': ['ENERGY', 'UTILITY', 'POWER', 'OIL', 'GAS'],
            'Transportation': ['TRANSPORTATION', 'AIRLINE', 'LOGISTICS', 'SHIPPING'],
            'Insurance': ['INSURANCE', 'UNDERWRITING'],
        }
        
        targeted = {}
        for alert in alerts:
            title = alert.get('title', '').upper()
            for sector, keywords in sectors.items():
                for keyword in keywords:
                    if keyword in title:
                        targeted[sector] = targeted.get(sector, 0) + 1
                        break
        
        return sorted(targeted.items(), key=lambda x: x[1], reverse=True) if targeted else [("General Targeting", len(alerts))]
    
    async def _load_threat_summary_async(self):
        """Build the local keyword analysis for the current data window"""
        if self.threat_summary_loading:
            return
        
        self.threat_summary_loading = True
        try:
            cutoff_time = datetime.now(timezone.utc) - timedelta(hours=self.recency_hours)
            window = [a for a in alert_queue if a['ts'] >= cutoff_time]
            top_alerts = [a for a in window if a.get('severity') in ['critical', 'zeroday', 'ransomware', 'apt', 'exploit', 'high', 'medium']][:10]
            
            if top_alerts:
                # Run all analysis methods to get comprehensive intelligence
                top_cves = self.analyze_top_cves(window)
                threat_actors = self.analyze_threat_actors(window)
                attack_surface = self.analyze_attack_surface(window)
                vuln_chains = self.analyze_vulnerability_chains(window)
                exploit_maturity = self.analyze_exploit_maturity(window)
                industry_targeting = self.analyze_industry_targeting(window)
                
                # Build combined analysis text - ordered for optimal pagination
                analysis_text = []
                analysis_text.append("LOCAL KEYWORD ANALYSIS")
                analysis_text.append("─" * 70)
                analysis_text.append("")
                
                analysis_text.append("TOP 10 CVEs (by frequency in alerts):")
                for i, (cve, count) in enumerate(top_cves, 1):
                    analysis_text.append(f"  {i}. {cve} [{count} alerts]")
                
                analysis_text.append("")
                analysis_text.append("AFFECTED SOFTWARE (Attack Surface):")
                for i, (software, count) in enumerate(attack_surface, 1):
                    analysis_text.append(f"  {i}. {software} [{count} CVEs/alerts]")
                
                analysis_text.append("")
                analysis_text.append("EXPLOIT MATURITY STATUS:")
                analysis_text.append(f"  In-The-Wild: {exploit_maturity['in-the-wild']} threats")
                analysis_text.append(f"  POC Available: {exploit_maturity['poc-available']} threats")
                analysis_text.append(f"  Actively Exploited: {exploit_maturity['exploited']} threats")
                analysis_text.append(f"  Active/Critical: {exploit_maturity['active']} threats")
                
                analysis_text.append("")
                analysis_text.append("VULNERABILITY CHAINS DETECTED:")
                if vuln_chains:
                    for chain_type, examples in vuln_chains:
                        analysis_text.append(f"  {chain_type}:")
                        for title, cves in examples[:2]:
                            analysis_text.append(f"    • {title}")
                            analysis_text.append(f"      CVEs: {', '.join(cves)}")
                else:
                    analysis_text.append("  No multi-CVE chains detected")
                
                analysis_text.append("")
                analysis_text.append("INDUSTRY/SECTOR TARGETING:")
                for sector, count in industry_targeting[:8]:
                    analysis_text.append(f"  • {sector}: {count} relevant alerts")
                
                analysis_text.append("")
                analysis_text.append("THREAT ACTORS DETECTED:")
                if threat_actors:
                    for i, (actor, count) in enumerate(threat_actors, 1):
                        analysis_text.append(f"  {i}. {actor} [{count} mentions]")
                else:
                    analysis_text.append("  No known threat actors detected in current alerts")
                
                analysis_text.append("")
                analysis_text.append(f"Total Alerts Analyzed: {len(window)} | High Priority: {len(top_alerts)}")
                analysis_text.append("─" * 70)
                
                self.threat_summary_full = "\n".join(analysis_text)
                self.threat_summary = "LOCAL KEYWORD ANALYSIS"
                self.threat_summary_timestamp = datetime.now(timezone.utc)
            else:
                self.threat_summary_full = "Waiting for threat data to arrive..."
                self.threat_summary = self.threat_summary_full
                self.threat_summary_timestamp = datetime.now(timezone.utc)
        except Exception as e:
            import traceback
            error_msg = f"Error: {str(e)}\n{traceback.format_exc()}"
            logging.error(error_msg)
            self.threat_summary = self.threat_summary_full = f"Error loading summary: {str(e)[:100]}"
            self.threat_summary_timestamp = datetime.now(timezone.utc)
        finally:
            self.threat_summary_loading = False
            self.mark_dirty()
    

    def watch_cold_war_mode(self, old_value, new_value):
        """Update footer color when cold war mode changes"""
        if getattr(self, '_initializing', False):
            return
        self.footer_color = "#00FF00" if new_value else "#55bbdd"
        if new_value:
            self.add_class("cold-war")
        else:
            self.remove_class("cold-war")
    
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
        self.apply_theme()
        self.push_screen(LoadingScreen(self.cold_war_mode))
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
            if not self.ai_problem:
                asyncio.create_task(self.generate_ai_briefing())
            asyncio.create_task(self.refresher())
            
            self.update_display()
            self.set_interval(1.0, self.render_tick)
            self.set_interval(0.7, self.animate_ticker)
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
        yield StyledHeader(show_clock=True)
        yield Static(id="ticker")
        
        # Always create both layouts, use CSS to control visibility
        with Horizontal(id="main-layout"):
            with VerticalScroll(id="feeds-container"):
                yield Static(id="feeds", expand=True)
            yield Static(id="dashboard", expand=True)
        
        yield CybrWireFooter()
    
    async def fetch_feeds(self):
        """Fetch data from all sources once"""
        global alert_queue, source_file_stats, failed_feeds, currently_loading
        
        new = []
        source_file_stats = {"curated": 0, "custom": 0, "community": 0}
        failed_feeds = {}

        all_sources = [s for s in CONFIG.sources if s['name'] not in disabled_feeds]
        parsers = {"json": lambda r, n, f: parse_json(r.json(), n, f),
                   "rss": lambda r, n, f: parse_rss(r.text, n, f),
                   "txt": lambda r, n, f: parse_txt(r.text, n, f)}
        semaphore = asyncio.Semaphore(MAX_CONCURRENT_FEEDS)

        async def fetch_one(c, src):
            global currently_loading
            async with semaphore:
                currently_loading = src['name']
                # Optional per-feed headers in YAML (e.g. API keys that must not go in the URL)
                r = await c.get(src["url"], headers=src.get("headers"))
                r.raise_for_status()
                # Parse in a thread so large feeds don't freeze the UI
                return await asyncio.to_thread(parsers[src["type"]], r, src['name'], src.get("source_file", "curated"))

        async with httpx.AsyncClient(headers=HEADERS, timeout=FEED_TIMEOUT, follow_redirects=True) as c:
            results = await asyncio.gather(*(fetch_one(c, src) for src in all_sources), return_exceptions=True)

        for src, result in zip(all_sources, results):
            src_name = src['name']
            if not isinstance(result, BaseException):
                self.feed_failure_counts.pop(src_name, None)  # Failures must be consecutive
                new.extend(result)
                source_file = src.get("source_file", "curated")
                source_file_stats[source_file] = source_file_stats.get(source_file, 0) + len(result)
                continue

            error_msg = str(result) or type(result).__name__
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
        
        alert_queue = sorted(
            [item for alerts in source_buckets.values() for item in alerts],
            key=lambda x: x.get("ts", datetime.min.replace(tzinfo=timezone.utc)),
            reverse=True
        )
        
        currently_loading = None  # Clear loading indicator
        
        STATE.record_alerts(alert_queue)
        STATE.save()
        self.incidents_key = None  # Rebuild incidents for the new data
        self.mark_dirty()
    
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
            self.next_refresh = datetime.now(timezone.utc) + timedelta(seconds=REFRESH_INTERVAL)
            self.mark_dirty()
    
    def update_display(self):
        """Update the UI display"""
        if self.is_loading:
            return
        
        self.dirty = False
        self.last_full_render = time.monotonic()
        try:
            self.ticker_core = self.make_ticker_core()
            self.animate_ticker(advance=False)
            
            # Update feeds table, incidents panel, or API tools (toggled with key v)
            feeds_widget = self.query_one("#feeds", Static)
            if self.main_view_mode == "alerts":
                feeds_content = self.make_feeds_table()
            elif self.main_view_mode == "incidents":
                feeds_content = self.make_incidents_panel()
            else:  # "api_tools"
                feeds_content = self.make_api_tools_panel()
            feeds_widget.update(feeds_content)
            # Force the widget to update its virtual size for scrolling
            feeds_widget.refresh(layout=True)
            
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
                    global failed_feeds, disabled_feeds
                    
                    is_focused = self.panel_focus == "dashboard"
                    
                    if not failed_feeds and not disabled_feeds:
                        if not self.cold_war_mode:
                            failed_msg = "✓ All feeds loaded successfully!"
                        else:
                            failed_msg = "[OK] All feeds loaded successfully!"
                        failed_style = "bold #00FF00" if not is_focused else "bold #000000 on #00FF00"
                        title_style = "#00FF00"
                        dashboard_content = Panel(
                            Text(failed_msg, style=failed_style),
                            title="FEED STATUS",
                            border_style=title_style,
                            padding=(1, 2)
                        )
                    else:
                        feeds_per_page = 8
                        
                        failed_list = sorted(failed_feeds.items())
                        disabled_list = sorted(disabled_feeds.items())
                        
                        total_feeds = len(failed_list) + len(disabled_list)
                        total_pages = (total_feeds + feeds_per_page - 1) // feeds_per_page
                        
                        self.dashboard_page_offset = max(0, min(self.dashboard_page_offset, total_pages - 1))
                        
                        start_idx = self.dashboard_page_offset * feeds_per_page
                        end_idx = start_idx + feeds_per_page
                        
                        failed_msg = ""
                        if not self.cold_war_mode:
                            failed_msg = "⚠ FAILED FEEDS:\n\n"
                        else:
                            failed_msg = "[ALERT] FAILED FEEDS:\n\n"
                        
                        current_idx = 0
                        for feed_name, (error_msg, failure_count) in failed_list:
                            if start_idx <= current_idx < end_idx:
                                error_short = error_msg[:50] + "..." if len(error_msg) > 50 else error_msg
                                failed_msg += f"• {feed_name} ({failure_count}/7)\n  {error_short}\n"
                            current_idx += 1
                        
                        if disabled_list and current_idx >= start_idx:
                            if any(start_idx <= current_idx + i < end_idx for i in range(len(disabled_list))):
                                failed_msg += "\n╶─ AUTOMATICALLY DISABLED FEEDS ─╴\n"
                                failed_msg += "Re-enable with 'e' on focused panel\n\n"
                        
                        for feed_name, (error_msg, reason) in disabled_list:
                            if start_idx <= current_idx < end_idx:
                                error_short = error_msg[:40] + "..." if len(error_msg) > 40 else error_msg
                                failed_msg += f"• {feed_name}\n  {reason}\n"
                            current_idx += 1
                        
                        if self.cold_war_mode:
                            title_style = "#00FF00"
                            text_color = "#00FF00"
                            border_color = "#00FF00"
                        else:
                            title_style = "#ff6666" if is_focused else "white"
                            text_color = "#ff6666"
                            border_color = "#ff6666" if is_focused else "white"
                        
                        failed_text = Text(failed_msg, style=text_color)
                        
                        if is_focused:
                            title_text = f"FEED STATUS - Page {self.dashboard_page_offset + 1}/{total_pages}"
                            title = Text(title_text, style=f"bold #000000 on {title_style}")
                        else:
                            title = "FEED STATUS"
                        
                        # Add pagination tip in subtitle if multiple pages
                        subtitle = None
                        if total_pages > 1:
                            subtitle_text = f"← → to change pages"
                            subtitle = Text(subtitle_text, style="bold #00ff00" if self.cold_war_mode else "bold cyan")
                        
                        dashboard_content = Panel(
                            failed_text,
                            title=title,
                            subtitle=subtitle,
                            border_style=border_color,
                            padding=(1, 2)
                        )
                else:
                    dashboard_content = self.make_dashboard()
                
                dashboard_widget.update(dashboard_content)
                dashboard_widget.refresh()
            except Exception as e:
                logging.error(f"Error updating dashboard: {e}")
                import traceback
                logging.error(traceback.format_exc())
            
        except Exception as e:
            logging.error(f"Error updating display: {e}")
            import traceback
            logging.error(traceback.format_exc())
    
    def animate_ticker(self, advance=True):
        """Scroll the ticker one step (only the ticker widget is redrawn)"""
        global ticker_offset
        if advance:
            ticker_offset += 1
        try:
            self.query_one("#ticker", Static).update(self.make_ticker())
        except Exception:
            pass
    
    def make_ticker_core(self):
        """Build the ticker text from current alerts (recomputed on redraw only)"""
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
        
        new_count = sum(1 for a in alert_queue if STATE.is_new(a))
        if new_count:
            ticker_parts.insert(0, f"{new_count} NEW since last visit")
        
        ticker_core = "  //  ".join(ticker_parts)
        return ticker_core or "--- NO CRITICAL THREATS DETECTED ---"
    
    def make_ticker(self):
        """Render the visible slice of the ticker at the current scroll offset"""
        core = getattr(self, "ticker_core", "") or "--- LOADING ---"
        loop = core + "   //   "
        offset = ticker_offset % len(loop)
        visible_text = (loop * 3)[offset:offset + max(self.size.width - 4, 10)]
        color = "#00ff00" if self.cold_war_mode else "#66cc66"
        return Panel(Text(visible_text, style=f"bold {color} on black"), title="LIVE THREAT TAPE",
                     border_style=color, padding=0)
    
    def is_alert(self, item):
        """Classify item as alert vs blog post"""
        # Simple rule: INFO = blog post, everything else = alert
        return item["severity"] != "info"
    
    PREVIEW_LINES = 8  # Lines reserved under the alert table for the selected-alert preview
    
    def filtered_alerts(self):
        """Alerts in the current time window, feed source and alert-type filter"""
        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=self.recency_hours)
        alerts = [a for a in alert_queue if a["ts"] >= cutoff_time]
        if active_feed_source != "all":
            alerts = [a for a in alerts if a.get("source_file") == active_feed_source]
        if self.filter_mode == "alerts":
            alerts = [a for a in alerts if self.is_alert(a)]
        elif self.filter_mode == "posts":
            alerts = [a for a in alerts if not self.is_alert(a)]
        return alerts
    
    def selected_alert(self):
        if 0 <= self.hover_row < len(self.page_alerts):
            return self.page_alerts[self.hover_row]
        return None
    
    def make_alert_preview(self, alert):
        """Detail pane for the highlighted alert"""
        accent = "#00ff00" if self.cold_war_mode else "#44ccaa"
        body = "#00ff00" if self.cold_war_mode else "#ccddee"
        dim = "#00aa00" if self.cold_war_mode else "#778899"
        text = Text()
        if not alert:
            text.append("Select an alert with ↑/↓ to see its summary here.", style=dim)
            return text
        
        text.append(alert["title"] + "\n", style=f"bold {accent}")
        text.append(f"{alert['source']}  •  {alert['ts']:%a %d %b %H:%M} UTC ({age(alert['ts'])} ago)  •  {alert['severity'].upper()}", style=dim)
        if STATE.is_new(alert):
            text.append("  •  NEW", style="bold #00ff00")
        text.append("\n")
        
        key = alert_key(alert)
        if key in self.alert_explanations:
            text.append("AI: " + self.alert_explanations[key].strip() + "\n", style="#ffcc66" if not self.cold_war_mode else body)
        elif key in self.explaining:
            text.append("AI: analyzing...\n", style="italic #ffcc66" if not self.cold_war_mode else body)
        else:
            text.append((alert.get("summary") or "No summary provided by this feed.") + "\n", style=body)
        
        if alert.get("url"):
            text.append(alert["url"] + "\n", style=f"underline {dim}")
        hint = "Enter open in browser"
        if not self.ai_problem and key not in self.alert_explanations:
            hint += "  •  a explain with AI"
        text.append(hint, style=f"italic {dim}")
        text.truncate(max(self.size.width, 40) * self.PREVIEW_LINES)
        return text
    
    def make_feeds_table(self):
        """Create feeds table with pagination and a preview of the selected alert"""
        try:
            available_height = max(10, self.query_one("#feeds-container").size.height - 6)
        except Exception:
            available_height = max(10, self.size.height - 12)
        self.rows_per_page = max(5, available_height - self.PREVIEW_LINES - 1)
        
        border = "#00FF00" if self.cold_war_mode else "#4499bb"
        table = Table(box=box.DOUBLE, show_header=False, padding=(0, 1), expand=True, border_style=border)
        narrow = self.size.width < 100
        table.add_column(width=3)                                    # NEW badge
        table.add_column(width=7 if narrow else 11, justify="right")  # published
        table.add_column(width=8 if narrow else 10)                   # severity
        table.add_column()                                            # title
        
        filtered_alerts = self.filtered_alerts()
        total_pages = max(1, (len(filtered_alerts) + self.rows_per_page - 1) // self.rows_per_page)
        self.feed_page_offset = max(0, min(self.feed_page_offset, (total_pages - 1) * self.rows_per_page))
        self.page_alerts = filtered_alerts[self.feed_page_offset:self.feed_page_offset + self.rows_per_page]
        self.alert_urls = [a.get("url", "") for a in self.page_alerts]
        self.hover_row = min(self.hover_row, len(self.page_alerts) - 1)
        
        severity_colors = {
            "critical": "bold white on #dd4444",
            "zeroday": "bold black on #e6d144",
            "ransomware": "bold black on #dd4488",
            "apt": "bold black on #b866cc",
            "exploit": "bold #dd5555",
            "info": "#55bbdd",
        }
        for row_idx, a in enumerate(self.page_alerts):
            if row_idx == self.hover_row:
                title_style = severity_style = date_style = "bold white on #004400" if self.cold_war_mode else "bold white on #333333"
            elif self.cold_war_mode:
                title_style = severity_style = date_style = "#00FF00"
            else:
                title_style = severity_style = severity_colors.get(a["severity"], "white")
                date_style = "#55bbdd"
            is_new = STATE.is_new(a)
            table.add_row(
                Text("NEW", style="bold black on #00ff00") if is_new else Text(""),
                Text(a["published"] if narrow else f"{a['published']} {age(a['ts']):>3}", style=date_style),
                Text(a["severity"].upper(), style=severity_style),
                Text(a["title"][:MAX_TITLE_LEN], style=title_style + (" bold" if is_new and row_idx != self.hover_row else "")),
            )
        
        if not self.page_alerts:
            table.add_row("", "", Text("NO ALERTS", style="yellow"), Text("Nothing matches the current filters", style="dim"))
        
        rem = int((self.next_refresh - datetime.now(timezone.utc)).total_seconds())
        uptime = datetime.now(timezone.utc) - start_time
        current_page = self.feed_page_offset // self.rows_per_page + 1
        green = "bold green"
        status = Text()
        status.append(f"Next refresh {max(rem, 0) // 60 + 1}m", green if self.cold_war_mode else "bold bright_red")
        status.append(f" — Up {int(uptime.total_seconds() // 3600)}h{int(uptime.total_seconds() % 3600 // 60):02d}m", green if self.cold_war_mode else "bold white")
        status.append(" — ↑/↓ select  |  Enter open  |  a explain", green if self.cold_war_mode else "bold magenta")
        if total_pages > 1:
            status.append("  |  ← → pages", green if self.cold_war_mode else "bold cyan")
        
        cw = " // *COLD*WAR*MODE*" if self.cold_war_mode else ""
        page = f" - Page {current_page}/{total_pages}" if total_pages > 1 else ""
        title_str = f"C Y B R W I R E 1.0 // Global Threat Feed ({len(filtered_alerts)}){page}{cw}"
        if self.panel_focus == "main":
            title_text = Text(title_str, style=f"bold black on {'#00ff00' if self.cold_war_mode else '#44ccaa'}")
        else:
            title_text = title_str
        
        preview = Panel(self.make_alert_preview(self.selected_alert()), border_style=border, box=box.ROUNDED,
                        padding=(0, 1), height=self.PREVIEW_LINES)
        return Panel(Group(table, preview),
                     title=title_text,
                     subtitle=status,
                     border_style="#00ff00" if self.cold_war_mode else "#44ccaa",
                     padding=(1, 2))
    
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
        window_alerts = [a for a in source_filtered_queue if a["ts"] >= cutoff_time]
        ioc_count = sum(1 for a in window_alerts if a["title"].startswith(IOC_TITLE_PREFIXES))
        
        # Rate calculation
        hour_ago = now - timedelta(hours=1)
        rate = filtered_count / max(self.recency_hours, 1)
        
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
            ("Avg/Hour", f"{rate:.1f}/hr", "#66dd66"),
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
        last_zeroday_time = max((a["ts"] for a in window_alerts if a["severity"] == "zeroday"), default=None)
        time_since_zeroday = f"{age(last_zeroday_time)} ago" if last_zeroday_time else "none in window"
        
        # Build heat bars (already capped above)
        indent = " " * 2
        heat_bar = "█" * int(capped_heat / 3) + "░" * (HEAT_BAR_WIDTH - int(capped_heat / 3))
        ransomware_bar = "█" * int(capped_ransomware / 3) + "░" * (HEAT_BAR_WIDTH - int(capped_ransomware / 3))
        apt_bar = "█" * int(capped_apt / 3) + "░" * (HEAT_BAR_WIDTH - int(capped_apt / 3))
        zeroday_bar = "█" * int(capped_zeroday / 3) + "░" * (HEAT_BAR_WIDTH - int(capped_zeroday / 3))
        exploit_bar = "█" * int(capped_exploit / 3) + "░" * (HEAT_BAR_WIDTH - int(capped_exploit / 3))
        defcon_bar = "█" * int(capped_master / 3) + "░" * (HEAT_BAR_WIDTH - int(capped_master / 3))
        # 0% at the farthest setting ever (17 minutes, 1991), 100% at midnight
        doomsday_pct = max(0, min(100, (1 - self.doomsday_seconds / 1020) * 100))
        doomsday_bar = "█" * int(doomsday_pct / 3) + "░" * (HEAT_BAR_WIDTH - int(doomsday_pct / 3))
        
        heat_info = ""
        heat_info += f"\n[{'#00ff00' if self.cold_war_mode else heat_style}]{indent}[bold]Heat Level (High-Threat %)[/bold]:\n{indent}[{'#00ff00' if self.cold_war_mode else heat_style}]{heat_bar}[/] {int(capped_heat)}%[/]\n"
        heat_info += f"[{'#00ff00' if self.cold_war_mode else '#dd4488'}]{indent}[bold]Ransomware Heat[/bold]:\n{indent}[{'#00ff00' if self.cold_war_mode else '#dd4488'}]{ransomware_bar}[/] {int(capped_ransomware)}%[/]\n"
        heat_info += f"[{'#00ff00' if self.cold_war_mode else '#b866cc'}]{indent}[bold]APT Heat[/bold]:\n{indent}[{'#00ff00' if self.cold_war_mode else '#b866cc'}]{apt_bar}[/] {int(capped_apt)}%[/]\n"
        heat_info += f"[{'#00ff00' if self.cold_war_mode else '#e6d144'}]{indent}[bold]Zero-Day Heat (Last: {time_since_zeroday})[/bold]:\n{indent}[{'#00ff00' if self.cold_war_mode else '#e6d144'}]{zeroday_bar}[/] {int(capped_zeroday)}%[/]\n"
        heat_info += f"[{'#00ff00' if self.cold_war_mode else '#dd5555'}]{indent}[bold]Exploit Heat[/bold]:\n{indent}[{'#00ff00' if self.cold_war_mode else '#dd5555'}]{exploit_bar}[/] {int(capped_exploit)}%[/]\n"
        heat_info += f"[{'#00ff00' if self.cold_war_mode else 'bold #dd4444'}]{indent}[bold]Doomsday Clock ({self.doomsday_seconds}s to Midnight)[/bold]:\n{indent}[{'#00ff00' if self.cold_war_mode else 'bold #dd4444'}]{doomsday_bar}[/][/]\n"
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
            
            # Determine color based on type
            threat_colors = {
                "Ransomware": "#ff0066",
                "APT": "#800080",
                "Zero-Day": "#e6d144",
                "Exploitation": "#dd5555",
                "Critical": "#dd4444",
            }
            threat_color = threat_colors.get(dominant_name, "#66ccff")
            
            # In cold war mode, everything is green
            if self.cold_war_mode:
                threat_color = "#00ff00"
            
            threat_label = f"DOMINANT THREAT: {dominant_name.upper()} WAVE"
            heat_info += f"\n[{threat_color}]{indent}[bold]{threat_label}[/bold][/]\n"
        
        # Alert Velocity - alerts published in the last 24h vs the 24h before
        now = datetime.now(timezone.utc)
        last_day = sum(1 for a in source_filtered_queue if a["ts"] > now - timedelta(hours=24))
        prev_day = sum(1 for a in source_filtered_queue if now - timedelta(hours=48) < a["ts"] <= now - timedelta(hours=24))
        
        if prev_day > 0:
            velocity = last_day / prev_day
            if velocity > 1.5:
                velocity_status = f"SPIKING ({last_day} vs {prev_day} prior day)"
                velocity_color = "bold #dd4444" if not self.cold_war_mode else "bold #00ff00"
            elif velocity > 1.2:
                velocity_status = f"INCREASING ({last_day} vs {prev_day})"
                velocity_color = "#dd5555" if not self.cold_war_mode else "#00ff00"
            elif velocity < 0.7:
                velocity_status = f"COOLING ({last_day} vs {prev_day})"
                velocity_color = "#66cc66" if not self.cold_war_mode else "#00ff00"
            else:
                velocity_status = f"STEADY ({last_day} vs {prev_day})"
                velocity_color = "#e6d144" if not self.cold_war_mode else "#00ff00"
        else:
            velocity_status = "NOT ENOUGH HISTORY"
            velocity_color = "dim white" if not self.cold_war_mode else "#00ff00"
        
        velocity_label = f"ALERT VELOCITY: {velocity_status}"
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
        for alert in window_alerts:
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
        
        # Ransomware hotspot - victim countries and groups from Ransomware.live in the window
        victims = [RANSOM_VICTIM_RE.match(a["title"]) for a in window_alerts if a["title"].startswith("RANSOMWARE VICTIM")]
        victims = [m for m in victims if m]
        if victims:
            geo_color = "#00ff00" if self.cold_war_mode else "#ff0066"
            countries = Counter(m.group(2) for m in victims if m.group(2))
            groups = Counter(m.group(1) for m in victims)
            if countries:
                code, n = countries.most_common(1)[0]
                heat_info += f"[{geo_color}]{indent}[bold]RANSOMWARE HOTSPOT: {COUNTRY_NAMES.get(code, code)} ({n} of {len(victims)} victims)[/bold][/]\n"
            group, n = groups.most_common(1)[0]
            heat_info += f"[{geo_color}]{indent}[bold]MOST ACTIVE GROUP: {group.upper()} ({n} victims)[/bold][/]\n"
        
        # Add focus indicator with highlighted style when focused
        if self.panel_focus == "dashboard":
            # Use green in cold war mode, otherwise use blue
            bg_color = "#00ff00" if self.cold_war_mode else "#5588dd"
            title_text = Text("WAR ROOM DASHBOARD", style=f"bold black on {bg_color}")
        else:
            title_text = "WAR ROOM DASHBOARD"
        
        return Panel(Group(metrics_table, Text.from_markup(heat_info)),
                    title=title_text,
                    border_style="#00ff00" if self.cold_war_mode else "#5588dd",
                    padding=(0,1))
    
    def current_incidents(self):
        """Incidents for the current window and feed source, rebuilt only when those change"""
        key = (id(alert_queue), self.recency_hours, active_feed_source)
        if key != self.incidents_key:
            cutoff_time = datetime.now(timezone.utc) - timedelta(hours=self.recency_hours)
            alerts = [a for a in alert_queue if a["ts"] >= cutoff_time]
            if active_feed_source != "all":
                alerts = [a for a in alerts if a.get("source_file") == active_feed_source]
            self.incidents = build_incidents(alerts, KEV_CATALOG)
            self.incidents_key = key
        return self.incidents
    
    def make_incidents_panel(self):
        """Correlated incidents with the context needed to act on them"""
        now = datetime.now(timezone.utc)
        incidents = self.current_incidents()
        cw = self.cold_war_mode
        green = "#00ff00"
        severity_colors = {"critical": "#dd4444", "zeroday": "#e6d144", "ransomware": "#dd4488",
                           "apt": "#b866cc", "exploit": "#dd5555", "info": "#55bbdd"}
        
        try:
            available = max(12, self.query_one("#feeds-container").size.height - 6)
        except Exception:
            available = 30
        lines_per_incident = 11
        per_page = max(1, available // lines_per_incident)
        total_pages = max(1, (len(incidents) + per_page - 1) // per_page)
        self.incident_page_offset = max(0, min(self.incident_page_offset, total_pages - 1))
        page = incidents[self.incident_page_offset * per_page:(self.incident_page_offset + 1) * per_page]
        self.hover_row = min(self.hover_row, len(page) - 1)
        
        width = max(40, self.size.width * 3 // 4 - 10)
        lines = []
        self.incident_rows = []
        for idx, inc in enumerate(page):
            selected = idx == self.hover_row
            start = len(lines)
            sev_color = green if cw else severity_colors.get(inc.severity, "#888888")
            body = green if cw else "#ccddee"
            dim = "#00aa00" if cw else "#778899"
            
            header = Text()
            header.append("▶ " if selected else "  ", style=f"bold {sev_color}")
            header.append(f" {inc.severity.upper()} ", style=f"bold black on {sev_color}")
            header.append(f"  {KIND_LABELS[inc.kind]} ", style=f"bold {dim}")
            header.append(inc.value, style=f"bold {green if cw else '#55bbdd'}")
            if inc.kev:
                header.append("  KNOWN EXPLOITED (CISA KEV)", style=f"bold {green if cw else '#ff6666'}")
            header.append(f"   {len(inc.sources)} sources • {len(inc.alerts)} alerts • latest {age(inc.last_seen, now)} ago",
                          style=dim)
            if selected:
                header.stylize("on #1a2a2a" if not cw else "on #002200")
            lines.append(header)
            
            lines.append(Text(f"    {inc.headline}"[:width], style=f"bold {body}"))
            what_lines = textwrap.wrap(f"What: {inc.what}", width=width - 4, max_lines=3, placeholder=" ...")
            lines.extend(Text(f"    {line}", style=body) for line in what_lines)
            lines.append(Text(f"    Why grouped: {inc.why}"[:width], style=dim))
            first = min(inc.alerts, key=lambda a: a["ts"])
            lines.append(Text(f"    Timeline: first seen {age(inc.first_seen, now)} ago ({first['source']}) → "
                              f"latest {age(inc.last_seen, now)} ago ({inc.timeline[0]['source']})"[:width], style=dim))
            related = inc.related(incidents)
            if related:
                lines.append(Text(f"    Related: {', '.join(related)}"[:width], style=green if cw else "#bb88dd"))
            for a in inc.timeline[:2]:
                lines.append(Text(f"      • {age(a['ts'], now):>3}  {a['source'][:22]:22}  {a['title']}"[:width], style=dim))
            lines.append(Text(""))
            self.incident_rows.append((inc, start, len(lines) - 1))
        
        if not page:
            lines.append(Text("No correlated incidents in this window.", style="dim yellow"))
            lines.append(Text("An incident needs the same CVE, IP or hash reported by two or more sources,", style="dim"))
            lines.append(Text("or a named threat actor appearing in several alerts. Try a longer data age (d).", style="dim"))
        
        status = Text()
        status.append(f"{len(incidents)} incidents from {len(self.filtered_alerts())} alerts",
                      "bold green" if cw else "bold cyan")
        if total_pages > 1:
            status.append(f" — Page {self.incident_page_offset + 1}/{total_pages}  |  ← → pages", "bold green" if cw else "bold yellow")
        status.append(" — ↑/↓ select  |  Enter open latest report", "bold green" if cw else "bold magenta")
        
        title_str = "CORRELATED INCIDENTS"
        if self.panel_focus == "main":
            title_text = Text(title_str, style=f"bold black on {green if cw else '#dd8866'}")
        else:
            title_text = title_str
        return Panel(Group(*lines), title=title_text, subtitle=status,
                     border_style=green if cw else "#dd8866", padding=(1, 2))
    
    def action_refresh(self):
        """Force refresh feeds"""
        force_event.set()
    
    def action_show_help(self):
        """Show help screen"""
        self.push_screen(HelpScreen(self.cold_war_mode))
    
    def make_api_tools_panel(self) -> Panel:
        """Display unified API enrichment tools for multiple providers - interactive query panel"""
        content = Text()
        
        # Provider info with tier information
        providers_info = {
            "abuseipdb": {
                "name": "AbuseIPDB",
                "accepts": "IPs",
                "icon": "🌐",
                "tier_note": "(Free tier: IP lookups only)"
            },
            "virustotal": {
                "name": "VirusTotal",
                "accepts": "IPs, hashes, domains, URLs",
                "icon": "🔍",
                "tier_note": "(Free tier: 4 lookups/min, 500/day)"
            },
            "pulsedive": {
                "name": "Pulsedive",
                "accepts": "IPs, domains, hashes, URLs",
                "icon": "📊",
                "tier_note": "(Free tier: limited indicator database)"
            },
            "abusech": {
                "name": "Abuse.ch",
                "accepts": "Hashes, URLs, IPs, domains",
                "icon": "⚠️",
                "tier_note": "(Free Auth-Key: MalwareBazaar + URLhaus)"
            }
        }
        
        # Show which providers are configured
        configured = [k for k in providers_info.keys() if k in enrichment_engine.providers]
        unconfigured = [k for k in providers_info.keys() if k not in enrichment_engine.providers]
        
        if not configured:
            # No providers configured
            content.append("╭─ NO PROVIDERS CONFIGURED ─╮\n\n", style="bold #ffaa00" if not self.cold_war_mode else "bold #00ff00")
            content.append("Available providers:\n\n", style="#00ff00" if self.cold_war_mode else "white")
            for key in providers_info.keys():
                info = providers_info[key]
                tier_note = info.get("tier_note", "")
                content.append(f"  {info['name']}: {info['accepts']}\n", style="dim #00ff00" if self.cold_war_mode else "dim white")
                if tier_note:
                    content.append(f"    {tier_note}\n", style="dim white" if self.cold_war_mode else "dim #888888")
            content.append("\nTo enable: Add API keys to cybrwire_local.yaml and restart.\n", style="dim white" if self.cold_war_mode else "dim #888888")
            content.append("\nNote: Free/limited tier accounts have restrictions on indicator types.\n", style="dim #ffaa00" if not self.cold_war_mode else "dim #00ff00")
            content.append("      Upgrade to paid plans for full IOC database access.\n", style="dim #ffaa00" if not self.cold_war_mode else "dim #00ff00")
            
            title_text = Text("API TOOLS", style="bold #00ff00" if self.cold_war_mode else "bold cyan")
        else:
            # Show input field
            content.append("╭─ ENRICHMENT QUERY ─╮\n", style="dim #00ff00" if self.cold_war_mode else "dim #4499bb")
            
            if self.api_tools_loading:
                content.append(f"[⏳ Querying] {self.api_tools_input_buffer}\n\n", style="bold #ffaa00" if not self.cold_war_mode else "bold #00ff00")
            else:
                # Input prompt
                input_style = "bold #ffff00" if not self.cold_war_mode else "bold #00ff00"
                cursor = "█" if len(self.api_tools_input_buffer) > 0 or self.api_tools_input_mode else ""
                content.append(f"Indicator: {self.api_tools_input_buffer}{cursor}\n", style=input_style)
            
            # Provider status line
            provider_line = "Providers: "
            for provider in configured:
                icon = providers_info[provider].get("icon", "•") if not self.cold_war_mode else ""
                name = providers_info[provider]['name']
                tier_note = providers_info[provider].get("tier_note", "")
                provider_line += f"{icon} {name}  ".lstrip() if self.cold_war_mode else f"{icon} {name}  "
            
            if unconfigured:
                provider_line += f"[disabled: {', '.join([providers_info[p]['name'] for p in unconfigured])}]"
            
            content.append(f"\n{provider_line}\n", style="dim #00ff00" if self.cold_war_mode else "dim white")
            
            # Results section
            if self.api_tools_last_query and self.api_tools_last_results:
                content.append("╭─ RESULTS ─╮\n\n", style="dim #00ff00" if self.cold_war_mode else "dim #4499bb")
                
                for provider_name, enrichment_data in self.api_tools_last_results.items():
                    if enrichment_data is None:
                        continue
                    
                    # Provider header
                    provider_info = providers_info.get(provider_name, {})
                    icon = provider_info.get("icon", "•") if not self.cold_war_mode else ""
                    provider_display = provider_info.get("name", provider_name)
                    provider_text = f"{icon} {provider_display}".lstrip() if self.cold_war_mode else f"{icon} {provider_display}"
                    content.append(f"\n{provider_text}\n", style="bold #00ff00" if self.cold_war_mode else "bold white")
                    content.append("─" * 40 + "\n", style="dim #666666")
                    
                    # Threat level with color
                    threat_level = enrichment_data.threat_level.value.upper()
                    threat_color = {
                        "CLEAN": "#00FF00",
                        "LOW": "#00FF00",
                        "MEDIUM": "#ffff00",
                        "HIGH": "#ff6666",
                        "CRITICAL": "#ff0000"
                    }.get(threat_level, "#00FF00")
                    
                    if self.cold_war_mode:
                        threat_color = "#00ff00"
                    
                    content.append(f"Threat: {threat_level}  |  Score: {int(enrichment_data.reputation_score)}/100\n", style=threat_color)
                    
                    # Details summary - show all relevant fields
                    if enrichment_data.details:
                        # Format details nicely, filtering out internal/redundant fields
                        details = enrichment_data.details
                        
                        # Define display order for common fields
                        priority_fields = [
                            "abuse_score", "report_count", "threat_type", "is_whitelisted", 
                            "malicious_vendors", "suspicious_vendors", "undetected_vendors",
                            "threat", "threat_feed_count", "enhanced_threat_score",
                            "malware_family", "signature_count", "submission_count",
                            "country", "isp", "domain", "asn", "network",
                            "last_reported", "first_reported", "threat_feed_count"
                        ]
                        
                        displayed_fields = set()
                        
                        # Show priority fields first
                        for field in priority_fields:
                            if field in details and details[field] not in [None, "", [], {}]:
                                value = details[field]
                                # Format arrays/lists nicely
                                if isinstance(value, (list, tuple)):
                                    if value:
                                        value_str = ", ".join(str(v)[:30] for v in value[:3])
                                        if len(value) > 3:
                                            value_str += f"... (+{len(value)-3})"
                                    else:
                                        value_str = "(empty)"
                                elif isinstance(value, dict):
                                    value_str = f"{len(value)} items"
                                elif isinstance(value, bool):
                                    value_str = "✓ Yes" if value else "✗ No"
                                else:
                                    value_str = str(value)[:50]
                                
                                content.append(f"  {field}: {value_str}\n", style="dim white")
                                displayed_fields.add(field)
                        
                        # Show other interesting fields (skip internal ones)
                        skip_fields = {"status", "status", "details", "timestamp", "analysis_stats", "sandbox_verdicts", "triage_verdicts"}
                        for key, value in details.items():
                            if key not in displayed_fields and key not in skip_fields and value not in [None, "", [], {}]:
                                if not key.startswith("_"):  # Skip internal fields
                                    if isinstance(value, (list, tuple)):
                                        if len(value) > 0:
                                            value_str = ", ".join(str(v)[:20] for v in value[:2])
                                            if len(value) > 2:
                                                value_str += f"... (+{len(value)-2})"
                                        else:
                                            continue
                                    elif isinstance(value, dict):
                                        value_str = f"{len(value)} items"
                                    elif isinstance(value, bool):
                                        value_str = "✓" if value else "✗"
                                    else:
                                        value_str = str(value)[:40]
                                    
                                    content.append(f"  {key}: {value_str}\n", style="dim white" if self.cold_war_mode else "dim #888888")
                    
                    content.append("\n", style="")
            elif self.api_tools_last_query and not self.api_tools_last_results:
                content.append("╭─ NO RESULTS ─╮\n", style="dim #00ff00" if self.cold_war_mode else "dim #4499bb")
                content.append(f"No threat data found for: {self.api_tools_last_query}\n", style="dim white")
            else:
                content.append("╭─ USAGE ─╮\n\n", style="dim #00ff00" if self.cold_war_mode else "dim #4499bb")
                content.append("Type an indicator (IP, hash, domain, URL) and press ENTER to query all configured providers.\n", style="#00ff00" if self.cold_war_mode else "white")
                content.append("Results will display below with threat scores from each provider.\n", style="#00ff00" if self.cold_war_mode else "white")
                content.append("\nPress ESC to clear the query buffer.\n", style="dim #00ff00" if self.cold_war_mode else "dim white")
                content.append("Press Ctrl+Shift+V to paste from clipboard.\n", style="dim #00ff00" if self.cold_war_mode else "dim white")
                
                # Add API tier limitation note
                content.append("\n╭─ API TIER INFORMATION ─╮\n", style="dim #00ff00" if self.cold_war_mode else "dim #4499bb")
                content.append("\nFree/limited API keys have restrictions on the indicator types they can query:\n\n", style="dim #00ff00" if self.cold_war_mode else "dim white")
                content.append("  VirusTotal Free:  All indicator types, 4 lookups/min, 500/day\n", style="dim #00ff00" if self.cold_war_mode else "dim #888888")
                content.append("  AbuseIPDB Free:   IP lookups only\n", style="dim #00ff00" if self.cold_war_mode else "dim #888888")
                content.append("  Pulsedive Free:   Limited indicator database\n", style="dim #00ff00" if self.cold_war_mode else "dim #888888")
                content.append("  Abuse.ch:         Free Auth-Key (hashes via MalwareBazaar; URLs/IPs/domains via URLhaus)\n", style="dim #00ff00" if self.cold_war_mode else "dim #888888")
                content.append("\nCLEAN means the provider has no record of the indicator, not that it is safe.\n", style="dim #00ff00" if self.cold_war_mode else "dim white")
            
            # Title with focus indicator
            if self.panel_focus == "main":
                title_text = Text("API TOOLS - IOC Enrichment", style="bold black on #00ff00" if self.cold_war_mode else "bold black on #336699")
            else:
                title_text = Text("API TOOLS - IOC Enrichment", style="bold #00ff00" if self.cold_war_mode else "bold cyan")
        
        return Panel(
            content,
            title=title_text,
            border_style="#00ff00" if self.cold_war_mode else "#336699",
            padding=(1, 2)
        )
    
    def action_cycle_data_age(self):
        """Cycle data age window: 24h → 48h → 7d → 24h"""
        time_windows = [24, 48, 168]  # 24h, 48h, 7d (168 hours)
        self.data_age_index = (self.data_age_index + 1) % len(time_windows)
        self.recency_hours = time_windows[self.data_age_index]
        self.feed_page_offset = 0  # Reset to first page
        self.hover_row = -1
        self.save_settings()
        self.call_later(self.update_display)
    
    def action_cycle_filter_type(self):
        """Cycle alert type filter: All → Alerts Only → Posts Only → All"""
        filter_modes = ["all", "alerts", "posts"]
        self.filter_type_index = (self.filter_type_index + 1) % len(filter_modes)
        self.filter_mode = filter_modes[self.filter_type_index]
        self.feed_page_offset = 0  # Reset to first page
        self.hover_row = -1
        self.save_settings()
        self.call_later(self.update_display)
    
    def action_toggle_cold_war(self):
        """Toggle cold war mode"""
        self.cold_war_mode = not self.cold_war_mode
        self.save_settings()
        self.call_later(self.update_display)
    
    def action_cycle_feeds(self):
        """Cycle through feed sources: all → curated → custom → community → all"""
        global active_feed_source
        sources = ["all", "curated", "custom", "community"]
        self.feed_source_index = (self.feed_source_index + 1) % len(sources)
        active_feed_source = sources[self.feed_source_index]
        self.feed_page_offset = 0
        self.hover_row = -1
        self.save_settings()
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
        views = ["alerts", "incidents", "api_tools"]
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
    
    def briefing_prompt(self):
        """Compact digest of the current window for the AI briefing"""
        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=self.recency_hours)
        window = [a for a in alert_queue if a["ts"] >= cutoff_time]
        ranked = sorted(window, key=lambda a: (SEVERITY_RANK.get(a["severity"], 9), -a["ts"].timestamp()))
        # Indicator lists (IPs, URLs) add little to a briefing; keep them out of the digest
        ranked = [a for a in ranked if not a["title"].startswith(IOC_TITLE_PREFIXES)][:60]
        lines = [f"Data window: last {self.recency_hours} hours. {len(window)} alerts from {len({a['source'] for a in window})} sources.", ""]
        incidents = self.current_incidents()[:10]
        if incidents:
            lines.append("Correlated incidents (same indicator reported by several sources):")
            for inc in incidents:
                lines.append(f"- {KIND_LABELS[inc.kind]} {inc.value}: {len(inc.sources)} sources"
                             f"{', CISA KEV' if inc.kev else ''}. {inc.headline}")
            lines.append("")
        lines.append("Alerts (most severe first):")
        for a in ranked:
            summary = f" - {a['summary'][:220]}" if a.get("summary") else ""
            lines.append(f"- [{a['severity'].upper()}] {a['title']} ({a['source']}, {age(a['ts'])} ago){summary}")
        return "\n".join(lines)
    
    async def generate_ai_briefing(self):
        """Ask the configured AI provider for a briefing on the current alerts"""
        if self.ai_briefing_loading:
            return
        if self.ai_problem:
            self.ai_briefing_error = self.ai_problem
            self.mark_dirty()
            return
        self.ai_briefing_loading = True
        self.ai_briefing_error = None
        self.mark_dirty()
        try:
            text = await ai.generate(self.ai_settings, self.BRIEFING_SYSTEM, self.briefing_prompt())
            self.ai_briefing = text.replace("**", "").replace("## ", "").strip()
            self.ai_briefing_time = datetime.now(timezone.utc)
            self.threat_summary_page = 0
        except ai.AIError as e:
            self.ai_briefing_error = str(e)
        except Exception as e:
            logging.error(f"AI briefing failed: {e}", exc_info=True)
            self.ai_briefing_error = f"Unexpected error: {type(e).__name__} - see cybrwire.log"
        finally:
            self.ai_briefing_loading = False
            self.mark_dirty()
    
    async def explain_alert(self, alert):
        """Ask the AI provider to explain one alert; shown in the preview pane"""
        key = alert_key(alert)
        if key in self.explaining:
            return
        self.explaining.add(key)
        self.mark_dirty()
        prompt = (f"Title: {alert['title']}\nSource: {alert['source']}\nPublished: {alert['ts']:%Y-%m-%d %H:%M} UTC\n"
                  f"Severity tag: {alert['severity']}\nSummary: {alert.get('summary') or '(none)'}\nURL: {alert.get('url') or '(none)'}")
        try:
            text = await ai.generate(self.ai_settings, self.EXPLAIN_SYSTEM, prompt)
            self.alert_explanations[key] = text.replace("**", "").strip()
        except ai.AIError as e:
            self.alert_explanations[key] = f"(AI unavailable: {e})"
        except Exception as e:
            logging.error(f"AI explanation failed: {e}", exc_info=True)
            self.alert_explanations[key] = f"(AI error: {type(e).__name__})"
        finally:
            self.explaining.discard(key)
            self.mark_dirty()
    
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
    
    def make_war_room_panel(self) -> Panel:
        """AI briefing followed by the local keyword analysis, paginated"""
        cw = self.cold_war_mode
        heading = "bold #00ff00" if cw else "bold cyan"
        body = "#00ff00" if cw else "#dde6ee"
        dim = "#00aa00" if cw else "#778899"
        
        lines = []
        label = ai.describe(self.ai_settings) if self.ai_settings.get("provider") else "no provider"
        lines.append(Text(f"AI BRIEFING ({label})", style=heading))
        if self.ai_briefing_loading:
            lines.append(Text("⏳ Analyzing current alerts...", style="bold yellow"))
        if self.ai_briefing_error:
            lines.append(Text(self.ai_briefing_error, style="bold #ff6666" if not cw else body))
            if self.ai_problem:
                lines.append(Text("Configure the ai: section in cybrwire_local.yaml (see readme), then restart.", style=dim))
        if self.ai_briefing:
            lines.append(Text(f"Generated {age(self.ai_briefing_time)} ago • press g to refresh", style=dim))
            for line in self.ai_briefing.split("\n"):
                stripped = line.strip()
                if stripped.endswith(":") and stripped[:-1].replace(" ", "").isupper():
                    if lines and lines[-1].plain:
                        lines.append(Text(""))
                    lines.append(Text(stripped, style=heading))
                elif stripped or (lines and lines[-1].plain):
                    lines.append(Text(line, style=body))
        elif not self.ai_briefing_loading and not self.ai_briefing_error:
            lines.append(Text("Press g to generate a briefing.", style=dim))
        
        lines.append(Text(""))
        if self.threat_summary:
            for line in self.threat_summary_full.split("\n"):
                if line.startswith("─"):
                    lines.append(Text("─" * 30, style=dim))
                elif line.endswith(":") or line == "LOCAL KEYWORD ANALYSIS":
                    lines.append(Text(line, style=heading))
                else:
                    lines.append(Text(line, style=body if not ("CVE-" in line and "[" in line) else ("bold #ff6666" if not cw else body)))
        
        try:
            page_height = max(10, self.query_one("#dashboard").size.height - 6)
        except Exception:
            page_height = 40
        # Wrapped lines take more than one row; estimate with the panel width
        try:
            width = max(20, self.query_one("#dashboard").size.width - 6)
        except Exception:
            width = 60
        pages, current, used = [], [], 0
        for line in lines:
            rows = max(1, -(-len(line.plain) // width))
            if used + rows > page_height and current:
                pages.append(current)
                current, used = [], 0
            current.append(line)
            used += rows
        pages.append(current)
        self.threat_summary_pages = pages
        self.threat_summary_page = max(0, min(self.threat_summary_page, len(pages) - 1))
        
        title_str = "WAR ROOM" + (f" - Page {self.threat_summary_page + 1}/{len(pages)}" if len(pages) > 1 else "")
        border_color = "#00ff00" if cw else "#9933ff"
        if self.panel_focus == "dashboard":
            title_text = Text(title_str, style=f"bold black on {border_color}")
        else:
            title_text = title_str
        subtitle = Text("← → pages  •  g refresh", style=f"bold {border_color}") if len(pages) > 1 else Text("g refresh", style=f"bold {border_color}")
        return Panel(Group(*pages[self.threat_summary_page]), title=title_text, subtitle=subtitle,
                     border_style=border_color, padding=(1, 2), expand=True)
    
    async def _run_api_tools_query(self, indicator: str):
        """Run enrichment query for the given indicator across all configured providers"""
#        logging.info(f"Starting API Tools enrichment for: {indicator}")
        
        try:
            # Run the enrichment query
            results = await enrichment_engine.enrich(indicator)
            self.api_tools_last_results = results
#            logging.info(f"API Tools enrichment complete for {indicator}: {len(results)} providers returned data")
        
        except Exception as e:
            logging.error(f"Error querying providers for {indicator}: {e}")
            self.api_tools_last_results = {}
        
        finally:
            self.api_tools_loading = False
            self.call_later(self.update_display)

    def action_toggle_view(self):
        """Toggle view in the focused panel - alerts/incidents/api_tools on left, dashboard views on right"""
        if self.panel_focus == "main":
            # Cycle alerts/incidents/api_tools in left panel
            views = ["alerts", "incidents", "api_tools"]
            current_idx = views.index(self.main_view_mode) if self.main_view_mode in views else 0
            self.main_view_mode = views[(current_idx + 1) % len(views)]
#            logging.info(f"Main view toggled to: {self.main_view_mode}")
            self.update_display()
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
            if not alert:
                self.notify("Select an alert with ↑/↓ first", timeout=2)
            elif alert.get("url"):
                webbrowser.open(alert["url"])
                STATE.mark_read(alert)
                STATE.save()
                self.notify("Opening alert in browser...")
            else:
                self.notify("No link for this alert (phishing URLs are never opened)", timeout=3)
            self.mark_dirty()
        elif self.main_view_mode == "incidents":
            if 0 <= self.hover_row < len(self.incident_rows):
                inc = self.incident_rows[self.hover_row][0]
                if inc.url:
                    webbrowser.open(inc.url)
                    self.notify("Opening latest report in browser...")
            else:
                self.notify("Select an incident with ↑/↓ first", timeout=2)

    def on_key(self, event: events.Key) -> None:
        """Handle key events - Tab, view toggle, and arrow key pagination"""
        # PRIORITY: Check for 'v' key FIRST to allow exiting input mode and cycling views
        # This ensures 'v' always works to cycle views, even when in input mode
        typing_indicator = self.main_view_mode == "api_tools" and self.api_tools_input_mode and self.api_tools_input_buffer
        if event.key == "v" and not typing_indicator:
            event.prevent_default()
            # Exit input modes if active
            if self.api_tools_input_mode:
                self.api_tools_input_mode = False
                self.api_tools_input_buffer = ""
#                logging.info("Exited API Tools input mode via 'v' key")
            # Now cycle the view
            self.action_toggle_view()
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
        
        # If in API Tools view AND in input mode, capture input for enrichment query
        if self.main_view_mode == "api_tools" and self.api_tools_input_mode:
            if event.key == "enter":
                # Submit the indicator for enrichment query
                event.prevent_default()
                indicator = self.api_tools_input_buffer.strip()
                
                if indicator and enrichment_engine.providers:
                    # Clear results and start query
                    self.api_tools_last_query = indicator
                    self.api_tools_last_results = {}
                    self.api_tools_loading = True
                    self.call_later(self.update_display)
                    
                    # Run async enrichment query
                    asyncio.create_task(self._run_api_tools_query(indicator))
                
                return
            
            elif event.key == "escape":
                # Exit input mode and clear the input buffer
                event.prevent_default()
#                logging.info(f"ESC pressed in API Tools input mode - exiting. Buffer was: {self.api_tools_input_buffer}")
                self.api_tools_input_buffer = ""
                self.api_tools_input_mode = False
                self.call_later(self.update_display)
                return
            
            elif event.key == "backspace":
                # Remove last character from input buffer
                event.prevent_default()
                self.api_tools_input_buffer = self.api_tools_input_buffer[:-1]
                self.call_later(self.update_display)
                return
            
            elif event.character and len(event.character) == 1 and event.character.isprintable():
                # Add character to input buffer
                event.prevent_default()
                self.api_tools_input_buffer += event.character
                self.call_later(self.update_display)
                return
        
        # If in API Tools view but NOT in input mode, any printable character enters input mode
        if self.main_view_mode == "api_tools" and not self.api_tools_input_mode:
            if event.character and len(event.character) == 1 and event.character.isprintable():
                event.prevent_default()
                self.api_tools_input_mode = True
                self.api_tools_input_buffer = event.character
                self.call_later(self.update_display)
                return
        
        # Normal key handling
        if event.key == "tab":
            event.prevent_default()
            self.action_toggle_panel_focus()
        elif event.key == "up":
            event.prevent_default()
            # Navigate up in alerts/incidents view to highlight previous row
            if self.main_view_mode in ["alerts", "incidents"]:
                self.hover_row = max(-1, self.hover_row - 1)
                self.call_later(self.update_display)
        elif event.key == "down":
            event.prevent_default()
            # Navigate down in alerts/incidents view to highlight next row
            if self.main_view_mode in ["alerts", "incidents"]:
                max_row = len(self.page_alerts) - 1 if self.main_view_mode == "alerts" else len(self.incident_rows) - 1
                self.hover_row = min(max_row, self.hover_row + 1)
                self.call_later(self.update_display)
        elif event.key == "left":
            event.prevent_default()
            self.action_focused_prev_page()
        elif event.key == "right":
            event.prevent_default()
            self.action_focused_next_page()

    def on_paste(self, event: events.Paste) -> None:
        """Handle paste events for input buffers - allows users to paste large IOCs without typing"""
        pasted_text = event.text.strip()
        
        # If in API Tools view, append pasted text to input buffer
        if self.main_view_mode == "api_tools" and self.api_tools_input_mode:
            self.api_tools_input_buffer += pasted_text
            self.call_later(self.update_display)
            return
    
    def action_focused_next_page(self):
        """Next page in the focused panel (main or dashboard)"""
        if self.panel_focus == "main":
            if self.main_view_mode == "alerts":
                self.feed_page_offset += self.rows_per_page
            elif self.main_view_mode == "incidents":
                self.incident_page_offset += 1
            else:  # api_tools view
                pass  # API tools doesn't use pagination
        else:  # dashboard focus
            if self.dashboard_panel_index == 1 and self.threat_summary_pages:
                self.threat_summary_page = min(self.threat_summary_page + 1, len(self.threat_summary_pages) - 1)
            else:
                self.dashboard_page_offset += 1
        self.call_later(self.update_display)
    
    def action_focused_prev_page(self):
        """Previous page in the focused panel (main or dashboard)"""
        if self.panel_focus == "main":
            if self.main_view_mode == "alerts":
                self.feed_page_offset = max(0, self.feed_page_offset - self.rows_per_page)
            elif self.main_view_mode == "incidents":
                self.incident_page_offset = max(0, self.incident_page_offset - 1)
            else:  # api_tools view
                pass  # API tools doesn't use pagination
        else:  # dashboard focus
            if self.dashboard_panel_index == 1 and self.threat_summary_pages:
                self.threat_summary_page = max(0, self.threat_summary_page - 1)
            else:
                self.dashboard_page_offset = max(0, self.dashboard_page_offset - 1)
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
        self.save_settings()
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
    
    def on_click(self, event) -> None:
        """Click a row to select it; click the selected row again to open it"""
        if self.main_view_mode not in ("alerts", "incidents") or getattr(event.widget, "id", None) != "feeds":
            return
        if self.main_view_mode == "alerts":
            # Outer panel border + padding + table top border = 3 rows before the first alert
            row = event.y - 3
            if not 0 <= row < len(self.page_alerts):
                return
        else:
            # Outer panel border + padding = 2 rows before the first incident line
            line = event.y - 2
            row = next((i for i, (_, first, last) in enumerate(self.incident_rows) if first <= line <= last), None)
            if row is None:
                return
        self.panel_focus = "main"
        if row == self.hover_row:
            self.action_open_selected_link()
        else:
            self.hover_row = row
            self.update_display()

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="CybrWire - terminal threat intelligence dashboard")
    parser.add_argument("--setup", action="store_true", help="choose data age and display mode again")
    args = parser.parse_args()
    
    saved = STATE.settings
    if saved and not args.setup:
        recency = saved.get("recency_hours", 24)
        cold_war = saved.get("cold_war", False)
    else:
        recency, cold_war = startup_prompts()
    
    app = CybrWireApp(cold_war=cold_war, recency=recency)
    try:
        app.run()
    finally:
        app.save_settings()

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
        ("║                                       v1.0 LEGENDARY // EDITION                                        ║", "#ff00ff"),
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
