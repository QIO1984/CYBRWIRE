#!/usr/bin/env python3
import argparse
import asyncio
import io
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
from feeds import MAX_TITLE_LEN, KEV_CATALOG, parse_json, parse_rss, parse_threatfox, parse_txt, fetch_doomsday_seconds
from incidents import CVE_RE, build_incidents, age, KIND_LABELS, SEVERITY_RANK
import cve_intel
from state import AppState, alert_key
from textual.app import App, Screen, ComposeResult
from textual.widgets import Static, Header
from textual.containers import Container, Horizontal, VerticalScroll
from textual.reactive import reactive
from textual.theme import Theme as TextualTheme
from theme import COLD_WAR, DEFAULT_PALETTE, PALETTES, Palette
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

RANSOM_VICTIM_RE = re.compile(r"^RANSOMWARE VICTIM: .* \(([^)]+)\)(?: \[([A-Z]{2})\])?")
COUNTRY_NAMES = {
    "US": "United States", "CA": "Canada", "GB": "United Kingdom", "DE": "Germany", "FR": "France",
    "IT": "Italy", "ES": "Spain", "NL": "Netherlands", "BE": "Belgium", "CH": "Switzerland", "AT": "Austria",
    "AU": "Australia", "BR": "Brazil", "MX": "Mexico", "IN": "India", "JP": "Japan", "KR": "South Korea",
    "TW": "Taiwan", "CN": "China", "SG": "Singapore", "ZA": "South Africa", "SE": "Sweden", "PL": "Poland",
}
force_event = asyncio.Event()
# What '4' cycles through. "All" leaves indicators out; they have their own view.
CONTENT_KINDS = [("all", "All"), ("advisory", "Advisories"), ("news", "News & Research"),
                 ("ransomware", "Ransomware"), ("indicators", "Indicators")]


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
    
    def __init__(self, palette):
        super().__init__()
        self.palette = palette
    
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
        color = self.palette.text
        accent = self.palette.accent
        
        # Header
        help_text.append("\n", style=color)
        help_text.append("═" * 100 + "\n", style=color)
        help_text.append(" " * 30 + "C Y B R W I R E  1.0  H E L P  S C R E E N\n", style=f"bold {color}")
        help_text.append("═" * 100 + "\n\n", style=color)
        help_text.append("Press ESC or 'Q' to close help\n\n", style=self.palette.muted)
        
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
        help_text.append("│  [CONTENT TYPE] (Press '4' to cycle)\n", style=f"bold {accent}")
        help_text.append("│    All (default) - Advisories, news and ransomware (indicators have their own view)\n", style=color)
        help_text.append("│    Advisories    - Vendor bulletins, CISA/KEV, national CERTs, GitHub advisories: what to patch\n", style=color)
        help_text.append("│    News & Research - Security news and vendor research: what's happening\n", style=color)
        help_text.append("│    Ransomware    - Ransomware.live victim claims: who's getting hit\n", style=color)
        help_text.append("│    Indicators    - Malicious IPs, URLs and C2 servers; Enter looks one up in API Tools\n", style=color)
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
        help_text.append("┌─ SOURCES & CVE SCORES (Right Side) " + "─" * 61 + "┐\n", style=accent)
        help_text.append("│\n", style=accent)
        help_text.append("│  [SOURCES]\n", style=f"bold {accent}")
        help_text.append("│    Items in the window from curated (vetted), custom and community feed sets\n", style=color)
        help_text.append("│\n", style=accent)
        help_text.append("│  [CVE SCORES] (alert preview, incidents, Top CVEs)\n", style=f"bold {accent}")
        help_text.append("│    KEV               - In CISA's Known Exploited Vulnerabilities catalog\n", style=color)
        help_text.append("│    CVSS              - Severity score 0-10 from NVD, fetched for the alert you select\n", style=color)
        help_text.append("│    EPSS              - FIRST.org estimate of the chance of exploitation in the next 30 days\n", style=color)
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
        help_text.append("│    Set one provider in the ai: section of cybrwire_local.yaml (examples in usrwire.yaml)\n", style=color)
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
        help_text.append("│    Themes: Synthwave (default), Retro Warm, Amber CRT\n", style=color)
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
        help_text.append("│  4              Content Type - All / Advisories / News & Research / Ransomware / Indicators\n", style=color)
        help_text.append("│  Tab            Switch Panel Focus - Toggle between left and right panels\n", style=color)
        help_text.append("│  V              Toggle View in Focused Panel - Switch between Alerts / Incidents / API Tools\n", style=color)
        help_text.append("│  E              Re-enable Feeds - Re-enable all auto-disabled feeds\n", style=color)
        help_text.append("│  C              Toggle Cold War Mode - Switch between colorful and green-only\n", style=color)
        help_text.append("│  G              AI Briefing - Generate a fresh briefing in the War Room\n", style=color)
        help_text.append("│  A              Explain Alert - AI explanation of the selected alert\n", style=color)
        help_text.append("│  T              Cycle Theme - Synthwave / Retro Warm / Amber CRT (leaves Cold War mode)\n", style=color)
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
        help_text.append("│  PRO TIP: Use keyboard shortcuts to quickly switch between filters and views\n", style=f"bold {self.palette.warn}")
        help_text.append("│           Example: D (switch time) → F (filter) → V (view) → Tab (Switch Panel Focus)\n", style=self.palette.muted)
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
        background: $background;
        height: 100%;
        overflow-y: auto;
    }
    """

class LoadingScreen(Screen):
    """Loading screen with animated ASCII art"""
    
    def __init__(self, palette):
        super().__init__()
        self.palette = palette
        self.cold_war_mode = palette.monochrome
        self.loading_step = 0
        self.feed_animation_step = 0
        self.messages = [
            "ESTABLISHING SECURE LINE...",
            "AUTHENTICATING STATION...",
            "CHECKING CRYPTO KEYS...",
            "HANDSHAKE COMPLETE...",
            "DECRYPTING TRAFFIC...",
            "COLLATING INTERCEPTS...",
            "STAND BY FOR TRAFFIC...",
        ] if self.cold_war_mode else [
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
        p = self.palette
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
        
        # Soft gradient from the palette (Cold War: phosphor brightness levels)
        gradient = [p.text] if self.cold_war_mode else [p.focus, p.accent, p.text, p.accent]
        ascii_art = [(line, gradient[i % len(gradient)] if i < len(ascii_art) - 1 else p.muted)
                     for i, (line, _) in enumerate(ascii_art)]
        art_text = "\n".join([f"[bold {color}]{line}[/]" for line, color in ascii_art])
        
        # Build stacked messages - completed messages stay static, current message blinks
        message_lines = []
        
        for i, msg in enumerate(self.messages[:self.loading_step]):
            message_lines.append(f"[bold {p.accent}]  {msg}[/]")
            # If this is the "CHECKING APIS..." message and we have APIs, show them on the next line
            if i == 2 and self.configured_apis:  # Index 2 is the API-check step
                apis_str = " • ".join(self.configured_apis)
                message_lines.append(f"[bold {p.accent}]    → {apis_str}[/]")
        
        if self.loading_step < len(self.messages):
            current_msg = self.messages[self.loading_step]
            if self.loading_step == len(self.messages) - 1:
                spinner = self.feed_spinner[self.feed_animation_step]
                global currently_loading
                feed_name = currently_loading if currently_loading else "INITIALIZING"
                if self.feed_animation_step % 2 == 0:
                    message_lines.append(f"[bold {p.accent}]{spinner} {current_msg} - {feed_name[:40]}[/]")
                else:
                    message_lines.append(f"[{p.muted}]{spinner} {current_msg} - {feed_name[:40]}[/]")
            else:
                if self.feed_animation_step % 2 == 0:
                    message_lines.append(f"[bold {p.accent}]{current_msg}[/]")
                else:
                    message_lines.append(f"[{p.muted}]{current_msg}[/]")
                if self.loading_step == 2 and self.configured_apis:  # The API-check step
                    apis_str = " • ".join(self.configured_apis)
                    message_lines.append(f"[bold {p.accent}]    → {apis_str}[/]")
        
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
        
        # Count of what the feed panel is showing
        count = len(app.filtered_alerts()) if not app.is_loading else 0
        
        # Build custom footer text with proper styling
        footer_text = Text()
        
        # Determine color based on cold war mode
        key_color = f"bold {app.palette.accent}"
        desc_color = app.palette.muted
        
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
        footer_text.append(f"Type: {CONTENT_KINDS[app.kind_index][1]}  ", style=desc_color)
        
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
        footer_text.append(f"Theme: {app.palette.name}  ", style=desc_color)
        
        # Help
        footer_text.append("h ", style=key_color)
        footer_text.append("Help  ", style=desc_color)
        
        # Quit
        footer_text.append("q ", style=key_color)
        footer_text.append("Quit", style=desc_color)
        
        return footer_text

class CybrWireApp(App):
    """Textual-based CybrWire threat intelligence dashboard"""
    
    # Colors come from the active palette, registered as a Textual theme (see apply_theme)
    CSS = """
    Screen, #main-layout, #feeds-container, #feeds, #dashboard, #ticker {
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
    
    #ticker {
        height: 3;
    }
    
    #main-layout {
        border: none;
    }
    
    #feeds-container {
        width: 3fr;
        height: 100%;
        overflow-y: auto;
    }
    
    #feeds {
        width: 100%;
    }
    
    #dashboard {
        width: 1fr;
        height: 100%;
    }
    
    #loading-content {
        padding: 2;
    }
    """
    
    TITLE = " C Y B R W I R E // v1.0 LEGENDARY EDITION "
    
    BINDINGS = [
        ("r", "refresh", "Force Refresh"),
        ("d", "cycle_data_age", "Data Age"),
        ("f", "cycle_filter_type", "Alert Type"),
        ("4", "cycle_feeds", "Content Type"),
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
    kind_index = reactive(0)  # Index into CONTENT_KINDS
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
        self.theme_mode = saved.get("theme") if saved.get("theme") in PALETTES else DEFAULT_PALETTE
        for p in (*PALETTES.values(), COLD_WAR):
            self.register_theme(TextualTheme(
                name=f"cybrwire-{p.key}", dark=True,
                primary=p.focus, secondary=p.accent, accent=p.accent,
                foreground=p.text, background=p.bg, surface=p.bg, panel=p.surface,
                success=p.good, warning=p.warn, error=p.bad,
            ))
        self.filter_type_index = saved.get("filter_type_index", 0)
        self.filter_mode = ["all", "alerts", "posts"][self.filter_type_index]
        self.kind_index = saved.get("kind_index", 0) if 0 <= saved.get("kind_index", 0) < len(CONTENT_KINDS) else 0
        
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
        self.api_tools_input_buffer = ""  # User input for IOC query
        self.api_tools_last_query = ""  # Last queried indicator
        self.api_tools_last_results = {}  # Results from all providers {provider: EnrichmentData}
        self.api_tools_loading = False  # Is query in progress
        self.api_tools_input_mode = True  # Always in input mode in this panel
        
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
            "kind_index": self.kind_index,
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
        except Exception:
            pass  # Not mounted yet; on_mount applies the theme again
        self.mark_dirty()
    
    def on_mount(self) -> None:
        """Show loading screen then start app"""
        self.apply_theme()
        self.push_screen(LoadingScreen(self.palette))
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
        yield StyledHeader(show_clock=True, icon="◆")
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

        abusech_key = (CONFIG.enrichment.get("abusech") or {}).get("api_key")
        # ThreatFox needs the abuse.ch Auth-Key; without one it is skipped rather than failing
        all_sources = [s for s in CONFIG.sources if s['name'] not in disabled_feeds
                       and (s["type"] != "threatfox" or abusech_key)]
        parsers = {"json": lambda r, n, f: parse_json(r.json(), n, f),
                   "rss": lambda r, n, f: parse_rss(r.text, n, f),
                   "txt": lambda r, n, f: parse_txt(r.text, n, f),
                   "threatfox": lambda r, n, f: parse_threatfox(r.json(), n, f)}
        semaphore = asyncio.Semaphore(MAX_CONCURRENT_FEEDS)

        async def fetch_one(c, src):
            global currently_loading
            async with semaphore:
                currently_loading = src['name']
                if src["type"] == "threatfox":
                    r = await c.post(src["url"], json={"query": "get_iocs", "days": 1},
                                     headers={"Auth-Key": abusech_key})
                else:
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
                for item in result:
                    # Parsers that know their content type set it; otherwise the feed's kind applies
                    item.setdefault("kind", src.get("kind", "news"))
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
        
        # Newest first, with undated items (stamped at fetch time) after dated alerts
        alert_queue = sorted(
            [item for alerts in source_buckets.values() for item in alerts],
            key=lambda x: (not x.get("undated"), x["ts"]),
            reverse=True
        )
        
        currently_loading = None  # Clear loading indicator
        
        # Exploit-likelihood scores for every CVE mentioned (one batched, free request)
        await cve_intel.fetch_epss(m.upper() for a in alert_queue for m in CVE_RE.findall(f"{a['title']} {a['summary']}"))
        
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
            self.query_one(CybrWireFooter).refresh()  # Type, filter and count change with the feed
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
                    dashboard_content = self.make_feed_status_panel()
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
        p = self.palette
        return Panel(Text(visible_text, style=f"bold {p.accent}"),
                     title=Text(f" {p.title('LIVE THREAT TAPE')} ", style=f"bold {p.muted}"),
                     border_style=p.border, box=box.ROUNDED, padding=0)
    
    def is_alert(self, item):
        """Classify item as alert vs blog post"""
        # Simple rule: INFO = blog post, everything else = alert
        return item["severity"] != "info"
    
    PREVIEW_LINES = 8  # Lines reserved under the alert table for the selected-alert preview
    
    def filtered_alerts(self):
        """Alerts in the current time window, feed source and alert-type filter"""
        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=self.recency_hours)
        alerts = [a for a in alert_queue if a["ts"] >= cutoff_time]
        kind = self.active_kind
        alerts = [a for a in alerts if (a.get("kind") != "indicators" if kind == "all" else a.get("kind") == kind)]
        if self.filter_mode == "alerts":
            alerts = [a for a in alerts if self.is_alert(a)]
        elif self.filter_mode == "posts":
            alerts = [a for a in alerts if not self.is_alert(a)]
        return alerts
    
    def selected_alert(self):
        if 0 <= self.hover_row < len(self.page_alerts):
            return self.page_alerts[self.hover_row]
        return None
    
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
    
    def make_alert_preview(self, alert):
        """Detail pane for the highlighted alert"""
        p = self.palette
        text = Text()
        if not alert:
            text.append("Select an alert with ↑/↓ or a click to see its summary here.", style=p.muted)
            return text
        
        if alert.get("kind") == "indicators":
            text.append((alert.get("ioc") or alert["title"]) + "\n", style=f"bold {p.text}")
            when = "no date in feed (list refreshed each fetch)" if alert.get("undated") else f"{p.stamp(alert['ts'], long=True)} ({age(alert['ts'])} ago)"
            text.append(f" {(alert.get('ioc_type') or 'IOC').upper()} ", style=f"bold {p.bg} on {p.accent}")
            text.append(f"  {alert.get('threat') or ''}  •  {alert['source']}  •  {when}\n", style=p.muted)
            text.append(alert.get("summary", "") + "\n", style=p.text)
            if alert.get("url"):
                text.append(alert["url"] + "\n", style=f"underline {p.muted}")
            hints = [("Enter", "look up in API Tools")] if enrichment_engine.providers else []
            text.append_text(self.hint_bar(hints) if hints else Text("Add enrichment API keys to look indicators up", style=p.muted))
            return text
        
        text.append(alert["title"] + "\n", style=f"bold {p.text}")
        when = "no publish date in feed" if alert.get("undated") else f"{p.stamp(alert['ts'], long=True)} ({age(alert['ts'])} ago)"
        sev = alert["severity"]
        label = p.severity_name(sev)
        if label != sev.upper():
            label += f" · {sev.upper()}"  # e.g. FLASH · ZERODAY
        text.append(f" {label} " if sev in ("critical", "zeroday") else label, style=p.badge(sev))
        text.append(f"  {alert['source']}  •  {when}", style=p.muted)
        if STATE.is_new(alert):
            text.append("  ")
            text.append(" NEW ", style=f"bold {p.bg} on {p.accent}")
        text.append("\n")
        
        cves = list(dict.fromkeys(m.upper() for m in CVE_RE.findall(f"{alert['title']} {alert.get('summary', '')}")))[:3]
        if cves:
            for i, cve in enumerate(cves):
                if i:
                    text.append("   ")
                text.append_text(self.cve_scores(cve))
            text.append("\n")
            missing = [c for c in cves if self.nvd.get(c) is None and c not in self.nvd.pending]
            if missing:
                asyncio.create_task(self._fetch_cvss(missing))
        
        key = alert_key(alert)
        if key in self.alert_explanations:
            text.append("AI  ", style=f"bold {p.accent}")
            text.append(self.alert_explanations[key].strip() + "\n", style=p.text)
        elif key in self.explaining:
            text.append("AI  analyzing...\n", style=f"italic {p.accent}")
        else:
            text.append((alert.get("summary") or "No summary provided by this feed.") + "\n", style=p.text)
        
        if alert.get("url"):
            text.append(alert["url"] + "\n", style=f"underline {p.muted}")
        hints = [("Enter", "open in browser")]
        if not self.ai_problem and key not in self.alert_explanations:
            hints.append(("a", "explain with AI"))
        text.append_text(self.hint_bar(hints))
        text.truncate(max(self.size.width, 40) * self.PREVIEW_LINES)
        return text
    
    def hint_bar(self, hints):
        """'key description' pairs with keys in the accent color"""
        p = self.palette
        text = Text()
        for i, (key, desc) in enumerate(hints):
            if i:
                text.append("   ")
            text.append(key, style=f"bold {p.accent}")
            text.append(f" {desc}", style=p.muted)
        return text
    
    def make_feeds_table(self):
        """Create feeds table with pagination and a preview of the selected alert"""
        p = self.palette
        try:
            container_height = self.query_one("#feeds-container").size.height
        except Exception:
            container_height = self.size.height - 8
        # Panel borders + padding (4) and the spacer above the preview (1)
        self.rows_per_page = max(5, container_height - 5 - self.PREVIEW_LINES)
        
        indicators_view = self.active_kind == "indicators"
        table = Table(box=None, show_header=indicators_view, header_style=f"bold {p.muted}",
                      padding=(0, 1), expand=True)
        narrow = self.size.width < 120
        date_width = 7 if p.military_time else 6 if narrow else 10
        table.add_column("SEEN", width=date_width, min_width=date_width, no_wrap=True)  # published date
        table.add_column("AGE", width=3, min_width=3, no_wrap=True, justify="right")    # age
        if indicators_view:
            table.add_column("TYPE", width=5, min_width=5, no_wrap=True)
            table.add_column("INDICATOR", ratio=3, no_wrap=True, overflow="ellipsis")
            table.add_column("THREAT", ratio=1, no_wrap=True, overflow="ellipsis")
            table.add_column("SOURCE", width=18, min_width=18, no_wrap=True, overflow="ellipsis")
            if table.show_header:
                self.rows_per_page -= 1
        else:
            table.add_column(width=12, min_width=12, no_wrap=True)                  # severity tag
            table.add_column(ratio=1, no_wrap=True, overflow="ellipsis")            # NEW badge + title
        
        filtered_alerts = self.filtered_alerts()
        total_pages = max(1, (len(filtered_alerts) + self.rows_per_page - 1) // self.rows_per_page)
        self.feed_page_offset = max(0, min(self.feed_page_offset, (total_pages - 1) * self.rows_per_page))
        self.page_alerts = filtered_alerts[self.feed_page_offset:self.feed_page_offset + self.rows_per_page]
        self.alert_urls = [a.get("url", "") for a in self.page_alerts]
        self.hover_row = min(self.hover_row, len(self.page_alerts) - 1)
        
        for row_idx, a in enumerate(self.page_alerts):
            selected = row_idx == self.hover_row
            sev = a["severity"]
            title = Text()
            if STATE.is_new(a):
                title.append(" NEW ", style=f"bold {p.bg} on {p.accent}")
                title.append(" ")
            urgent = sev in ("critical", "zeroday")
            title_style = f"bold {p.focus}" if selected and p.monochrome else f"bold {p.text}" if urgent or selected else p.text
            title.append(a["title"], style=title_style)
            if selected and p.monochrome:
                title.append(" █", style=f"blink {p.focus}")  # teletype cursor
            short_date = f"{a['ts']:%d %b}" if narrow and not p.military_time else p.stamp(a["ts"])
            row_style = f"on {p.surface}" if selected else None
            if indicators_view:
                table.add_row(
                    Text(short_date, style=p.muted),
                    Text("—" if a.get("undated") else age(a["ts"]), style=p.muted),
                    Text((a.get("ioc_type") or "").upper(), style=f"bold {p.accent}"),
                    Text(a.get("ioc") or a["title"], style=title_style),
                    Text(a.get("threat") or "", style=p.text),
                    Text(a["source"], style=p.muted),
                    style=row_style,
                )
                continue
            table.add_row(
                Text(short_date, style=p.muted),
                Text("—" if a.get("undated") else age(a["ts"]), style=p.muted),
                Text(f" {p.severity_name(sev)} " if urgent else p.severity_name(sev), style=p.badge(sev)),
                title,
                style=row_style,
            )
        
        if not self.page_alerts:
            empty = [Text("NO ALERTS", style=p.warn), Text("Nothing matches the current filters", style=p.muted)]
            table.add_row("", "", *empty, *([""] * (len(table.columns) - 4)))
        
        rem = int((self.next_refresh - datetime.now(timezone.utc)).total_seconds())
        uptime = datetime.now(timezone.utc) - start_time
        current_page = self.feed_page_offset // self.rows_per_page + 1
        status = Text(f" refresh in {max(rem, 0) // 60 + 1}m · up {int(uptime.total_seconds() // 3600)}h"
                      f"{int(uptime.total_seconds() % 3600 // 60):02d}m   ", style=p.muted)
        hints = [("↑↓", "select"), ("Enter", "open"), ("a", "explain")]
        if total_pages > 1:
            hints.append(("←→", "pages"))
        status.append_text(self.hint_bar(hints))
        status.append(" ")
        
        page = f" · page {current_page}/{total_pages}" if total_pages > 1 else ""
        kind_label = "" if self.active_kind == "all" else f" · {CONTENT_KINDS[self.kind_index][1].upper()}"
        title_text, border = self.frame(f"GLOBAL THREAT FEED{kind_label} ({len(filtered_alerts)}){page}", self.panel_focus == "main")
        
        preview = Panel(self.make_alert_preview(self.selected_alert()), border_style=p.border, box=box.ROUNDED,
                        padding=(0, 1), height=self.PREVIEW_LINES)
        return Panel(Group(table, Text(""), preview),
                     title=title_text, subtitle=status, border_style=border, box=box.ROUNDED,
                     padding=(1, 2))
    
    def frame(self, title, focused):
        """Title and border style for a panel; only the focused panel is highlighted"""
        p = self.palette
        title = p.title(title)
        if focused:
            return Text(f" {title} ", style=f"bold {p.bg} on {p.focus}"), p.focus
        return Text(f" {title} ", style=f"bold {p.muted}"), p.border
    
    def bar(self, pct, color, width=HEAT_BAR_WIDTH):
        """Horizontal meter: filled part in color, remainder muted"""
        filled = int(round(max(0, min(100, pct)) / 100 * width))
        meter = Text("█" * filled, style=color)
        meter.append("░" * (width - filled), style=self.palette.surface if not self.palette.monochrome else self.palette.muted)
        return meter
    
    def make_dashboard(self):
        """Create dashboard panel with all metrics"""
        p = self.palette
        now = datetime.now(timezone.utc)
        cutoff_time = now - timedelta(hours=self.recency_hours)
        
        source_filtered_queue = alert_queue
        window_alerts = [a for a in source_filtered_queue if a["ts"] >= cutoff_time]
        # Undated items (IP/URL lists, some blogs) are re-stamped on every fetch, so they
        # don't count as "incoming"
        dated_alerts = [a for a in source_filtered_queue if not a.get("undated")]
        
        counts = Counter(a["severity"] for a in window_alerts)
        critical_count, zeroday_count = counts["critical"], counts["zeroday"]
        ransomware_count, apt_count, exploit_count = counts["ransomware"], counts["apt"], counts["exploit"]
        filtered_count = len(window_alerts)
        new_count = sum(1 for a in dated_alerts if now - a["ts"] < timedelta(hours=1))
        ioc_count = sum(1 for a in window_alerts if a.get("kind") == "indicators")
        rate = filtered_count / max(self.recency_hours, 1)
        
        # --- Metrics (left) and source mix (right) ---
        metrics_list = [
            ("Total Alerts", filtered_count, p.text),
            ("Critical/KEV", critical_count, p.critical),
            ("Zero-Day", zeroday_count, p.zeroday),
            ("Ransomware", ransomware_count, p.ransomware),
            ("APT Activity", apt_count, p.apt),
            ("Exploits/POC", exploit_count, p.exploit),
            ("IOCs Listed", ioc_count, p.text),
            ("Incoming (1h)", new_count, p.text),
            ("Avg/Hour", f"{rate:.0f}/hr", p.text),
        ]
        # Which feed sets are loaded: curated (vetted) vs custom and community contributions
        source_counts = Counter(a.get("source_file", "curated") for a in window_alerts)
        total_sources = sum(source_counts.values()) or 1
        sources_right = [Text("SOURCES", style=f"bold {p.accent}")]
        for key, label in (("curated", "Curated"), ("custom", "Custom"), ("community", "Community")):
            n = source_counts.get(key, 0)
            line = Text(f"{label} ", style=p.text if n else p.muted)
            line.append(str(n), style=p.muted)
            sources_right.append(line)
            meter = self.bar(n / total_sources * 100, p.accent if n else p.muted, width=12)
            meter.append(f" {int(n / total_sources * 100)}%", style=p.muted)
            sources_right.append(meter)
        
        metrics_table = Table(show_header=False, box=None, expand=True, padding=(0, 1))
        metrics_table.add_column(no_wrap=True, ratio=1)
        metrics_table.add_column(no_wrap=True, ratio=1)
        for i in range(max(len(metrics_list), len(sources_right))):
            left = Text()
            if i < len(metrics_list):
                label, value, color = metrics_list[i]
                left.append(f"{label:<13} ", style=p.muted)
                left.append(str(value), style=f"bold {color}" if value not in (0, "0/hr") else p.muted)
            metrics_table.add_row(left, sources_right[i] if i < len(sources_right) else Text(""))
        
        # --- Heat meters ---
        def pct_of(n):
            return n / filtered_count * 100 if filtered_count else 0
        total_threats = critical_count + zeroday_count + ransomware_count + apt_count + exploit_count
        heat_pct = pct_of(total_threats)
        # Weighted score: zero-days 5x, critical/KEV 4x, ransomware & APT 3x, exploits 2x
        weighted = critical_count * 4 + zeroday_count * 5 + (ransomware_count + apt_count) * 3 + exploit_count * 2
        master_pct = min(100, weighted / (filtered_count * 17) * 100) if filtered_count else 0
        defcon = 5 if master_pct < 20 else 4 if master_pct < 40 else 3 if master_pct < 60 else 2 if master_pct < 80 else 1
        last_zeroday_time = max((a["ts"] for a in window_alerts if a["severity"] == "zeroday"), default=None)
        time_since_zeroday = f"{age(last_zeroday_time)} ago" if last_zeroday_time else "none in window"
        # 0% at the farthest setting ever (17 minutes, 1991), 100% at midnight
        doomsday_pct = max(0, min(100, (1 - self.doomsday_seconds / 1020) * 100))
        
        meters = [
            ("Heat Level", f"{int(heat_pct)}%", heat_pct, p.level(heat_pct)),
            ("Ransomware", f"{int(pct_of(ransomware_count))}%", pct_of(ransomware_count), p.ransomware),
            ("APT", f"{int(pct_of(apt_count))}%", pct_of(apt_count), p.apt),
            ("Zero-Day", f"{int(pct_of(zeroday_count))}%", pct_of(zeroday_count), p.zeroday),
            ("Exploit", f"{int(pct_of(exploit_count))}%", pct_of(exploit_count), p.exploit),
            ("Doomsday", f"{self.doomsday_seconds}s", doomsday_pct, p.bad),
            (f"DEFCON {defcon}", f"{int(master_pct)}%", master_pct, p.level(master_pct)),
        ]
        try:
            inner_width = self.query_one("#dashboard").size.width - 4
        except Exception:
            inner_width = 44
        # One line per meter: label, bar, value
        bar_width = max(8, inner_width - 11 - 6)
        lines = [Text("")]
        for label, value, pct, color in meters:
            row = Text(f"{label:<11}", style=f"bold {p.text}")
            row.append_text(self.bar(pct, color, width=bar_width))
            row.append(f" {value:>4}", style=p.muted)
            lines.append(row)
        
        # --- Recent breaches (HIBP) ---
        lines.append(Text(""))
        lines.append(Text("RECENT BREACHES", style=f"bold {p.accent}"))
        self.breach_urls = []
        for breach in breach_list:
            name = breach.get("Title", "Unknown")
            name = name if len(name) <= 20 else name[:19] + "…"
            count = breach.get("PwnCount", 0)
            count_str = f"{count / 1e6:.1f}M" if count >= 1e6 else f"{count / 1e3:.0f}K" if count >= 1e3 else str(count)
            self.breach_urls.append(f"https://haveibeenpwned.com/?q={name.replace(' ', '+')}")
            row = Text(f"{name:<21}", style=p.text)
            row.append(f"{breach.get('AddedDate', '')[5:10]:<6}", style=p.muted)
            row.append(f"{count_str:>7}", style=p.accent)
            lines.append(row)
        if not breach_list:
            lines.append(Text("Fetching breach data...", style=p.muted))
        
        # --- Insights ---
        insights = []
        if total_threats:
            name, _ = max({"Ransomware": ransomware_count, "APT": apt_count, "Zero-Day": zeroday_count,
                           "Exploitation": exploit_count, "Critical": critical_count}.items(), key=lambda x: x[1])
            color = {"Ransomware": p.ransomware, "APT": p.apt, "Zero-Day": p.zeroday,
                     "Exploitation": p.exploit, "Critical": p.critical}[name]
            insights.append(("Dominant threat", f"{name} wave", color))
        insights.append(("Last zero-day", time_since_zeroday, p.zeroday if last_zeroday_time else p.muted))
        
        # Alert Velocity - alerts published in the last 24h vs the 24h before. Each feed only
        # keeps its newest items, so only count feeds whose history reaches back 48h;
        # otherwise busy feeds make every day look like a spike.
        oldest = {}
        for a in dated_alerts:
            oldest[a["source"]] = min(oldest.get(a["source"], a["ts"]), a["ts"])
        covered = [a for a in dated_alerts if oldest[a["source"]] <= now - timedelta(hours=48)]
        last_day = sum(1 for a in covered if a["ts"] > now - timedelta(hours=24))
        prev_day = sum(1 for a in covered if now - timedelta(hours=48) < a["ts"] <= now - timedelta(hours=24))
        if prev_day:
            ratio = last_day / prev_day
            status, color = (("Spiking", p.bad) if ratio > 1.5 else ("Increasing", p.warn) if ratio > 1.2
                             else ("Cooling", p.good) if ratio < 0.7 else ("Steady", p.text))
            insights.append(("Alert velocity", f"{status} ({last_day} vs {prev_day} prior day)", color))
        else:
            insights.append(("Alert velocity", "not enough history", p.muted))
        
        vectors = Counter()
        for alert in window_alerts:
            title_lower = alert["title"].lower()
            vectors.update(v for v in ("Malware", "Ransomware", "Web", "Exploit", "Phishing", "Email") if v.lower() in title_lower)
        if vectors:
            vector, n = vectors.most_common(1)[0]
            insights.append(("Primary vector", f"{vector} ({int(n / max(filtered_count, 1) * 100)}%)", p.text))
        
        victims = [m for m in (RANSOM_VICTIM_RE.match(a["title"]) for a in window_alerts
                               if a["title"].startswith("RANSOMWARE VICTIM")) if m]
        if victims:
            countries = Counter(m.group(2) for m in victims if m.group(2))
            if countries:
                code, n = countries.most_common(1)[0]
                insights.append(("Ransom hotspot", f"{COUNTRY_NAMES.get(code, code)} ({n} of {len(victims)} victims)", p.ransomware))
            group, n = Counter(m.group(1) for m in victims).most_common(1)[0]
            insights.append(("Top group", f"{group.upper()} ({n} victims)", p.ransomware))
        
        insight_grid = Table.grid(expand=True, padding=(0, 1))
        insight_grid.add_column(no_wrap=True, style=p.muted)
        insight_grid.add_column(ratio=1)
        for label, value, color in insights:
            insight_grid.add_row(label, Text(value, style=f"bold {color}"))
        
        # --- Activity: dated alerts per hour over the last 24h, oldest on the left ---
        hourly = [0] * 24
        for a in dated_alerts:
            hours_ago = int((now - a["ts"]).total_seconds() // 3600)
            if 0 <= hours_ago < 24:
                hourly[23 - hours_ago] += 1
        peak = max(hourly) or 1
        blocks = "▁▂▃▄▅▆▇█"
        spark = Text()
        for n in hourly:
            # Quiet hours stay visible as a muted baseline
            spark.append(blocks[max(1, min(7, round(n / peak * 7)))] if n else blocks[0], style=p.accent if n else p.border)
        activity = [Text("ACTIVITY", style=f"bold {p.accent}") + Text(f"  last 24h · peak {peak}/hr", style=p.muted),
                    Text("24h ", style=p.muted) + spark + Text(" now", style=p.muted)]
        
        # --- Top CVEs: most independent sources in the window, KEV first on ties ---
        cve_sources = {}
        for a in window_alerts:
            for cve in set(m.upper() for m in CVE_RE.findall(f"{a['title']} {a['summary']}")):
                cve_sources.setdefault(cve, set()).add(a["source"])
        top_cves = sorted(cve_sources.items(), key=lambda kv: (-len(kv[1]), kv[0] not in KEV_CATALOG, kv[0]))[:3]
        cve_lines = [Text("TOP CVEs", style=f"bold {p.accent}") + Text("  by number of sources", style=p.muted)]
        for cve, sources in top_cves:
            row = Text(f"{cve:<17}", style=p.text)
            row.append(" KEV " if cve in KEV_CATALOG else "     ", style=f"bold {p.bg} on {p.bad}" if cve in KEV_CATALOG else "")
            row.append(f" {len(sources)} src", style=p.muted)
            if cve in cve_intel.EPSS:
                prob = cve_intel.EPSS[cve][0] * 100
                row.append(f"  EPSS {prob:.0f}%" if prob >= 10 else f"  EPSS {prob:.1f}%",
                           style=p.bad if prob >= 10 else p.warn if prob >= 1 else p.muted)
            cve_lines.append(row)
        if not top_cves:
            cve_lines.append(Text("No CVEs mentioned in this window", style=p.muted))
        
        # Sections in display order; when space is short, drop the lowest priority first
        breaches_start = lines.index(next(l for l in lines if l.plain == "RECENT BREACHES")) - 1
        sections = [
            ("metrics", [metrics_table], 0),
            ("meters", lines[:breaches_start], 0),
            ("breaches", lines[breaches_start:], 3),
            ("insights", [Text(""), insight_grid], 2),
            ("activity", [Text(""), *activity], 1),
            ("cves", [Text(""), *cve_lines], 1),
        ]
        try:
            available = self.query_one("#dashboard").size.height - 2
            measure = Console(width=max(20, self.query_one("#dashboard").size.width - 4), file=io.StringIO())
            heights = {name: len(measure.render_lines(Group(*parts), pad=False)) for name, parts, _ in sections}
            for name, _, priority in sorted(sections, key=lambda s: -s[2]):
                if priority == 0 or sum(heights[n] for n, _, _ in sections) <= available:
                    break
                sections = [sec for sec in sections if sec[0] != name]
        except Exception:
            pass  # Not mounted yet; render everything
        
        title, border = self.frame("WAR ROOM DASHBOARD", self.panel_focus == "dashboard")
        return Panel(Group(*(part for _, parts, _ in sections for part in parts)),
                     title=title, border_style=border, box=box.ROUNDED, padding=(0, 1))
    
    def make_feed_status_panel(self):
        """Failed and auto-disabled feeds, paginated"""
        p = self.palette
        total = len(CONFIG.sources)
        broken = len(failed_feeds) + len(disabled_feeds)
        body = [Text(f"{total - broken} of {total} feeds healthy", style=f"bold {p.good if not broken else p.text}"), Text("")]
        
        entries = [("failed", name, f"{msg}", f"{count}/7 failures") for name, (msg, count) in sorted(failed_feeds.items())]
        entries += [("disabled", name, msg, reason) for name, (msg, reason) in sorted(disabled_feeds.items())]
        per_page = 8
        total_pages = max(1, (len(entries) + per_page - 1) // per_page)
        self.dashboard_page_offset = max(0, min(self.dashboard_page_offset, total_pages - 1))
        section = None
        for kind, name, msg, detail in entries[self.dashboard_page_offset * per_page:(self.dashboard_page_offset + 1) * per_page]:
            if kind != section:
                section = kind
                heading = "FAILED THIS CYCLE" if kind == "failed" else "AUTO-DISABLED (press e to re-enable)"
                body.append(Text(heading, style=f"bold {p.warn if kind == 'failed' else p.bad}"))
            line = Text(f"{name}  ", style=p.text)
            line.append(detail, style=p.muted)
            body.append(line)
            body.append(Text(f"  {msg[:60]}", style=p.muted))
        
        title_str = "FEED STATUS" + (f" · page {self.dashboard_page_offset + 1}/{total_pages}" if total_pages > 1 else "")
        title, border = self.frame(title_str, self.panel_focus == "dashboard")
        hints = [("←→", "pages"), ("e", "re-enable")] if total_pages > 1 else [("e", "re-enable"), ("r", "refresh")]
        return Panel(Group(*body), title=title, subtitle=self.hint_bar(hints),
                     border_style=border, box=box.ROUNDED, padding=(1, 2))
    
    def current_incidents(self):
        """Incidents for the current window and feed source, rebuilt only when those change"""
        key = (id(alert_queue), self.recency_hours)
        if key != self.incidents_key:
            cutoff_time = datetime.now(timezone.utc) - timedelta(hours=self.recency_hours)
            alerts = [a for a in alert_queue if a["ts"] >= cutoff_time]
            self.incidents = build_incidents(alerts, KEV_CATALOG)
            self.incidents_key = key
        return self.incidents
    
    def incident_block(self, inc, incidents, width, now, selected):
        """Lines describing one incident"""
        p = self.palette
        
        def labeled(label, value, value_style=p.text):
            line = Text(f"    {label + ':':<9}", style=p.muted)
            line.append(value, style=value_style)
            line.truncate(width, overflow="ellipsis")
            return line
        
        lines = []
        header = Text()
        header.append("▶ " if selected else "  ", style=f"bold {p.accent}")
        # Incident headers get a filled badge; Cold War keeps reverse video for FLASH only
        badge_style = p.badge(inc.severity) if p.monochrome else f"bold {p.bg} on {p.severity(inc.severity)}"
        header.append(f" {p.severity_name(inc.severity)} ", style=badge_style)
        header.append(f"  {KIND_LABELS[inc.kind]} ", style=p.muted)
        header.append(inc.value, style=f"bold {p.accent if selected else p.text}" + (" underline" if selected else ""))
        if inc.kev:
            header.append("  KNOWN EXPLOITED", style=f"bold {p.bad}")
        if inc.kind == "cve":
            # Scores only (the CVE ID and KEV status are already in the header)
            header.append_text(self.cve_scores(inc.value, scores_only=True))
        n_src = len(inc.sources)
        header.append(f"   {n_src} source{'s' if n_src != 1 else ''} · {len(inc.alerts)} alerts · latest {age(inc.last_seen, now)} ago",
                      style=p.muted)
        lines.append(header)
        
        lines.append(Text(f"    {inc.headline}"[:width], style=f"bold {p.text}"))
        what_lines = textwrap.wrap(inc.what, width=width - 13, max_lines=3, placeholder=" ...")
        for i, line in enumerate(what_lines):
            lines.append(labeled("What", line) if i == 0 else Text(f"{'':13}{line}", style=p.text))
        lines.append(labeled("Why", inc.why))
        first = min(inc.alerts, key=lambda a: a["ts"])
        lines.append(labeled("When", f"first {age(inc.first_seen, now)} ago ({first['source']}) → "
                                     f"latest {age(inc.last_seen, now)} ago ({inc.timeline[0]['source']})"))
        related = inc.related(incidents)
        if related:
            lines.append(labeled("Related", ", ".join(related), p.accent))
        for a in inc.timeline[:2]:
            row = Text(f"{'':13}{age(a['ts'], now):>3}  ", style=p.muted)
            row.append(f"{a['source'][:22]:<23}", style=p.muted)
            row.append(a["title"], style=p.text)
            row.truncate(width, overflow="ellipsis")
            lines.append(row)
        lines.append(Text(""))
        return lines
    
    def make_incidents_panel(self):
        """Correlated incidents with the context needed to act on them"""
        now = datetime.now(timezone.utc)
        incidents = self.current_incidents()
        p = self.palette
        
        try:
            available = max(12, self.query_one("#feeds-container").size.height - 6)
        except Exception:
            available = 30
        width = max(40, self.size.width * 3 // 4 - 10)
        
        # Fill pages by actual block height so the panel isn't left half empty
        heights = [len(self.incident_block(inc, incidents, width, now, False)) for inc in incidents]
        pages, current, used = [], [], 0
        for i, h in enumerate(heights):
            if current and used + h > available:
                pages.append(current)
                current, used = [], 0
            current.append(i)
            used += h
        pages.append(current)
        total_pages = len(pages)
        self.incident_page_offset = max(0, min(self.incident_page_offset, total_pages - 1))
        page = [incidents[i] for i in pages[self.incident_page_offset]]
        self.hover_row = min(self.hover_row, len(page) - 1)
        
        lines = []
        self.incident_rows = []
        for idx, inc in enumerate(page):
            start = len(lines)
            lines.extend(self.incident_block(inc, incidents, width, now, idx == self.hover_row))
            self.incident_rows.append((inc, start, len(lines) - 1))
        
        if not page:
            lines.append(Text("No correlated incidents in this window.", style=f"bold {p.text}"))
            lines.append(Text("An incident needs the same CVE, IP or hash reported by two or more sources,", style=p.muted))
            lines.append(Text("or a named threat actor appearing in several alerts. Try a longer data age (d).", style=p.muted))
        
        status = Text(f" {len(incidents)} incidents from {len(self.filtered_alerts())} alerts   ", style=p.muted)
        hints = [("↑↓", "select"), ("Enter", "open latest report")]
        if total_pages > 1:
            hints.append(("←→", f"page {self.incident_page_offset + 1}/{total_pages}"))
        status.append_text(self.hint_bar(hints))
        status.append(" ")
        
        title_text, border = self.frame("CORRELATED INCIDENTS", self.panel_focus == "main")
        return Panel(Group(*lines), title=title_text, subtitle=status,
                     border_style=border, box=box.ROUNDED, padding=(1, 2))
    
    def action_refresh(self):
        """Force refresh feeds"""
        force_event.set()
    
    def action_show_help(self):
        """Show help screen"""
        self.push_screen(HelpScreen(self.palette))
    
    def make_api_tools_panel(self) -> Panel:
        """Display unified API enrichment tools for multiple providers - interactive query panel"""
        p = self.palette
        content = Text()
        
        # Provider info with tier information
        providers_info = {
            "abuseipdb": {
                "name": "AbuseIPDB",
                "accepts": "IPs",
                "tier_note": "(Free tier: IP lookups only)"
            },
            "virustotal": {
                "name": "VirusTotal",
                "accepts": "IPs, hashes, domains, URLs",
                "tier_note": "(Free tier: 4 lookups/min, 500/day)"
            },
            "pulsedive": {
                "name": "Pulsedive",
                "accepts": "IPs, domains, hashes, URLs",
                "tier_note": "(Free tier: limited indicator database)"
            },
            "abusech": {
                "name": "Abuse.ch",
                "accepts": "Hashes, URLs, IPs, domains",
                "tier_note": "(Free Auth-Key: MalwareBazaar + URLhaus)"
            }
        }
        
        # Show which providers are configured
        configured = [k for k in providers_info.keys() if k in enrichment_engine.providers]
        unconfigured = [k for k in providers_info.keys() if k not in enrichment_engine.providers]
        
        if not configured:
            # No providers configured
            content.append("NO PROVIDERS CONFIGURED\n\n", style=f"bold {p.warn}")
            content.append("Available providers:\n\n", style=p.text)
            for key in providers_info.keys():
                info = providers_info[key]
                tier_note = info.get("tier_note", "")
                content.append(f"  {info['name']}: {info['accepts']}\n", style=p.muted)
                if tier_note:
                    content.append(f"    {tier_note}\n", style=p.muted)
            content.append("\nTo enable: Add API keys to cybrwire_local.yaml and restart.\n", style=p.muted)
            content.append("\nNote: Free/limited tier accounts have restrictions on indicator types.\n", style=p.warn)
            content.append("      Upgrade to paid plans for full IOC database access.\n", style=p.warn)
            
        else:
            # Show input field
            content.append("ENRICHMENT QUERY\n", style=f"bold {p.accent}")
            
            if self.api_tools_loading:
                content.append(f"[⏳ Querying] {self.api_tools_input_buffer}\n\n", style=f"bold {p.warn}")
            else:
                # Input prompt
                input_style = f"bold {p.accent}"
                cursor = "█" if len(self.api_tools_input_buffer) > 0 or self.api_tools_input_mode else ""
                content.append(f"Indicator: {self.api_tools_input_buffer}{cursor}\n", style=input_style)
            
            # Provider status line
            provider_line = "Providers: "
            for provider in configured:
                name = providers_info[provider]['name']
                tier_note = providers_info[provider].get("tier_note", "")
                provider_line += f"{name}  "
            
            if unconfigured:
                provider_line += f"[disabled: {', '.join([providers_info[p]['name'] for p in unconfigured])}]"
            
            content.append(f"\n{provider_line}\n", style=p.muted)
            
            # Results section
            if self.api_tools_last_query and self.api_tools_last_results:
                content.append("RESULTS\n\n", style=f"bold {p.accent}")
                
                for provider_name, enrichment_data in self.api_tools_last_results.items():
                    if enrichment_data is None:
                        continue
                    
                    # Provider header
                    provider_info = providers_info.get(provider_name, {})
                    provider_display = provider_info.get("name", provider_name)
                    provider_text = provider_display
                    content.append(f"\n{provider_text}\n", style=f"bold {p.text}")
                    content.append("─" * 40 + "\n", style=p.muted)
                    
                    # Threat level with color
                    threat_level = enrichment_data.threat_level.value.upper()
                    threat_color = {"CLEAN": p.good, "LOW": p.good, "MEDIUM": p.warn,
                                    "HIGH": p.bad, "CRITICAL": p.critical}.get(threat_level, p.text)
                    
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
                                
                                content.append(f"  {field}: {value_str}\n", style=p.muted)
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
                                    
                                    content.append(f"  {key}: {value_str}\n", style=p.muted)
                    
                    content.append("\n", style="")
            elif self.api_tools_last_query and not self.api_tools_last_results:
                content.append("NO RESULTS\n", style=f"bold {p.accent}")
                content.append(f"No threat data found for: {self.api_tools_last_query}\n", style=p.muted)
            else:
                content.append("USAGE\n\n", style=f"bold {p.accent}")
                content.append("Type an indicator (IP, hash, domain, URL) and press ENTER to query all configured providers.\n", style=p.text)
                content.append("Results will display below with threat scores from each provider.\n", style=p.text)
                content.append("\nPress ESC to clear the query buffer.\n", style=p.muted)
                content.append("Press Ctrl+Shift+V to paste from clipboard.\n", style=p.muted)
                
                # Add API tier limitation note
                content.append("\nAPI TIER INFORMATION\n", style=f"bold {p.accent}")
                content.append("\nFree/limited API keys have restrictions on the indicator types they can query:\n\n", style=p.muted)
                content.append("  VirusTotal Free:  All indicator types, 4 lookups/min, 500/day\n", style=p.muted)
                content.append("  AbuseIPDB Free:   IP lookups only\n", style=p.muted)
                content.append("  Pulsedive Free:   Limited indicator database\n", style=p.muted)
                content.append("  Abuse.ch:         Free Auth-Key (hashes via MalwareBazaar; URLs/IPs/domains via URLhaus)\n", style=p.muted)
                content.append("\nCLEAN means the provider has no record of the indicator, not that it is safe.\n", style=p.muted)
            
        title_text, border = self.frame("API TOOLS · IOC ENRICHMENT", self.panel_focus == "main")
        return Panel(content, title=title_text, border_style=border, box=box.ROUNDED, padding=(1, 2))
    
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
    
    @property
    def active_kind(self) -> str:
        return CONTENT_KINDS[self.kind_index][0]
    
    def action_cycle_feeds(self):
        """Cycle content types: All → Advisories → News & Research → Ransomware → Indicators"""
        self.kind_index = (self.kind_index + 1) % len(CONTENT_KINDS)
        self.feed_page_offset = 0
        self.hover_row = -1
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
        ranked = [a for a in ranked if a.get("kind") != "indicators"][:60]
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
            STATE.briefing = {"text": self.ai_briefing, "time": self.ai_briefing_time.isoformat()}
            STATE.save()
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
        p = self.palette
        heading = f"bold {p.accent}"
        body = p.text
        dim = p.muted
        
        lines = []
        label = ai.describe(self.ai_settings) if self.ai_settings.get("provider") else "no provider"
        lines.append(Text(f"AI BRIEFING ({label})", style=heading))
        if self.ai_briefing_loading:
            lines.append(Text("⏳ Analyzing current alerts...", style=f"bold {p.warn}"))
        if self.ai_briefing_error:
            lines.append(Text(self.ai_briefing_error, style=f"bold {p.bad}"))
            if self.ai_problem:
                lines.append(Text("Configure the ai: section in cybrwire_local.yaml (see readme), then restart.", style=dim))
        if self.ai_briefing:
            lines.append(Text(f"Generated {age(self.ai_briefing_time)} ago ({self.ai_briefing_time:%a %d %b %H:%M} UTC) • press g to refresh", style=dim))
            for line in self.ai_briefing.split("\n"):
                stripped = line.strip()
                if stripped.endswith(":") and stripped[:-1].replace(" ", "").isupper():
                    if lines and lines[-1].plain:
                        lines.append(Text(""))
                    lines.append(Text(stripped, style=heading))
                elif stripped or (lines and lines[-1].plain):
                    lines.append(Text(line, style=body))
        elif not self.ai_briefing_loading and not self.ai_briefing_error:
            lines.append(Text("Press g to generate a briefing (one AI call).", style=dim))
        
        lines.append(Text(""))
        if self.threat_summary:
            for line in self.threat_summary_full.split("\n"):
                if line.startswith("─"):
                    lines.append(Text("─" * 30, style=dim))
                elif line.endswith(":") or line == "LOCAL KEYWORD ANALYSIS":
                    lines.append(Text(line, style=heading))
                else:
                    lines.append(Text(line, style=body if not ("CVE-" in line and "[" in line) else f"bold {p.text}"))
        
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
        title_text, border = self.frame(title_str, self.panel_focus == "dashboard")
        hints = [("←→", "pages"), ("g", "refresh")] if len(pages) > 1 else [("g", "refresh")]
        subtitle = self.hint_bar(hints)
        return Panel(Group(*pages[self.threat_summary_page]), title=title_text, subtitle=subtitle,
                     border_style=border, box=box.ROUNDED, padding=(1, 2), expand=True)
    
    def lookup_indicator(self, alert):
        """Send an indicator from the Indicators view to API Tools and run the lookup"""
        if not enrichment_engine.providers:
            self.notify("No enrichment providers configured (see usrwire.yaml)", timeout=4)
            return
        value = alert.get("ioc") or ""
        if alert.get("ioc_type") == "cidr":
            value = value.split("/")[0]
            self.notify("Looking up the network address of this range", timeout=3)
        STATE.mark_read(alert)
        self.main_view_mode = "api_tools"
        self.api_tools_input_mode = True
        self.api_tools_input_buffer = value
        self.api_tools_last_query = value
        self.api_tools_last_results = {}
        self.api_tools_loading = True
        asyncio.create_task(self._run_api_tools_query(value))
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
            self.mark_dirty()
    
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
            if alert and alert.get("kind") == "indicators":
                self.lookup_indicator(alert)
                return
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
        """Cycle through the color themes (Cold War is separate, on 'c')"""
        keys = list(PALETTES)
        current_idx = keys.index(self.theme_mode) if self.theme_mode in keys else 0
        self.theme_mode = keys[(current_idx + 1) % len(keys)]
        if self.cold_war_mode:
            self.cold_war_mode = False  # 't' means "show me the themes"
        self.apply_theme()
        self.save_settings()
        self.notify(f"Theme: {self.palette.name}", timeout=2)
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
            # Outer panel border + top padding = 2 rows before the first alert (+1 header in Indicators)
            row = event.y - 2 - (1 if self.active_kind == "indicators" else 0)
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
