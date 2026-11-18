"""The full-window screens: help, and the loading screen with its animated banner."""

from rich.text import Text
from textual.app import ComposeResult
from textual.containers import Container
from textual.screen import Screen
from textual.widgets import Static

from . import __version__
from .widgets import CardButton

EDITION = f"v{__version__} LEGENDARY // EDITION"


def boxed(text: str, width: int = 104) -> str:
    """One line of the startup banner box, centred"""
    return "║" + text.center(width) + "║"


class ScrollableContainer(Container):
    """Scrollable container for help screen"""
    
    DEFAULT_CSS = """
    ScrollableContainer {
        background: $background;
        height: 100%;
        overflow-y: auto;
    }
    """


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
        yield CardButton("Close help", id="help-close")
        yield ScrollableContainer(Static(id="help-content"))
    
    def on_button_pressed(self, event) -> None:
        event.stop()
        self.action_close_help()
    
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
        help_text.append(" " * 30 + f"C Y B R W I R E  {__version__}  H E L P  S C R E E N\n", style=f"bold {color}")
        help_text.append("═" * 100 + "\n\n", style=color)
        help_text.append("Press ESC or 'Q' to close help\n\n", style=self.palette.muted)
        
        # NAVIGATION & CONTROLS
        help_text.append("┌─ NAVIGATION & CONTROLS " + "─" * 72 + "┐\n", style=accent)
        help_text.append("│\n", style=accent)
        help_text.append("│  [GENERAL]\n", style=f"bold {accent}")
        help_text.append("│    ↑/↓           Select an alert or incident (the alert preview shows its summary)\n", style=color)
        help_text.append("│    Click         Select a row, click it again to open it. Footer commands are clickable\n", style=color)
        help_text.append("│    Right-click   In either panel, does what V does there. The wheel scrolls and turns pages\n", style=color)
        help_text.append("│    ← →           Jump a screen in the Feed and Incidents, change page in the War Room\n", style=color)
        help_text.append("│    Enter         Open the selected alert (or an incident's latest report) in your browser\n", style=color)
        help_text.append("│    Shift+K       Enter, test and secure API keys and notification URLs\n", style=color)
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
        help_text.append("│    All (default) - Advisories, news, ransomware and active outages (indicators have their own view)\n", style=color)
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
        help_text.append("│    Items Seen        - Everything loaded in the data window\n", style=color)
        help_text.append("│    Alerts            - What the default Alerts filter shows: evidence, watchlist hits, breaches\n", style=color)
        help_text.append("│    Confirmed         - On an official exploited list (CISA KEV, ENISA)\n", style=color)
        help_text.append("│    Likely            - High exploit-likelihood score, or public exploit code and a raised score\n", style=color)
        help_text.append("│    Reported          - News or a CIRCL sighting says exploited, not officially confirmed\n", style=color)
        help_text.append("│    Ransomware        - Ransomware claims and stories\n", style=color)
        help_text.append("│    Exploits          - Exploitation reported, or public exploit code. Blocklists don't count\n", style=color)
        help_text.append("│    IOCs Listed       - IP addresses, URLs and domains on blocklists\n", style=color)
        help_text.append("│    Incoming (1h)     - New items in the last 60 minutes\n", style=color)
        help_text.append("│\n", style=accent)
        help_text.append("│  [HEAT LEVELS]\n", style=f"bold {accent}")
        help_text.append("│    Heat Level        - % of total alerts that are high-threat (critical+severe)\n", style=color)
        help_text.append("│    Ransomware Heat   - % of ransomware threats (rising = ransomware wave)\n", style=color)
        help_text.append("│    APT Heat          - % of APT activity (rising = targeted campaigns)\n", style=color)
        help_text.append("│    Zero-Day Heat     - % of zero-day vulns (rising = day-zero activity spike)\n", style=color)
        help_text.append("│    Exploit Heat      - % with exploitation or exploit code (rising = mass exploitation risk)\n", style=color)
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
        help_text.append("│  [PROVIDERS] (Shift+K)\n", style=f"bold {accent}")
        help_text.append("│    anthropic, gemini, openai, openrouter, ollama (local), openai_compatible\n", style=color)
        help_text.append("│    Press Shift+K to choose a provider and add its key\n", style=color)
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
        help_text.append("│    Press Shift+K to enter and test keys; they go to your system keychain\n", style=color)
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
        help_text.append("│    Themes: Neon Noir (default), Synthwave, Retro Warm, Amber CRT\n", style=color)
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
        help_text.append("│  4              Content Type - All / Advisories / News & Research / Ransomware / Indicators / Outages\n", style=color)
        help_text.append("│  /              Search - Filter as you type, across all feeds and history; Esc clears it\n", style=color)
        help_text.append("│  w              Watchlist Only - Show only items matching your watchlist (marked ★)\n", style=color)
        help_text.append("│  Shift+W        Watchlist Card - See all terms and their hits, add or remove them\n", style=color)
        help_text.append("│  L              Live Wire - Jump to what's on the top bar (or click the bar)\n", style=color)
        help_text.append("│  Z              World Clock - Show or hide your time and reference cities (see readme to change them)\n", style=color)
        help_text.append("│  M              Threat Map - Full-window world map of ransomware victims and outages (also in the right panel with V)\n", style=color)
        help_text.append("│  B              Alert Sound - Off, PC speaker, teletype bell, modem chirp or terminal bell\n", style=color)
        help_text.append("│  U              Group Duplicates - Merge the same story from several feeds (marked +N)\n", style=color)
        help_text.append("│  I              CVE Card - CVSS, EPSS, KEV and exploit details for the selected item\n", style=color)
        help_text.append("│  Tab            Switch Panel Focus - Toggle between left and right panels\n", style=color)
        help_text.append("│  V              Toggle View in Focused Panel - Switch between Alerts / Incidents / API Tools\n", style=color)
        help_text.append("│  E              Re-enable Feeds - Re-enable all auto-disabled feeds\n", style=color)
        help_text.append("│  C              Toggle Cold War Mode - Switch between colorful and green-only\n", style=color)
        help_text.append("│  G              AI Briefing - Generate a fresh briefing in the War Room\n", style=color)
        help_text.append("│  A              Explain Alert - AI explanation of the selected alert\n", style=color)
        help_text.append("│  T              Cycle Theme - Neon Noir / Synthwave / Retro Warm / Amber CRT (leaves Cold War mode)\n", style=color)
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


class LoadingScreen(Screen):
    """Loading screen with animated ASCII art"""
    
    def __init__(self, palette, current_feed=lambda: None, configured_apis=()):
        super().__init__()
        self.palette = palette
        self.current_feed = current_feed  # Name of the feed being checked right now, or None
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
        self.configured_apis = list(configured_apis)  # Shown under "CHECKING APIS..."
    
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
                (boxed(f"{EDITION} // *COLD*WAR*MODE*"), "green"),
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
                (boxed(EDITION), "#ff00ff"),
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
                feed_name = self.current_feed() or "INITIALIZING"
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
