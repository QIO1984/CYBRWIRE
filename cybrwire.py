#!/usr/bin/env python3
import asyncio
import feedparser
import httpx
import json
import logging
import re
import time
import os
import sys
import yaml
import webbrowser
import google.genai as genai
from datetime import datetime, timedelta, timezone
from typing import Dict, Any
from rich.console import Console, Group
from rich.table import Table
from rich.text import Text
from rich.theme import Theme
from rich.panel import Panel
from rich import box
from collections import deque
from enrichment import enrichment_engine, initialize_enrichment
from textual.app import App, Screen, ComposeResult
from textual.widgets import Static, Header
from textual.containers import Container, Horizontal, VerticalScroll
from textual.reactive import reactive
from textual import events

# Configure logging to suppress noisy library logs (httpx, etc.)
logging.basicConfig(level=logging.WARNING, format='%(message)s')
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

def check_configured_apis():
    """Check which APIs are configured in cybrwire_local.yaml and usrwire.yaml (enrichment section)"""
    configured_apis = []
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    # API key field mappings: config_field -> display_name
    api_key_mappings = {
        'gemini_api_key': 'GEMINI',
        'abuseipdb_api_key': 'ABUSEIPDB',
        'virustotal_api_key': 'VIRUSTOTAL',
        'pulsedive_api_key': 'PULSEDIVE',
        'abuse_ch_api_key': 'ABUSE.CH'
    }
    
    # Check cybrwire_local.yaml first (local testing keys)
    local_secrets_path = os.path.join(script_dir, "cybrwire_local.yaml")
    try:
        if os.path.exists(local_secrets_path):
            with open(local_secrets_path, 'r') as f:
                data = yaml.safe_load(f) or {}
                enrichment = data.get('enrichment', {})
                for config_key, display_name in api_key_mappings.items():
                    if enrichment.get(config_key):
                        configured_apis.append(display_name)
    except Exception as e:
        pass
    
    # Check usrwire.yaml for production keys
    usrwire_path = os.path.join(script_dir, "usrwire.yaml")
    try:
        if os.path.exists(usrwire_path):
            with open(usrwire_path, 'r') as f:
                data = yaml.safe_load(f) or {}
                enrichment = data.get('enrichment', {})
                for config_key, display_name in api_key_mappings.items():
                    if enrichment.get(config_key) and display_name not in configured_apis:
                        configured_apis.append(display_name)
    except Exception as e:
        pass
    
    return configured_apis

def load_sources():
    """Load sources from YAML files (curated, custom, community, local secrets)"""
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
                    for src_key, src_list in data.items():
                        if isinstance(src_list, list):
                            for src in src_list:
                                src["source_file"] = src_key  # Tag with source category
                                sources.append(src)
        except Exception as e:
            logging.error(f"Failed to load {yaml_path}: {e}")
    
    local_secrets_path = os.path.join(script_dir, "cybrwire_local.yaml")
    try:
        if os.path.exists(local_secrets_path):
            with open(local_secrets_path, 'r') as f:
                data = yaml.safe_load(f) or {}
                for src_key, src_list in data.items():
                    if isinstance(src_list, list):
                        for src in src_list:
                            src["source_file"] = src_key  # Tag with source category
                            sources.append(src)
    except Exception as e:
        logging.warning(f"Local secrets file not found or error loading {local_secrets_path}: {e}")
    
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
        return [s for s in all_sources if s.get("source_file") == feed_source]

SOURCES = load_sources()

# ========== INCIDENT CORRELATION ENGINE ==========
class Incident:
    """Represents a correlated group of related alerts (an incident)"""
    _incident_id_counter = 1000
    
    def __init__(self, name, severity, ioc_type, ioc_value):
        self.incident_id = Incident._incident_id_counter
        Incident._incident_id_counter += 1
        self.name = name  # Human-readable incident name
        self.severity = severity  # critical, high, medium, low
        self.status = "open"  # open, investigating, resolved
        self.created_at = datetime.now(timezone.utc)
        self.updated_at = datetime.now(timezone.utc)
        self.related_alerts = []  # List of alert dicts
        self.related_iocs = []  # List of IOCs (IPs, hashes, URLs)
        self.attack_chain = []  # Timeline of events
        self.tags = []  # Tags for categorization
        self.notes = ""  # Investigation notes
        self.ioc_type = ioc_type  # "cve", "ip", "hash", "url", "actor", "domain"
        self.ioc_value = ioc_value  # The actual value (CVE-2024-..., 192.168.1.1, etc.)
    
    def add_alert(self, alert):
        """Add an alert to this incident"""
        if alert not in self.related_alerts:
            self.related_alerts.append(alert)
            self.updated_at = datetime.now(timezone.utc)
    
    def add_ioc(self, ioc_type, ioc_value):
        """Add an IOC to this incident's list"""
        ioc = {"type": ioc_type, "value": ioc_value}
        if ioc not in self.related_iocs:
            self.related_iocs.append(ioc)
    
    def update_severity(self):
        """Auto-update severity based on related alerts"""
        if not self.related_alerts:
            return
        severities = ["critical", "zeroday", "ransomware", "apt", "exploit", "info"]
        severity_ranks = {"critical": 0, "zeroday": 1, "ransomware": 2, "apt": 3, "exploit": 4, "info": 5}
        
        alert_severities = [a.get("severity", "info") for a in self.related_alerts]
        worst_severity = min(alert_severities, key=lambda s: severity_ranks.get(s, 99))
        self.severity = worst_severity
    
    def get_timeline(self):
        """Get timeline of alerts sorted by date"""
        sorted_alerts = sorted(self.related_alerts, key=lambda a: a.get("ts", datetime.now(timezone.utc)))
        return sorted_alerts


def extract_iocs_from_alert(alert):
    """Extract IOCs (IP, hash, URL, CVE) from an alert"""
    iocs = []
    title = alert.get("title", "").upper()
    summary = alert.get("summary", "").upper()
    text = f"{title} {summary}"
    
    cve_matches = re.findall(r'CVE-\d{4}-\d{4,5}', text)
    for cve in cve_matches:
        iocs.append(("cve", cve))
    
    ip_matches = re.findall(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b', text)
    for ip in ip_matches:
        if not ip.startswith("255"):
            iocs.append(("ip", ip))
    
    md5_matches = re.findall(r'\b[a-fA-F0-9]{32}\b', text)
    for md5 in md5_matches:
        iocs.append(("hash", md5))
    
    sha1_matches = re.findall(r'\b[a-fA-F0-9]{40}\b', text)
    for sha1 in sha1_matches:
        iocs.append(("hash", sha1))
    
    sha256_matches = re.findall(r'\b[a-fA-F0-9]{64}\b', text)
    for sha256 in sha256_matches:
        iocs.append(("hash", sha256))
    
    domain_matches = re.findall(r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b', text.lower())
    for domain in domain_matches:
        if domain not in iocs and not domain.startswith("www"):
            iocs.append(("domain", domain))
    
    return iocs


def generate_incidents_from_alerts(alert_list, active_source="all"):
    """
    Correlate alerts into incidents by CVE, IP, hash, domain, and attack patterns
    Returns list of Incident objects
    """
    incidents = []
    cve_incidents = {}
    ip_incidents = {}
    hash_incidents = {}
    domain_incidents = {}
    
    if active_source != "all":
        filtered_alerts = [a for a in alert_list if a.get("source_file") == active_source]
    else:
        filtered_alerts = alert_list
    
    for alert in filtered_alerts:
        iocs = extract_iocs_from_alert(alert)
        
        for ioc_type, ioc_value in iocs:
            if ioc_type == "cve":
                if ioc_value not in cve_incidents:
                    # Create new CVE incident
                    incident = Incident(
                        name=f"CVE Incident: {ioc_value}",
                        severity=alert.get("severity", "info"),
                        ioc_type="cve",
                        ioc_value=ioc_value
                    )
                    cve_incidents[ioc_value] = incident
                    incidents.append(incident)
                
                cve_incidents[ioc_value].add_alert(alert)
    
    for alert in filtered_alerts:
        iocs = extract_iocs_from_alert(alert)
        
        for ioc_type, ioc_value in iocs:
            if ioc_type == "ip":
                if ioc_value not in ip_incidents:
                    incident = Incident(
                        name=f"IP Activity: {ioc_value}",
                        severity=alert.get("severity", "info"),
                        ioc_type="ip",
                        ioc_value=ioc_value
                    )
                    ip_incidents[ioc_value] = incident
                    incidents.append(incident)
                
                ip_incidents[ioc_value].add_alert(alert)
    
    for alert in filtered_alerts:
        iocs = extract_iocs_from_alert(alert)
        
        for ioc_type, ioc_value in iocs:
            if ioc_type == "hash":
                if ioc_value not in hash_incidents:
                    incident = Incident(
                        name=f"Hash Match: {ioc_value[:16]}...",
                        severity=alert.get("severity", "info"),
                        ioc_type="hash",
                        ioc_value=ioc_value
                    )
                    hash_incidents[ioc_value] = incident
                    incidents.append(incident)
                
                hash_incidents[ioc_value].add_alert(alert)
    
    for incident in incidents:
        incident.update_severity()
    
    # Sort by severity (critical first) and then by most recent
    severity_rank = {"critical": 0, "zeroday": 1, "ransomware": 2, "apt": 3, "exploit": 4, "info": 5}
    incidents.sort(key=lambda x: (
        severity_rank.get(x.severity, 99),
        -x.updated_at.timestamp()
    ))
    
    return incidents
# ========== END INCIDENT CORRELATION ENGINE ==========

# Global state
alert_queue = []
alert_history = deque(maxlen=100)
breach_list = []
source_cache = {}
source_file_stats = {"curated": 0, "custom": 0, "community": 0}
failed_feeds = {}  # Tracks current cycle failures: {feed_name: (error_msg, failure_count)}
disabled_feeds = {}  # Tracks disabled feeds: {feed_name: (error_msg, disable_reason)}
currently_loading = None
incidents_cache = []
start_time = datetime.now(timezone.utc)
ticker_offset = 0
ticker_counter = 0
border_color = "bright_magenta"
last_critical = None
force_event = asyncio.Event()
active_feed_source = "all"

def is_blog_post_content(title: str, summary: str, source_name: str) -> bool:
    """
    Detect if content is a blog post/educational material rather than threat intelligence.
    Returns True if it's a blog post, False if it's actual threat intelligence.
    """
    combined_text = (title + " " + summary).lower()
    
    # Strong indicators it's NOT threat intelligence (blog/educational content)
    blog_keywords = [
        # Tutorial/educational
        "tutorial", "guide", "how to", "how-to", "getting started", "quick start",
        "introduction to", "beginners", "learn", "step by step", "step-by-step",
        "advanced guide", "advanced tips", "best practices", "tips and tricks",
        
        # General news/announcements
        "announces", "announced", "launches", "launched", "releases", "released",
        "celebrates", "celebrates", "wins award", "awarded", "named one of",
        "interview", "podcast", "webinar", "conference", "summit", "newsletter",
        
        # Product reviews/comparisons
        "review", "comparison", "benchmark", "testing", "hands-on",
        "first look", "unboxing", "impressions", "pros and cons",
        
        # Opinion pieces
        "opinion", "perspective", "why we", "why i", "my thoughts", "i think",
        "controversial", "debate", "discussion forum", "poll", "tips", "tricks",
        
        # Marketing/PR/News
        "case study", "success story", "customer story", "white paper",
        "infographic", "report", "ebook", "free download",
        "news", "news brief", "this week in", "roundup", "wrap-up", "highlights",
        "state of", "best of", "top ", "trends", "insights",
        
        # Open source / general tech topics (usually not threat intel)
        "open source", "collaboration", "community", "ecosystem",
        
        # General company/tech news (not threat-related)
        "meta", "google", "facebook", "microsoft", "amazon", "apple"
    ]
    
    # Strong indicators it IS threat intelligence (keep it)
    threat_keywords = [
        # CVE/Vulnerability
        "cve-", "vulnerability", "vuln", "patch", "critical flaw",
        "zero-day", "0-day", "zeroday", "n-day",
        
        # Active threats
        "exploit", "poc", "proof of concept", "actively exploited",
        "in the wild", "wild", "actively being exploited",
        
        # Malware/APT
        "malware", "ransomware", "trojan", "worm", "botnet", "rootkit",
        "apt", "threat actor", "threat group", "cybercriminal",
        "lockbit", "conti", "blackcat", "akira", "clop", "lazarus",
        
        # Attack/Incident
        "breach", "attack", "compromised", "hacked", "incident",
        "data leak", "leaked", "stolen data", "ransomware gang",
        
        # Indicators
        "ioc", "indicator", "iocs", "malicious ip", "malicious domain",
        "c2", "c&c", "command and control", "payload",
        
        # Security research/analysis in threat context (specific phrases)
        "vulnerability research", "threat analysis", "malware analysis", "reverse engineering",
        
        # Advisories/Warnings
        "advisory", "alert", "warning", "urgent", "immediate action",
        "critical patch", "security update", "hotfix"
    ]
    
    # Count keyword matches
    threat_score = sum(1 for kw in threat_keywords if kw in combined_text)
    blog_score = sum(1 for kw in blog_keywords if kw in combined_text)
    
    # If it has threat keywords, it's threat intel (don't filter)
    if threat_score >= 1:
        return False  # It's threat intel, not a blog post
    
    # If it has 2+ blog keywords or specific blog indicators, it's a blog post
    if blog_score >= 2:
        return True  # It's a blog post
    
    # Single strong blog keyword might still be a blog post
    if blog_score == 1:
        # These keywords are strong enough on their own
        strong_blog_keywords = ["tutorial", "guide", "how to", "how-to", "getting started",
                               "interview", "podcast", "review", "white paper", "case study",
                               "newsletter", "state of", "best of", "open source", "collaboration",
                               "community", "ecosystem"]
        if any(kw in combined_text for kw in strong_blog_keywords):
            return True
    
    # Default: if ambiguous, assume it's threat intel (don't filter out)
    return False

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
        
        # Filter out blog posts and non-threat content
        if is_blog_post_content(title, summary, source_name):
            continue  # Skip this item - it's a blog post, not threat intel
        
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
        help_text.append("│    ↑/↓           Select alerts in current view\n", style=color)
        help_text.append("│    ← →           Change pages in paginated views (Feed, Incidents, War Room)\n", style=color)
        help_text.append("│    Enter         Open selected alert in browser\n", style=color)
        help_text.append("│    Tab           Switch between left panel (alerts) and right panel (dashboard)\n", style=color)
        help_text.append("│    V             Toggle between Alerts, Incidents, and API Tools views\n", style=color)
        help_text.append("│\n", style=accent)
        help_text.append("│  [VIEW PANELS]\n", style=f"bold {accent}")
        help_text.append("│    V             Cycle through focused dashboard panels:\n", style=color)
        help_text.append("│                  0 = War Room Dashboard\n", style=color)
        help_text.append("│                  1 = Gemini Analysis (AI Threat Analysis)\n", style=color)
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
        help_text.append("│    All (default) - All sources combined (95 feeds total)\n", style=color)
        help_text.append("│\n", style=accent)
        help_text.append("│  [FEED MANAGEMENT] (Press 'E' to re-enable)\n", style=f"bold {accent}")
        help_text.append("│    Auto-Disable  - Feeds that fail 7 consecutive times are auto-disabled\n", style=color)
        help_text.append("│    Re-enable     - Press 'E' to re-enable all disabled feeds at once\n", style=color)
        help_text.append("│    Feed Status   - View (7) then (2) to see failed/disabled feeds dashboard\n", style=color)
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
        help_text.append("│    Alerts/Hour       - Velocity (rate of new alerts per hour)\n", style=color)
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
        help_text.append("│    Doomsday Clock    - Fictional 89-second countdown (always shows max threat)\n", style=color)
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
        help_text.append("┌─ WAR ROOM: AI-POWERED THREAT ANALYSIS " + "─" * 54 + "┐\n", style=accent)
        help_text.append("│\n", style=accent)
        help_text.append("│  [WHAT IS WAR ROOM?]\n", style=f"bold {accent}")
        help_text.append("│    AI-powered threat intelligence using Google Gemini API\n", style=color)
        help_text.append("│    Analyzes current alerts to identify patterns, priorities, and threats\n", style=color)
        help_text.append("│\n", style=accent)
        help_text.append("│  [HOW TO ACCESS]\n", style=f"bold {accent}")
        help_text.append("│    1. Press Tab to switch to right panel (dashboard)\n", style=color)
        help_text.append("│    2. Press number 7 to cycle dashboard panels to War Room (panel 1)\n", style=color)
        help_text.append("│    Press G to refresh the AI analysis (updates from current alerts)\n", style=color)
        help_text.append("│\n", style=accent)
        help_text.append("│  [WHAT IT SHOWS]\n", style=f"bold {accent}")
        help_text.append("│    Top CVEs          - Most frequently appearing vulnerabilities\n", style=color)
        help_text.append("│    Affected Software - Which products/services are most at risk\n", style=color)
        help_text.append("│    Exploit Maturity  - What exploits are in-the-wild vs POC vs under development\n", style=color)
        help_text.append("│    Threat Actors     - Known APT/ransomware groups detected in alerts\n", style=color)
        help_text.append("│    Industry Targeting- Which sectors are being targeted (Healthcare, Finance, etc)\n", style=color)
        help_text.append("│    Vuln Chains       - Multiple CVEs being exploited in coordinated attacks\n", style=color)
        help_text.append("│\n", style=accent)
        help_text.append("│  [REQUIREMENTS]\n", style=f"bold {accent}")
        help_text.append("│    GEMINI_API_KEY set in usrwire.yaml (enrichment: section)\n", style=color)
        help_text.append("│    If not configured, War Room shows notification\n", style=color)
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
        help_text.append("│    Press Ctrl+Shift+V to submit query\n", style=color)
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
        help_text.append("│  [INCIDENT DETAIL ELEMENTS]\n", style=f"bold {accent}")
        help_text.append("│    [INC-####]           Incident ID (unique identifier for threat group)\n", style=color)
        help_text.append("│    SEVERITY             Alert severity level (INFO, CRITICAL, HIGH, etc)\n", style=color)
        help_text.append("│    [INDICATOR_TYPE]     Type in brackets: [HASH], [IP], [DOMAIN], [CVE], [URL]\n", style=color)
        help_text.append("│    VALUE                Actual indicator value (IOC - Indicator of Compromise)\n", style=color)
        help_text.append("│    Updated X ago        How recently this threat was last seen/updated\n", style=color)
        help_text.append("│    N alerts             Number of alerts associated with this incident\n", style=color)
        help_text.append("│\n", style=accent)
        help_text.append("│  [STAT] Statistics Section:\n", style=f"bold {accent}")
        help_text.append("│    ⊕HH:MM:SS           First occurrence timestamp (⊕ = start time)\n", style=color)
        help_text.append("│    Last:XX              Last confirmed activity time\n", style=color)
        help_text.append("│    Peak:LEVEL           Peak intensity (INF = ongoing/infinite)\n", style=color)
        help_text.append("│    Age:HH:MM:SS         Total age/lifespan of this threat\n", style=color)
        help_text.append("│    Summary:TEXT         Intelligence summary from analysis\n", style=color)
        help_text.append("│\n", style=accent)
        help_text.append("│  [CHAIN] Correlation Section:\n", style=f"bold {accent}")
        help_text.append("│    Topics:CVE-XXXX      Associated CVE vulnerabilities\n", style=color)
        help_text.append("│    Feeds:SOURCE         Which intelligence feed(s) reported it\n", style=color)
        help_text.append("│\n", style=accent)
        help_text.append("│  [STATUS] Indicator:\n", style=f"bold {accent}")
        help_text.append("│    ⊚ OPEN               Threat is active/unresolved\n", style=color)
        help_text.append("│    ◉ CLOSED             Threat resolved/mitigated\n", style=color)
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
        help_text.append("│  G              Refresh War Room - Re-analyze current alerts with Gemini AI\n", style=color)
        help_text.append("│  T              Cycle Theme - Switch color themes (normal mode only)\n", style=color)
        help_text.append("│  H              Show This Help - Display help screen\n", style=color)
        help_text.append("│  Q / Esc        Quit / Close Help - Exit application or close help screen\n", style=color)
        help_text.append("│\n", style=accent)
        help_text.append("└" + "─" * 98 + "┘\n\n", style=accent)
        
        # TIPS & FEATURES
        help_text.append("┌─ TIPS & FEATURES " + "─" * 77 + "┐\n", style=accent)
        help_text.append("│\n", style=accent)
        help_text.append("│  PAGINATION        - Most views support pagination with ← → arrow keys\n", style=color)
        help_text.append("│  INCIDENTS VIEW    - Auto-correlates alerts by CVE, IP, hash, and domain\n", style=color)
        help_text.append("│  LIVE TICKER       - Shows critical threats scrolling at the top (updates live)\n", style=color)
        help_text.append("│  BREACH DATABASE   - Shows latest data breaches from Have I Been Pwned (HIBP)\n", style=color)
        help_text.append("│  VELOCITY TRACKING - Monitors alert rate changes and forecasts trends\n", style=color)
        help_text.append("│  ATTACK VECTORS    - Identifies most common attack methods in current data\n", style=color)
        help_text.append("│  GEO HOTSPOTS      - Infers likely geographic sources of threats\n", style=color)
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
        self.configured_apis = check_configured_apis()  # Check which APIs are available
    
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
        ("g", "gemini_refresh", "Gemini Refresh"),
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
        self.cold_war_mode = cold_war
        self.recency_hours = recency
        self.refresher_task = None
        self.alert_urls = []
        self.breach_urls = []
        self.incident_source_urls = []
        self.feed_page_offset = 0
        self.incident_page_offset = 0
        self.hover_row = -1
        self.rows_per_page = 20
        self.filter_mode = "all"
        self.theme_mode = "textual-ansi"
        
        self.feed_failure_counts = {}  # Track consecutive failures per feed
        
        # Initialize threat summary cache
        self.threat_summary = None
        self.threat_summary_timestamp = None
        self.threat_summary_loading = False
        self.threat_summary_pages = []  # Paginated content
        self.threat_summary_page = 0  # Current page
        
        # Initialize AbuseIPDB lookup cache
        self.abuseipdb_last_query = ""  # Last queried IP
        self.abuseipdb_last_result = None  # Last AbuseIPDB result
        self.abuseipdb_loading = False  # Is AbuseIPDB query in progress
        self.abuseipdb_input_mode = False  # Waiting for user IP input
        self.abuseipdb_input_buffer = ""  # Accumulate IP input
        
        # Initialize API Tools panel state
        self.api_tools_input_buffer = ""  # User input for IOC query
        self.api_tools_last_query = ""  # Last queried indicator
        self.api_tools_last_results = {}  # Results from all providers {provider: EnrichmentData}
        self.api_tools_loading = False  # Is query in progress
        self.api_tools_input_mode = True  # Always in input mode in this panel
        
        # Initialize Gemini API - check cybrwire_local.yaml and usrwire.yaml (enrichment section)
        gemini_key = None
        
        # Try cybrwire_local.yaml first (local testing keys)
        try:
            script_dir = os.path.dirname(os.path.abspath(__file__))
            local_secrets_path = os.path.join(script_dir, "cybrwire_local.yaml")
            if os.path.exists(local_secrets_path):
                with open(local_secrets_path, 'r') as f:
                    data = yaml.safe_load(f) or {}
                    enrichment = data.get('enrichment', {})
                    if enrichment.get('gemini_api_key'):
                        gemini_key = enrichment['gemini_api_key']
        except Exception as e:
            pass
        
        # Try usrwire.yaml if not found in local config
        if not gemini_key:
            try:
                script_dir = os.path.dirname(os.path.abspath(__file__))
                usrwire_path = os.path.join(script_dir, "usrwire.yaml")
                if os.path.exists(usrwire_path):
                    with open(usrwire_path, 'r') as f:
                        data = yaml.safe_load(f) or {}
                        enrichment = data.get('enrichment', {})
                        if enrichment.get('gemini_api_key'):
                            gemini_key = enrichment['gemini_api_key']
            except Exception as e:
                pass
        
        if gemini_key:
            self.gemini_client = genai.Client(api_key=gemini_key)
            self.gemini_model = "gemini-2.5-flash"  # Model name as string
            self.ai_cache = {}  # Cache AI responses
        else:
            self.gemini_client = None
            self.gemini_model = None
            self.ai_cache = {}
            logging.warning("GEMINI_API_KEY not found in cybrwire_local.yaml or usrwire.yaml (enrichment section)")
        
        # Set footer color based on cold war mode
        self.footer_color = "#00FF00" if self.cold_war_mode else "#55bbdd"
        
        # Initialize next refresh time
        self.next_refresh = datetime.now(timezone.utc) + timedelta(seconds=REFRESH_INTERVAL)
        
        if self.cold_war_mode:
            self.add_class("cold-war")
        
        self._initializing = False  # Allow watchers to work now
    
    def refresh_threat_summary(self):
        """Refresh threat summary (wrapper for async loading)"""
        asyncio.create_task(self._load_threat_summary_async())
    
    def _should_refresh_gemini_data(self, timestamp):
        """Check if Gemini data is older than 1 hour and needs refresh"""
        if timestamp is None:
            return True  # Never loaded
        elapsed = datetime.now(timezone.utc) - timestamp
        return elapsed.total_seconds() > 3600  # 1 hour in seconds
    
    def action_gemini_refresh(self):
        """Refresh current Gemini analysis panel (g key)"""
        if self.dashboard_panel_index == 1:  # War room (threat summary)
            asyncio.create_task(self._load_threat_summary_async())
    
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
        """Load AI-powered threat summary asynchronously"""
        if self.threat_summary_loading:
            return
        
        self.threat_summary_loading = True
        try:
            top_alerts = [a for a in alert_queue if a.get('severity') in ['critical', 'zeroday', 'ransomware', 'apt', 'exploit', 'high', 'medium']][:10]
            
            if top_alerts:
                # Run all analysis methods to get comprehensive intelligence
                top_cves = self.analyze_top_cves(alert_queue)
                threat_actors = self.analyze_threat_actors(alert_queue)
                attack_surface = self.analyze_attack_surface(alert_queue)
                vuln_chains = self.analyze_vulnerability_chains(alert_queue)
                exploit_maturity = self.analyze_exploit_maturity(alert_queue)
                industry_targeting = self.analyze_industry_targeting(alert_queue)
                
                # Build combined analysis text - ordered for optimal pagination
                analysis_text = []
                analysis_text.append("THREAT INTELLIGENCE ANALYSIS")
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
                analysis_text.append(f"Total Alerts Analyzed: {len(alert_queue)} | High Priority: {len(top_alerts)}")
                analysis_text.append("─" * 70)
                
                # For now: show everything on one page to verify all content is generated
                full_text = "\n".join(analysis_text)
                
                # Split into pages - 40 lines per page
                pages = []
                lines = analysis_text
                lines_per_page = 40
                
                for i in range(0, len(lines), lines_per_page):
                    page_lines = lines[i:i + lines_per_page]
                    pages.append("\n".join(page_lines))
                
                self.threat_summary_pages = pages if pages else [full_text]
                self.threat_summary_page = 0  # Reset to first page
                self.threat_summary = self.threat_summary_pages[0] if self.threat_summary_pages else "No data"
                self.threat_summary_timestamp = datetime.now(timezone.utc)
            else:
                self.threat_summary_pages = []
                self.threat_summary_page = 0
                self.threat_summary = "Waiting for threat data to arrive..."
                self.threat_summary_timestamp = datetime.now(timezone.utc)
        except Exception as e:
            import traceback
            error_msg = f"Error: {str(e)}\n{traceback.format_exc()}"
            logging.error(error_msg)
            self.threat_summary = f"Error loading summary: {str(e)[:100]}"
            self.threat_summary_timestamp = datetime.now(timezone.utc)
        finally:
            self.threat_summary_loading = False
            # Schedule the UI refresh on the main event loop
            self.call_later(lambda: self.query_one("#dashboard").refresh(recompose=True))
    

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
    
    def _initialize_enrichment(self):
        """Initialize enrichment engine with API keys from local config, fallback to usrwire.yaml"""
        try:
            enrichment_config = {}
            script_dir = os.path.dirname(__file__)
            
            # Try to load from cybrwire_local.yaml first (local secrets with testing keys)
            local_config_path = os.path.join(script_dir, "cybrwire_local.yaml")
            enrichment_config = self._load_enrichment_keys(local_config_path)
            
            # If not found or incomplete, fall back to usrwire.yaml (production keys)
            if not enrichment_config:
                usrwire_path = os.path.join(script_dir, "usrwire.yaml")
                enrichment_config = self._load_enrichment_keys(usrwire_path)
                if enrichment_config:
                    pass
            else:
                pass
            
            # Initialize enrichment engine
            if enrichment_config:
                initialize_enrichment(enrichment_config)
            else:
                pass
        
        except Exception as e:
            logging.error(f"Failed to initialize enrichment: {e}")
    
    def _load_enrichment_keys(self, config_path: str) -> dict:
        """
        Load and transform enrichment API keys from YAML file.
        
        Transforms from YAML format:
            enrichment:
              abuseipdb_api_key: "value"
              virustotal_api_key: "value"
        
        To internal format expected by initialize_enrichment():
            {"abuseipdb": {"api_key": "value"}, ...}
        """
        enrichment_config = {}
        
        if not os.path.exists(config_path):
            return enrichment_config
        
        try:
            with open(config_path, 'r') as f:
                data = yaml.safe_load(f) or {}
            
            enrichment_section = data.get("enrichment", {})
            if not enrichment_section:
                return enrichment_config
            
            # Map YAML key names to provider names and extract API keys
            key_mappings = {
                'abuseipdb_api_key': 'abuseipdb',
                'virustotal_api_key': 'virustotal',
                'pulsedive_api_key': 'pulsedive',
                'abuse_ch_api_key': 'abusech',
            }
            
            for yaml_key, provider_name in key_mappings.items():
                api_key = enrichment_section.get(yaml_key)
                if api_key:  # Only add if key is not empty
                    enrichment_config[provider_name] = {"api_key": api_key}
            
        except Exception as e:
            logging.warning(f"Error loading enrichment keys from {config_path}: {e}")
        
        return enrichment_config
    
    async def enrich_indicator(self, indicator: str, indicator_type: str = "ip") -> Dict[str, Any]:
        """
        Enrich an indicator (IP, hash, domain, etc) using configured providers
        
        Args:
            indicator: The IOC to enrich
            indicator_type: Type of indicator ("ip", "hash", "domain", "url")
        
        Returns:
            Dict with enrichment results from all providers
        """
        try:
            # Check if we have any providers configured
            if not enrichment_engine.providers:
                return {}
            
            # Query enrichment engine (async)
            results = await enrichment_engine.enrich(indicator, indicator_type)
            
            return results
        except Exception as e:
            logging.error(f"Error enriching {indicator}: {e}")
            return {}
        
    def on_mount(self) -> None:
        """Show loading screen then start app"""
        # Apply initial theme
        self.apply_theme()
        
        # Show loading screen
        self.push_screen(LoadingScreen(self.cold_war_mode))
        
        # Start background refresh
        self.refresher_task = asyncio.create_task(self.initial_load())
        
        # Schedule threat summary load after UI is ready
    
    async def initial_load(self):
        """Initial data load with loading screen"""
        global alert_queue, alert_history
        
        # Suppress any stdout/stderr output during loading to keep loading screen clean
        import io
        import contextlib
        
        old_stdout = sys.stdout
        old_stderr = sys.stderr
        output_buffer = io.StringIO()
        
        try:
            # Redirect all output to buffer
            sys.stdout = output_buffer
            sys.stderr = output_buffer
            
            try:
                # Wait for first data fetch
                await self.fetch_feeds()
                
                # Initialize enrichment engine with local config
                self._initialize_enrichment()
                
                await fetch_breaches()
                
                # Populate initial history for last 5 hours with current count
                # This gives immediate velocity data instead of waiting 5 hours
                now = datetime.now(timezone.utc)
                current_count = len(alert_queue)
                for i in range(5, 0, -1):
                    timestamp = now - timedelta(hours=i)
                    alert_history.append((timestamp, current_count))
                
                # Wait minimum time for loading screen effect
                await asyncio.sleep(3)
                
                # Still suppressed - pop screen with output suppressed
                self.pop_screen()
                self.is_loading = False
            finally:
                # Restore stdout/stderr AFTER screen pop and all data loading
                sys.stdout = old_stdout
                sys.stderr = old_stderr
                
                # Discard any buffered output that tried to escape
                output_buffer.close()
            
            # Now that output is restored, do remaining operations WITHOUT logging
            # Force an immediate update
            self.call_later(self.update_display)
            
            # Load threat summary at startup (main dashboard needs it)
            # Correlation and ranking load on-demand when user navigates to those panels
            asyncio.create_task(self._load_threat_summary_async())
            
            # Start refresh loop
            asyncio.create_task(self.refresher())
            
            # Start UI updates
            self.set_interval(0.5, self.update_display)
            self.set_interval(0.7, self.animate_ticker)
        except Exception as e:
            # Make sure output is restored even on error
            sys.stdout = old_stdout
            sys.stderr = old_stderr
            logging.error(f"Error in initial_load: {e}", exc_info=True)
            import traceback
            traceback.print_exc()
            raise
        
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
        global alert_queue, alert_history, source_cache, source_file_stats, active_feed_source, failed_feeds, disabled_feeds, currently_loading
        
        new = []
        source_file_stats = {"curated": 0, "custom": 0, "community": 0}
        failed_feeds = {}
        
        all_sources = get_active_sources("all")
        
        async with httpx.AsyncClient(headers=HEADERS, timeout=30, follow_redirects=True) as c:
            for src in all_sources:
                src_name = src['name']
                
                if src_name in disabled_feeds:
                    continue
                
                try:
                    currently_loading = src_name
                    r = await c.get(src["url"])
                    r.raise_for_status()
                    
                    source_file = src.get("source_file", "curated")
                    if src["type"] == "json":
                        parsed = parse_cisa(r.json(), src_name, source_file)
                    elif src["type"] == "rss":
                        parsed = parse_rss(r.text, src_name, source_file)
                    elif src["type"] == "txt":
                        parsed = parse_txt(r.text, src_name, source_file)
                    
                    new.extend(parsed)
                    source_file_stats[source_file] = source_file_stats.get(source_file, 0) + len(parsed)
                except Exception as e:
                    error_msg = str(e)
                    
                    if src_name in self.feed_failure_counts:
                        self.feed_failure_counts[src_name] += 1
                    else:
                        self.feed_failure_counts[src_name] = 1
                    
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
        
        # Generate incidents from alerts (correlation engine)
        global incidents_cache
        incidents_cache = generate_incidents_from_alerts(alert_queue, "all")
    
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
#                logging.info("Force refresh completed")
            except asyncio.TimeoutError:
                # Normal automatic refresh - track in history
                await self.fetch_feeds()
                await fetch_breaches()
                alert_history.append((datetime.now(timezone.utc), len(alert_queue)))
                self.is_loading = False  # Clear loading flag after fetch
#                logging.info("Automatic refresh completed")
            self.next_refresh = datetime.now(timezone.utc) + timedelta(seconds=REFRESH_INTERVAL)
    
    def update_display(self):
        """Update the UI display"""
        if self.is_loading:
            return
        
        try:
            
            # Update ticker
            ticker_widget = self.query_one("#ticker", Static)
            ticker_content = self.make_ticker()
            ticker_widget.update(ticker_content)
            
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
        
        # Apply solid green color to ticker text
        visible_text = ticker_str[offset:offset + visible_width]
        
        # Build text with color - respecting cold war mode
        # Use curated metric green (#66cc66) in normal mode, pure green (#00ff00) in cold war
        color = "#00ff00" if self.cold_war_mode else "#66cc66"
        ticker_text = Text(visible_text, style=f"bold {color} on black")
        
        return Panel(ticker_text, title="LIVE THREAT TAPE", 
                    border_style="#00ff00" if self.cold_war_mode else "#66cc66", padding=0)
    
    def is_alert(self, item):
        """Classify item as alert vs blog post"""
        # Simple rule: INFO = blog post, everything else = alert
        return item["severity"] != "info"
    
    def make_feeds_table(self):
        """Create feeds table with pagination"""
        now = datetime.now(timezone.utc)
        cutoff_time = now - timedelta(hours=self.recency_hours)
        
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
        
        table = Table(box=box.DOUBLE, show_header=False, padding=(0,1), expand=True, border_style="#4499bb" if not self.cold_war_mode else "#00FF00")
        
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
        self.alert_row_mapping = {}  # Map row index to alert URL
        
        for row_idx, a in enumerate(page_alerts):
            # Muted cybrwire.py theme colors (increased saturation)
            severity_colors = {
                "critical": "bold white on #dd4444" if not self.cold_war_mode else "bold white on #00FF00",         
                "zeroday": "bold black on #e6d144" if not self.cold_war_mode else "bold white on #00FF00",        
                "ransomware": "bold black on #dd4488" if not self.cold_war_mode else "bold white on #00FF00",     
                "apt": "bold black on #b866cc" if not self.cold_war_mode else "bold white on #00FF00",            
                "exploit": "bold #dd5555" if not self.cold_war_mode else "bold #00FF00",                   
                "info": "#55bbdd" if not self.cold_war_mode else "#00FF00"                            
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
                    title_style = "#00FF00"
                    severity_style = "#00FF00"
                    date_style = "#00FF00"
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
            
            # Store URL for this row - both in list and in mapping
            url = a.get("url", "")
            self.alert_urls.append(url)
            self.alert_row_mapping[rows_added] = url
            
            table.add_row(
                Text(a["published"], style=date_style),
                Text(a["severity"].upper(), style=severity_style), 
                title_text
            )
            rows_added += 1
        
        
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
        status.append(f" — Next: {m:02d}:{s:02d}", "bold green" if self.cold_war_mode else "bold bright_red")
        status.append(f" — Uptime: {uptime}", "bold green" if self.cold_war_mode else "bold white")
        status.append(f" — ↑/↓ to select  |  Enter to open", "bold green" if self.cold_war_mode else "bold magenta")
        
        if total_pages > 1:
            status.append(f"  |  ← → to change pages", "bold green" if self.cold_war_mode else "bold cyan")
        
        # Add focus indicator with highlighted style when focused
        if self.panel_focus == "main":
            # Show colored background when focused
            bg_color = "#00ff00" if self.cold_war_mode else "#44ccaa"
            # Show page number in title when focused and paginated
            if total_pages > 1:
                title_str = f"C Y B R W I R E 1.0 // Global Threat Feed - Page {current_page}/{total_pages}{' // *COLD*WAR*MODE*' if self.cold_war_mode else ''}"
            else:
                title_str = f"C Y B R W I R E 1.0 // Global Threat Feed{' // *COLD*WAR*MODE*' if self.cold_war_mode else ''}"
            title_text = Text(title_str, style=f"bold black on {bg_color}")
        else:
            # No background when not focused
            title_text = f"C Y B R W I R E 1.0 // Global Threat Feed{' // *COLD*WAR*MODE*' if self.cold_war_mode else ''}"
        
        return Panel(table, 
                    title=title_text,
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
                velocity_color = "bold #dd4444" if not self.cold_war_mode else "bold #00ff00"
            elif velocity > 1.2:
                velocity_status = "INCREASING"
                velocity_color = "#dd5555" if not self.cold_war_mode else "#00ff00"
            elif velocity < 0.7:
                velocity_status = "COOLING"
                velocity_color = "#66cc66" if not self.cold_war_mode else "#00ff00"
            else:
                velocity_status = "STEADY"
                velocity_color = "#e6d144" if not self.cold_war_mode else "#00ff00"
        else:
            velocity_status = "CALIBRATING"
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
            geo_color = "#00ff00" if self.cold_war_mode else geo_color
            heat_info += f"[{geo_color}]{indent}[bold]HOTSPOT: {geo_region}[/bold][/]\n"
        
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
    
    def make_incidents_panel(self):
        """Create incidents panel showing correlated incidents with rich details"""
        global incidents_cache, active_feed_source
        now = datetime.now(timezone.utc)
        
        # Filter incidents by active feed source
        if active_feed_source == "all":
            filtered_incidents = incidents_cache
        else:
            filtered_incidents = [inc for inc in incidents_cache 
                                if any(a.get("source_file") == active_feed_source for a in inc.related_alerts)]
        
        # Sort by most recent first (by updated_at)
        filtered_incidents = sorted(filtered_incidents, key=lambda x: x.updated_at, reverse=True)
        
        # Pagination - 7 incidents per page for compact display
        incidents_per_page = 7
        total_pages = max(1, (len(filtered_incidents) + incidents_per_page - 1) // incidents_per_page)
        
        # Clamp page offset
        self.incident_page_offset = max(0, min(self.incident_page_offset, total_pages - 1))
        
        start_idx = self.incident_page_offset * incidents_per_page
        end_idx = start_idx + incidents_per_page
        page_incidents = filtered_incidents[start_idx:end_idx]
        
        # Build incident source URL mapping for click handling
        self.incident_source_urls = []
        
        severity_colors = {
            "critical": "#dd4444",
            "zeroday": "#e6d144",
            "ransomware": "#dd4488",
            "apt": "#b866cc",
            "exploit": "#dd5555",
            "info": "#55bbdd"
        }
        
        incident_details = []
        
        if not page_incidents:
            incident_details.append(Text("No incidents to display", style="dim yellow"))
        else:
            for inc in page_incidents:
                # Build source URL map for this incident
                source_urls = {}
                for alert in inc.related_alerts:
                    source = alert.get("source", "Unknown")
                    url = alert.get("url", "")
                    if source not in source_urls and url:
                        source_urls[source] = url
                
                # Store incident with its source URLs for click handling
                self.incident_source_urls.append((inc.incident_id, source_urls))
                
                detail_group = []
                
                # ===== MAIN HEADER: ID, Severity, IOC + Right: Age & Count =====
                header = Text()
                header.append(f"[INC-{inc.incident_id}]", style="bold #00ff00" if self.cold_war_mode else "bold #55bbdd")
                header.append(" • ", style="dim")
                
                sev_color = severity_colors.get(inc.severity, "#555555")
                if self.cold_war_mode:
                    sev_color = "#00ff00"
                header.append(inc.severity.upper(), style="bold " + sev_color)
                header.append(" • ", style="dim")
                
                # Primary IOC
                ioc_icon = {
                    "cve": "[CVE]",
                    "ip": "[IP]",
                    "hash": "[HASH]",
                    "url": "[URL]",
                    "domain": "[DOM]",
                    "actor": "[ACT]"
                }.get(inc.ioc_type, "●")
                
                header.append(f"{ioc_icon} ", style=sev_color)
                header.append(inc.ioc_value[:50], style="bold #00FF00" if self.cold_war_mode else "bold #55bbdd")
                
                # Right side: Age and alert count
                age_str = str(now - inc.updated_at).split('.')[0]
                header.append("  |  ", style="dim")
                header.append(f"Updated {age_str} ago", style="dim #00ff00" if self.cold_war_mode else "dim #88cc88")
                header.append(f"  •  {len(inc.related_alerts)} alerts", style="dim #00ff00" if self.cold_war_mode else "dim #ddaa66")
                
                detail_group.append(header)
                
                # ===== METRICS LINE: Rich context info =====
                metrics_line = Text()
                
                # LEFT SIDE: Alert severity breakdown
                severity_counts = {}
                for alert in inc.related_alerts:
                    sev = alert.get("severity", "info")
                    severity_counts[sev] = severity_counts.get(sev, 0) + 1
                
                metrics_line.append("  [STAT] ", style="dim")
                sev_order = ["critical", "zeroday", "ransomware", "apt", "exploit"]
                sev_display = []
                for sev in sev_order:
                    if sev in severity_counts:
                        count = severity_counts[sev]
                        color = severity_colors.get(sev, "#555555")
                        if self.cold_war_mode:
                            color = "#00ff00"
                        sev_display.append((f"{count}×{sev[:3]}", color))
                
                for i, (part, color) in enumerate(sev_display):
                    metrics_line.append(part, style=color)
                    if i < len(sev_display) - 1:
                        metrics_line.append(" ", style="dim")
                
                # MIDDLE: Timeline and sources
                if inc.related_alerts:
                    sorted_alerts = sorted(inc.related_alerts, key=lambda a: a.get("ts", now))
                    oldest = sorted_alerts[0].get("ts", now)
                    newest = sorted_alerts[-1].get("ts", now)
                    span = newest - oldest
                    span_str = str(span).split('.')[0]
                    
                    metrics_line.append("  |  ", style="dim")
                    metrics_line.append("⏱ ", style="dim")
                    metrics_line.append(f"{span_str}", style="#55bbdd" if not self.cold_war_mode else "#00ff00")
                    
                    # Source count
                    sources = sorted(set(a.get("source", "Unknown") for a in inc.related_alerts))
                    metrics_line.append(" • ", style="dim")
                    metrics_line.append(f"{len(sources)}src", style="#66ccff" if not self.cold_war_mode else "#00ff00")
                    
                    # Last alert time
                    last_alert_time = newest
                    time_diff = now - last_alert_time
                    if time_diff.total_seconds() < 60:
                        last_str = "now"
                    elif time_diff.total_seconds() < 3600:
                        last_str = f"{int(time_diff.total_seconds()//60)}m"
                    else:
                        last_str = f"{int(time_diff.total_seconds()//3600)}h"
                    metrics_line.append(" • ", style="dim")
                    metrics_line.append(f"Last:{last_str}", style="#00ff00" if self.cold_war_mode else "#ffaa00")
                    
                    # Most critical severity
                    alert_severities = [a.get("severity", "info") for a in inc.related_alerts]
                    sev_order_check = ["critical", "zeroday", "ransomware", "apt", "exploit"]
                    most_critical = next((s for s in sev_order_check if s in alert_severities), "info")
                    crit_color = severity_colors.get(most_critical, "#555555")
                    if self.cold_war_mode:
                        crit_color = "#00ff00"
                    metrics_line.append(" • ", style="dim")
                    metrics_line.append(f"Peak:{most_critical[:3].upper()}", style=crit_color)
                    
                    # Incident age (created vs updated)
                    creation_age = now - inc.created_at
                    creation_str = str(creation_age).split('.')[0]
                    metrics_line.append(" • ", style="dim")
                    metrics_line.append(f"Age:{creation_str}", style="#88aa88" if not self.cold_war_mode else "#00ff00")
                    
                    # Summary from most critical alert
                    metrics_line.append("  •  ", style="dim")
                    metrics_line.append("Summary: ", style="dim")
                    # Find the most critical alert
                    critical_alert = None
                    for sev in sev_order_check:
                        critical_alert = next((a for a in inc.related_alerts if a.get("severity") == sev), None)
                        if critical_alert:
                            break
                    if critical_alert:
                        summary = critical_alert.get("summary", critical_alert.get("title", ""))[:160]
                        metrics_line.append(summary, style="#00ff00" if self.cold_war_mode else "#ccddee")
                        
                        # Extract exploit status and CVSS if available
                        alert_text = f"{critical_alert.get('title', '')} {critical_alert.get('summary', '')}".upper()
                        exploit_indicators = []
                        if "ZERO-DAY" in alert_text or "0-DAY" in alert_text:
                            exploit_indicators.append("0-day")
                        if "EXPLOITED" in alert_text or "IN THE WILD" in alert_text or "ACTIVE EXPLOITATION" in alert_text:
                            exploit_indicators.append("InTheWild")
                        if "CVSS" in alert_text:
                            import re as regex_module
                            cvss_match = regex_module.search(r'CVSS[:\s]+([0-9.]+)', alert_text)
                            if cvss_match:
                                exploit_indicators.append(f"CVSS:{cvss_match.group(1)}")
                        
                        if exploit_indicators:
                            metrics_line.append("  [", style="dim")
                            metrics_line.append(", ".join(exploit_indicators), style="#00ff00" if self.cold_war_mode else "#ff6666")
                            metrics_line.append("]", style="dim")
                    else:
                        metrics_line.append("No summary", style="dim")
                
                detail_group.append(metrics_line)
                
                # ===== IOC & ATTACK CHAIN LINE: Indicators and context =====
                ioc_chain_line = Text()
                
                # IOC type breakdown
                ioc_by_type = {}
                for ioc in inc.related_iocs:
                    ioc_type = ioc.get("type", "unknown")
                    if ioc_type not in ioc_by_type:
                        ioc_by_type[ioc_type] = 0
                    ioc_by_type[ioc_type] += 1
                
                ioc_chain_line.append("  [CHAIN] ", style="dim")
                ioc_parts = []
                for ioc_type in ["cve", "ip", "hash", "domain", "url"]:
                    if ioc_type in ioc_by_type:
                        count = ioc_by_type[ioc_type]
                        ioc_color = "#dd8866" if not self.cold_war_mode else "#00ff00"
                        ioc_parts.append((f"{count} {ioc_type.upper()}", ioc_color))
                
                for i, (part, color) in enumerate(ioc_parts):
                    ioc_chain_line.append(part, style=color)
                    if i < len(ioc_parts) - 1:
                        ioc_chain_line.append(" | ", style="dim")
                
                # Attack chain / purpose if available
                if inc.attack_chain:
                    ioc_chain_line.append("  •  ", style="dim")
                    ioc_chain_line.append("Purpose: ", style="dim")
                    chain_str = " → ".join(inc.attack_chain[:3])  # Show first 3 steps
                    ioc_chain_line.append(chain_str[:60], style="#00ff00" if self.cold_war_mode else "#bb88dd")
                elif inc.notes:
                    ioc_chain_line.append("  •  ", style="dim")
                    ioc_chain_line.append("Note: ", style="dim")
                    ioc_chain_line.append(inc.notes[:60], style="#00ff00" if self.cold_war_mode else "#aabbcc")
                else:
                    # Show most common alert topics
                    alert_titles = [a.get("title", "").split()[0] for a in inc.related_alerts if a.get("title")]
                    from collections import Counter
                    if alert_titles:
                        title_counter = Counter(alert_titles)
                        top_topics = [topic for topic, _ in title_counter.most_common(3)]
                        ioc_chain_line.append("  •  ", style="dim")
                        ioc_chain_line.append("Topics: ", style="dim")
                        ioc_chain_line.append(" • ".join(top_topics), style="#00ff00" if self.cold_war_mode else "#99ccee")
                
                # Add source feed names on the right side
                if inc.related_alerts:
                    sources = sorted(set(a.get("source", "Unknown") for a in inc.related_alerts))
                    ioc_chain_line.append("  |  ", style="dim")
                    ioc_chain_line.append("Feeds: ", style="dim")
                    source_display = []
                    for src in sources[:4]:  # Show first 4 sources
                        # Clean up source name (remove file extensions)
                        clean_src = src.replace(".yaml", "").replace(".json", "")
                        source_display.append(clean_src)
                    ioc_chain_line.append(", ".join(source_display), style="#88ccdd" if not self.cold_war_mode else "#00ff00")
                    if len(sources) > 4:
                        ioc_chain_line.append(f" +{len(sources)-4}", style="dim")
                    
                    # Extract affected systems/products from alert titles
                    systems = set()
                    for alert in inc.related_alerts:
                        title = alert.get("title", "")
                        # Look for common OS/software patterns
                        import re as regex_module
                        patterns = [
                            r'(Windows\s+(?:Server\s+)?(?:\d{4}|XP|7|10|11|Vista|8))',
                            r'(Linux|Ubuntu|CentOS|Debian|RHEL|Red\s+Hat)',
                            r'(Apache|Nginx|IIS|Tomcat|Node\.js)',
                            r'(Microsoft\s+\w+)',
                            r'(OpenSSL|OpenSSH|Log4j|Spring|Struts)'
                        ]
                        for pattern in patterns:
                            matches = regex_module.findall(pattern, title, regex_module.IGNORECASE)
                            for match in matches:
                                systems.add(match)
                    
                    if systems:
                        ioc_chain_line.append("  •  ", style="dim")
                        ioc_chain_line.append("Affected: ", style="dim")
                        affected_list = list(systems)[:3]
                        ioc_chain_line.append(", ".join(affected_list), style="#ddaa88" if not self.cold_war_mode else "#00ff00")
                    
                    # Extract threat actor if mentioned in tags or incident name
                    actor_tags = [tag for tag in inc.tags if any(x in tag.lower() for x in ["apt", "actor", "group", "lazarus", "apt-", "wizard", "dragon"])]
                    if actor_tags:
                        ioc_chain_line.append("  •  ", style="dim")
                        ioc_chain_line.append("Actors: ", style="dim")
                        ioc_chain_line.append(", ".join(actor_tags[:2]), style="#cc88dd" if not self.cold_war_mode else "#00ff00")
                    
                    # Extract geography if IP-based incidents
                    if inc.ioc_type == "ip":
                        # Check alerts for country mentions
                        countries = set()
                        for alert in inc.related_alerts:
                            text = f"{alert.get('title', '')} {alert.get('summary', '')}".upper()
                            # Common country patterns with emoji flags
                            country_patterns = {
                                "🇷🇺": ["RUSSIA", "RUSSIAN", "RU ", "AS12389"],
                                "🇨🇳": ["CHINA", "CHINESE", "CN "],
                                "🇰🇵": ["NORTH KOREA", "NK ", "DPRK"],
                                "🇮🇷": ["IRAN", "IRANIAN", "IR "],
                                "🇰🇷": ["SOUTH KOREA", "SK "],
                            }
                            for emoji, keywords in country_patterns.items():
                                if any(kw in text for kw in keywords):
                                    countries.add(emoji)
                        
                        if countries:
                            ioc_chain_line.append("  •  ", style="dim")
                            ioc_chain_line.append("Origin: ", style="dim")
                            ioc_chain_line.append(" ".join(countries), style="#88ddcc" if not self.cold_war_mode else "#00ff00")
                
                detail_group.append(ioc_chain_line)
                
                # ===== STATUS LINE (compact) =====
                status_line = Text()
                status_color = "#66ff66" if inc.status == "open" else "#00ff00" if inc.status == "investigating" else "#00ff00" if self.cold_war_mode else "#55bbdd"
                if self.cold_war_mode:
                    status_color = "#00ff00"
                
                status_line.append("  ⚙ ", style="dim")
                status_line.append(inc.status.upper(), style=status_color)
                
                if inc.tags:
                    status_line.append("  •  Tags: ", style="dim")
                    status_line.append(", ".join(inc.tags[:2]), style="#00ff00" if self.cold_war_mode else "#aabbcc")
                
                detail_group.append(status_line)
                
                # Add all lines to output
                for line in detail_group:
                    incident_details.append(line)
                incident_details.append(Text("", style="dim"))  # Blank line separator
        
        # Convert to Group for display
        content = Group(*incident_details) if incident_details else Text("No incidents to display", style="dim yellow")
        
        # Build status line
        status = Text()
        status.append(f"{datetime.now(timezone.utc):%H:%M:%S} UTC", "bold green" if self.cold_war_mode else "bold white")
        status.append(f" — {len(filtered_incidents)} incidents", "bold green" if self.cold_war_mode else "bold cyan")
        if total_pages > 1:
            status.append(f" — Page {self.incident_page_offset + 1}/{total_pages}", "bold green" if self.cold_war_mode else "bold yellow")
            status.append(f"  |  ← → to change pages", "bold green" if self.cold_war_mode else "bold cyan")
        status.append(f" — ↑/↓ to select  |  Enter to open", "bold green" if self.cold_war_mode else "bold magenta")
        
        # Add focus indicator with highlighted style when focused
        if self.panel_focus == "main":
            # Use green in cold war mode, otherwise use orange
            bg_color = "#00ff00" if self.cold_war_mode else "#dd8866"
            # Show page number in title when focused and paginated
            if total_pages > 1:
                title_text_str = f"CORRELATED INCIDENTS (Reduced Noise by ~80%) - Page {self.incident_page_offset + 1}/{total_pages}"
            else:
                title_text_str = "CORRELATED INCIDENTS (Reduced Noise by ~80%)"
            title_text = Text(title_text_str, style=f"bold black on {bg_color}")
        else:
            title_text = "CORRELATED INCIDENTS (Reduced Noise by ~80%)"
        
        return Panel(content,
                    title=title_text,
                    subtitle=status,
                    border_style="#00FF00" if self.cold_war_mode else "#dd8866",
                    padding=(1,2))
    
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
                "tier_note": "(Free tier: IP lookups only - hashes/URLs need paid plan)"
            },
            "pulsedive": {
                "name": "Pulsedive",
                "accepts": "IPs, domains, hashes, URLs",
                "icon": "📊",
                "tier_note": "(Free tier: limited indicator database)"
            },
            "abusech": {
                "name": "Abuse.ch",
                "accepts": "Hashes, URLs",
                "icon": "⚠️",
                "tier_note": "(Free/open: hash and URL lookups)"
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
                content.append("  VirusTotal Free:  IP lookups only (hashes need paid plan)\n", style="dim #00ff00" if self.cold_war_mode else "dim #888888")
                content.append("  AbuseIPDB Free:   IP lookups only\n", style="dim #00ff00" if self.cold_war_mode else "dim #888888")
                content.append("  Pulsedive Free:   Limited indicator database\n", style="dim #00ff00" if self.cold_war_mode else "dim #888888")
                content.append("  Abuse.ch:         Open/free database (full hash + URL support)\n", style="dim #00ff00" if self.cold_war_mode else "dim #888888")
                content.append("\nIf you see 'CLEAN' results on indicators that should be malicious,\n", style="dim #00ff00" if self.cold_war_mode else "dim white")
                content.append("it likely means your API tier doesn't have access to that indicator type.\n", style="dim #00ff00" if self.cold_war_mode else "dim white")
                content.append("Consider upgrading to paid plans for comprehensive threat intelligence.\n", style="dim #00ff00" if self.cold_war_mode else "dim #666666")
            
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
        self.call_later(self.update_display)
    
    def action_cycle_filter_type(self):
        """Cycle alert type filter: All → Alerts Only → Posts Only → All"""
        filter_modes = ["all", "alerts", "posts"]
        self.filter_type_index = (self.filter_type_index + 1) % len(filter_modes)
        self.filter_mode = filter_modes[self.filter_type_index]
        self.feed_page_offset = 0  # Reset to first page
        self.call_later(self.update_display)
    
    def action_open_browser(self):
        """Open top alert in browser"""
        if alert_queue:
            webbrowser.open(alert_queue[0]['url'])
    
    def action_open_breach(self):
        """Open top breach in browser"""
        if breach_list:
            breach_url = f"https://haveibeenpwned.com/api/v3/breaches?breach={breach_list[0]['Name']}"
            webbrowser.open(f"https://haveibeenpwned.com/?q={breach_list[0]['Title'].replace(' ', '+')}")
    
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
        self.feed_page_offset = 0
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
    
    def get_ai_summary(self, alert_text: str) -> str:
        """Get Gemini AI summary of an alert with caching and retry logic for rate limiting"""
        if not self.gemini_client:
            return "AI unavailable - Gemini key not configured"
        
        cache_key = hash(alert_text)
        if cache_key in self.ai_cache:
            return self.ai_cache[cache_key]
        
        max_retries = 3
        retry_delay = 1
        
        for attempt in range(max_retries):
            try:
                prompt = f"""Analyze this security alert CONCISELY in 3 lines max:
1. What is the threat?
2. Risk level (Low/Medium/High/Critical)
3. Key action

Alert: {alert_text[:300]}"""
                
                response = self.gemini_client.models.generate_content(
                    model=self.gemini_model,
                    contents=prompt
                )
                summary = response.text if response and response.text else "Analysis failed - no response"
                self.ai_cache[cache_key] = summary
                return summary
            except Exception as e:
                error_str = str(e)
                # Check for rate limit error (429)
                if "429" in error_str or "rate" in error_str.lower():
                    if attempt < max_retries - 1:
                        time.sleep(retry_delay)
                        retry_delay *= 2  # Exponential backoff
                        continue
                    else:
                        error_detail = "API rate limited - please try again later"
                else:
                    error_detail = str(e)[:60]
                    error_msg = f"API Error: {error_detail}"
                    self.ai_cache[cache_key] = error_msg
                    return error_msg
        
        # Fallback if all retries exhausted
        error_msg = "API rate limited - please try again later"
        self.ai_cache[cache_key] = error_msg
        return error_msg
    
    async def get_ai_summary_async(self, alert_text: str) -> str:
        """Async wrapper for Gemini AI summary to avoid blocking event loop"""
        import concurrent.futures
        loop = asyncio.get_event_loop()
        
        # Run the blocking Gemini call in a thread executor
        with concurrent.futures.ThreadPoolExecutor() as executor:
            return await loop.run_in_executor(executor, self.get_ai_summary, alert_text)
    
    def make_war_room_panel(self) -> Panel:
        """Display AI-powered war room executive threat summary with scrolling"""
        
        # Rainbow gradient colors
        if self.cold_war_mode:
            rainbow_colors = ["#00ff00"] * 7
            heading_color = "bold #00ff00"
            bar_style = "bold #00ff00"
            cve_style = "bold #00ff00"
        else:
            rainbow_colors = ["#ff6666", "#ff9966", "#ffcc66", "#66ff66", "#66ccff", "#cc99ff", "#99ffff"]
            heading_color = "bold cyan"
            bar_style = "bold #9933ff"
            cve_style = "bold #ff0000"
        
        content_lines = []
        
        if self.threat_summary_loading:
            content_lines.append(Text("⏳ Loading threat analysis...", style="bold yellow"))
            content_lines.append(Text("This takes a moment as Gemini analyzes your alerts", style="dim cyan"))
        elif not self.threat_summary:
            content_lines.append(Text("⏳ Initializing threat summary...", style="dim yellow"))
            content_lines.append(Text("Waiting for alerts to arrive", style="dim cyan"))
        else:
            # Get full content from current page
            if self.threat_summary_pages and 0 <= self.threat_summary_page < len(self.threat_summary_pages):
                summary_text = self.threat_summary_pages[self.threat_summary_page]
            else:
                summary_text = self.threat_summary
            
            rainbow_idx = 0
            
            # Format the threat summary with colors
            for line in summary_text.split('\n'):
                if not line.strip():
                    content_lines.append(Text(""))
                elif line.startswith('─'):
                    content_lines.append(Text(line, style=bar_style))
                elif ':' in line and all(c.isupper() or c.isspace() or c in '()/' for c in line):
                    content_lines.append(Text(line, style=heading_color))
                elif 'CVE-' in line and '[' in line:
                    content_lines.append(Text(line, style=cve_style))
                else:
                    if line.strip():
                        color = rainbow_colors[rainbow_idx % len(rainbow_colors)]
                        content_lines.append(Text(line, style=f"bold {color}"))
                        rainbow_idx += 1
                    else:
                        content_lines.append(Text(""))
        
        border_color = "#00ff00" if self.cold_war_mode else "#9933ff"
        
        # Show page number if paginated and create title with focus styling
        if self.threat_summary_pages and len(self.threat_summary_pages) > 1:
            page_num = self.threat_summary_page + 1
            total = len(self.threat_summary_pages)
            title_str = f"GEMINI ANALYSIS - Page {page_num}/{total}"
        else:
            title_str = "GEMINI ANALYSIS"
        
        # Highlight title background when focused
        if self.panel_focus == "dashboard" and self.dashboard_panel_index == 1:
            bg_color = "#00ff00" if self.cold_war_mode else "#9933ff"
            title_text = Text(title_str, style=f"bold black on {bg_color}")
        else:
            title_text = title_str
        
        # Create content as a Text object combining all lines
        full_text = Text()
        for i, text_obj in enumerate(content_lines):
            full_text.append_text(text_obj)
            if i < len(content_lines) - 1:
                full_text.append("\n")
        
        content = full_text if content_lines else Text("Initializing threat analysis...", style="dim yellow")
        
        # Add pagination subtitle if multiple pages
        subtitle = None
        if self.threat_summary_pages and len(self.threat_summary_pages) > 1:
            subtitle_text = f"← → to change pages"
            subtitle = Text(subtitle_text, style="bold #00ff00" if self.cold_war_mode else "bold #9933ff")
        
        return Panel(content,
                    title=title_text,
                    subtitle=subtitle,
                    border_style=border_color,
                    padding=(1, 2),
                    expand=True)
    
    def action_cycle_dashboard(self):
        """Cycle through dashboard panels: metrics → war room → feed status"""
#        logging.info("KEY 7 PRESSED: Cycling dashboard panel")
        # 0 = Main metrics, 1 = War room, 2 = Feed status
        self.dashboard_panel_index = (self.dashboard_panel_index + 1) % 3
        # Reset all page offsets when switching panels
        self.dashboard_page_offset = 0
        self.threat_summary_page = 0
#        logging.info(f"Dashboard panel index now: {self.dashboard_panel_index}")
        self.update_display()
    
    def action_abuseipdb_lookup(self):
        """Action placeholder - AbuseIPDB lookup removed"""
#        logging.info("AbuseIPDB lookup not available - feature removed")
        pass
    
    async def _prompt_for_abuseipdb_ip(self):
        """Prompt user for IP and run AbuseIPDB lookup"""
        # In a real TUI app, you'd use Input widget. For now, we'll use a simple approach
        # by marking the panel as needing input, then using on_key to capture the IP
#        logging.info("AbuseIPDB lookup initiated - waiting for IP input")
        self.abuseipdb_input_mode = True
        self.abuseipdb_input_buffer = ""
        self.call_later(self.update_display)
    
    async def _run_abuseipdb_query(self, ip_address: str):
        """Run AbuseIPDB query for the given IP"""
#        logging.info(f"Starting AbuseIPDB query for: {ip_address}")
        self.abuseipdb_last_query = ip_address
        self.abuseipdb_loading = True
        self.abuseipdb_last_result = None
        self.call_later(self.update_display)
        
        try:
            # Run the AbuseIPDB query
            results = await self.enrich_indicator(ip_address, "ip")
            self.abuseipdb_last_result = results
#            logging.info(f"AbuseIPDB complete for {ip_address}: {len(results)} providers returned data")
        
        except Exception as e:
            logging.error(f"Error querying AbuseIPDB for {ip_address}: {e}")
            self.abuseipdb_last_result = None
        
        finally:
            self.abuseipdb_loading = False
            self.call_later(self.update_display)
    
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
        """Open URL for the currently highlighted row (via keyboard navigation with up/down arrows)"""
        if self.main_view_mode == "alerts":
            if 0 <= self.hover_row < len(self.alert_urls):
                url = self.alert_urls[self.hover_row]
                if url:
                    webbrowser.open(url)
#                    logging.info(f"Opened alert URL via keyboard (row {self.hover_row}): {url[:80]}")
                    self.notify(f"Opening alert in browser...")
                else:
                    self.notify("No URL available for this alert", timeout=2)
        
        elif self.main_view_mode == "incidents":
            if 0 <= self.hover_row < len(self.incident_source_urls):
                incident_id, source_urls = self.incident_source_urls[self.hover_row]
                # Open the first available source URL for this incident
                for source_name in sorted(source_urls.keys()):
                    url = source_urls[source_name]
                    if url:
                        webbrowser.open(url)
#                        logging.info(f"Opened {source_name} source for INC-{incident_id} via keyboard: {url}")
                        self.notify(f"Opening incident source in browser...")
                        return
            else:
                self.notify("No incident selected", timeout=2)

    def on_key(self, event: events.Key) -> None:
        """Handle key events - Tab, view toggle, and arrow key pagination"""
        # PRIORITY: Check for 'v' key FIRST to allow exiting input mode and cycling views
        # This ensures 'v' always works to cycle views, even when in input mode
        if event.key == "v":
            event.prevent_default()
            # Exit input modes if active
            if self.api_tools_input_mode:
                self.api_tools_input_mode = False
                self.api_tools_input_buffer = ""
#                logging.info("Exited API Tools input mode via 'v' key")
            # Now cycle the view
            self.action_toggle_view()
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
                max_row = len(self.alert_urls) - 1 if self.main_view_mode == "alerts" else len(self.incident_source_urls) - 1
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
        """Handle clicks on the feeds area - only enable clicks in specific views with valid targets"""
        # Only allow clicking in alerts or incidents view
        if self.main_view_mode not in ["alerts", "incidents"]:
            return
        
        # Only process clicks on the feeds widget
        if event.widget.id != "feeds":
            return
        
        # In incidents view, open the source URL for the clicked incident
        if self.main_view_mode == "incidents":
            # Only allow clicks if we have incident data
            if not self.incident_source_urls:
                return
            
            click_y = event.y - 3  # Account for panel border/title
            # Estimate which incident row was clicked (roughly 6 lines per incident)
            incident_index = click_y // 6
            
            if 0 <= incident_index < len(self.incident_source_urls):
                incident_id, source_urls = self.incident_source_urls[incident_index]
                for source_name in sorted(source_urls.keys()):
                    url = source_urls[source_name]
                    if url:
                        webbrowser.open(url)
#                        logging.info(f"Opened {source_name} source for INC-{incident_id}: {url}")
                        return
            else:
                pass
        
        if self.main_view_mode == "alerts":
            # Only allow clicks if we have alert data
            if not self.alert_urls:
                return
            
            click_y = event.y
            
            # Better row estimation: 
            # Panel border/title typically = 3 lines
            # Each table row is typically 2 lines (1 for content + 1 spacing)
            # But Rich tables can vary, so we'll be more generous with row height
            
            panel_header_offset = 3  # Account for border + title + padding
            adjusted_y = click_y - panel_header_offset
            
            # Estimate row: assuming ~2-3 Y units per row
            # Try 2 first, then 3 if out of bounds
            row_index = adjusted_y // 2
            
            # If that puts us out of bounds and we're positive, try 3
            if row_index >= len(self.alert_urls) and adjusted_y > 0:
                row_index = adjusted_y // 3
            
            # Ensure valid range
            row_index = max(0, min(row_index, len(self.alert_urls) - 1))
            
            if 0 <= row_index < len(self.alert_urls):
                url = self.alert_urls[row_index]
                if url:
                    webbrowser.open(url)
#                    logging.info(f"Opened alert URL (row {row_index} of {len(self.alert_urls)}, click_y {event.y}): {url[:80]}")
                    return
                else:
                    pass
            else:
                pass

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
    
    # Condensed info section
    console.print(" [bold cyan]Quick Start:[/]")
    console.print("   • Real-time threat intelligence dashboard with auto-refresh every 60 seconds")
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
    console.print(" [dim]Loading CybrWire...[/]")
    console.print()
    
    console.clear()
    
    app = CybrWireApp(cold_war=cold_war, recency=recency)
    app.run()

if __name__ == "__main__":
    main()
