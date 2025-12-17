#!/usr/bin/env python3
import asyncio
import feedparser
import httpx
import json
import re
import time
from datetime import datetime, timedelta, timezone
from rich.console import Console
from rich.table import Table
from rich.text import Text
from rich.theme import Theme
from rich.panel import Panel
from rich import box
from rich.layout import Layout
import threading
import sys
import os
from collections import deque

# Force truecolor for accurate colors
console = Console(color_system="truecolor", theme=Theme({
    "critical": "bold white on red",
    "zeroday": "bold black on bright_yellow",
    "ransomware": "bold white on #ff0066",
    "apt": "bold white on #800080",
    "exploit": "bold bright_red",
    "info": "bright_cyan",
    "new": "bold reverse white on #00ff00",
}))

HEADERS = {"User-Agent": "C Y B R W I R E 2.0 // Legendary Edition"}
# Constants for magic numbers
MAX_TITLE_LEN = 90
MAX_SUMMARY_LEN = 140
TICKER_TITLE_LEN = 60
HEAT_BAR_WIDTH = 33
REFRESH_INTERVAL = 300
TICKER_LOOKBACK = 8
TOP_SOURCES_COUNT = 5
TREND_LOOKBACK = 5
TICKER_SPEED = 1 # Update ticker every N UI frames (0.7s * 4 = ~2.8s per character)

SOURCES = [
    {"name": "CISA KEV", "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "type": "json"},
    {"name": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/", "type": "rss"},
    {"name": "TheHackerNews", "url": "https://feeds.feedburner.com/TheHackersNews", "type": "rss"},
    {"name": "Krebs", "url": "https://krebsonsecurity.com/feed/", "type": "rss"},
    {"name": "VulDB", "url": "https://vuldb.com/?rss.recent", "type": "rss"},
    {"name": "NVD Recent CVEs", "url": "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss.xml", "type": "rss"},
    {"name": "ZDI Published", "url": "https://www.zerodayinitiative.com/rss/published/", "type": "rss"},
    {"name": "ZDI Upcoming", "url": "https://www.zerodayinitiative.com/rss/upcoming/", "type": "rss"},
    {"name": "Sophos Threat", "url": "https://news.sophos.com/en-us/category/threat-research/feed/", "type": "rss"},
    {"name": "DShield Attackers", "url": "https://feeds.dshield.org/top10.txt", "type": "txt"},
    {"name": "DShield Block", "url": "https://feeds.dshield.org/block.txt", "type": "txt"},
    {"name": "Kaspersky Securelist", "url": "https://securelist.com/feed/", "type": "rss"},
    {"name": "Kaspersky Malware", "url": "https://securelist.com/feed/?tag=malware", "type": "rss"},
    {"name": "Kaspersky APT", "url": "https://securelist.com/feed/?tag=apt", "type": "rss"},
    {"name": "Kaspersky Bad URLs", "url": "https://opentip.kaspersky.com/feeds/maliciousurls/", "type": "txt"},
    {"name": "Dark Reading", "url": "https://www.darkreading.com/rss.xml", "type": "rss"},
    {"name": "SANS ISC Diary", "url": "https://isc.sans.edu/rssfeed.xml", "type": "rss"},
    {"name": "ThreatFox", "url": "https://threatfox.abuse.ch/export/json/recent/", "type": "json"},

    # SecurityWeek alternate (only one left to try)
    {"name": "SecurityWeek Alt2", "url": "https://www.securityweek.com/feed/", "type": "rss"},

    # US-CERT Alerts alternate (only working ones left)
    #{"name": "US-CERT Alerts Alt4", "url": "https://www.us-cert.gov/ncas/alerts.xml", "type": "rss"}, #pulling old data
]

alert_queue = []
next_refresh = datetime.now(timezone.utc)
border_color = "bright_magenta"
last_critical = None
ticker_offset = 0
ticker_counter = 0  # Counter to control ticker speed
start_time = datetime.now(timezone.utc)
recency_hours = 24  # Default to 24 hours; can be toggled with keys 1, 2, 3
# Use deque with (timestamp, count) tuples for accurate rate calculation
alert_history = deque(maxlen=100)

def critical_sound():
    try:
        if sys.platform.startswith("linux"):
            # Remove echo -e, just use '\a' for bell if paplay fails
            os.system('paplay /usr/share/sounds/freedesktop/stereo/alarm-clock-elapsed.oga 2>/dev/null || printf "\\a"')
        elif sys.platform == "darwin":
            os.system('afplay /System/Library/Sounds/Glass.aiff')
        else:
            print('\a', end='', flush=True)
    except Exception as e:
        console.print(f"[dim]Warning: Could not play sound: {e}[/]")

def is_recent(s, hours=24):
    """Check if date string is within the specified hours window."""
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00")) if "Z" in s else datetime.strptime(s[:10], "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except Exception:
        try:
            p = feedparser._parse_date(s)
            dt = datetime(*p[:6], tzinfo=timezone.utc) if p else datetime.now(timezone.utc)
        except Exception:
            return True
    now = datetime.now(timezone.utc)
    return (now - dt).total_seconds() <= (hours * 3600)

# --- In your parse_cisa function, ensure strict recency filtering ---
def parse_cisa(data, source_name):
    items = []
    for v in data.get("vulnerabilities", [])[:3]:
        date_added = v.get("dateAdded", "")
        try:
            ts = datetime.fromisoformat(date_added + "T00:00:00+00:00") if date_added else datetime.now(timezone.utc)
        except Exception:
            ts = datetime.now(timezone.utc)
        items.append({
            "title": f"KEV ACTIVE → {v['cveID']}",
            "summary": v.get("shortDescription", "")[:MAX_SUMMARY_LEN],
            "published": date_added[:10],
            "severity": "critical",
            "source": source_name,
            "url": f"https://nvd.nist.gov/vuln/detail/{v['cveID']}",
            "ts": ts
        })
    return items

def parse_rss(text, source_name):
    f = feedparser.parse(text)
    items = []
    for e in f.entries[:3]:
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
        items.append({"title": title, "summary": summary, "published": pub[:10], "severity": sev, "source": source_name, 
                      "url": link, "ts": ts})
    return items

def parse_txt(text, source_name):
    lines = [line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#")]
    items = []
    for line in lines[:3]:
        parts = line.split()
        if len(parts) >= 3:
            ip_net = parts[0]
            attacks = parts[1]
            items.append({"title": f"TOP MALICIOUS IP: {ip_net} ({attacks} attacks)", "summary": "DShield top attacker", 
                         "published": datetime.now(timezone.utc).strftime("%Y-%m-%d"), "severity": "exploit", 
                         "source": source_name, "url": f"https://www.dshield.org/ipinfo.html?ip={ip_net.split('/')[0]}",
                         "ts": datetime.now(timezone.utc)})
    return items

async def refresher():
    global alert_queue, next_refresh, border_color, last_critical, alert_history
    async with httpx.AsyncClient(headers=HEADERS, timeout=30, follow_redirects=True) as c:
        while True:
            new = []
            for src in SOURCES:
                try:
                    r = await c.get(src["url"])
                    r.raise_for_status()
                    if src["type"] == "json":
                        new.extend(parse_cisa(r.json(), src["name"]))
                    elif src["type"] == "rss":
                        new.extend(parse_rss(r.text, src["name"]))
                    elif src["type"] == "txt":
                        new.extend(parse_txt(r.text, src["name"]))
                except Exception as e:
                    console.print(f"[dim]Failed {src['name']}: {e}[/]")
            seen = set()
            # Limit to max 3 items per source
            source_buckets = {}
            for a in new:
                src = a.get("source", "Unknown")
                if src not in source_buckets:
                    source_buckets[src] = []
                if len(source_buckets[src]) < 3:
                    source_buckets[src].append(a)
            alert_queue = sorted(
                [item for alerts in source_buckets.values() for item in alerts],
                key=lambda x: x.get("ts", datetime.min.replace(tzinfo=timezone.utc)),
                reverse=True
            )

            alert_history.append((datetime.now(timezone.utc), len(alert_queue)))

            fresh_critical = any(a["severity"] in ["critical","zeroday"] for a in alert_queue[:3])
            if fresh_critical and (last_critical != (alert_queue[0]["title"] if alert_queue else None)):
                last_critical = alert_queue[0]["title"] if alert_queue else None
                threading.Thread(target=critical_sound, daemon=True).start()
                border_color = "bright_red"
                asyncio.create_task(flash_border())

            next_refresh = datetime.now(timezone.utc) + timedelta(seconds=REFRESH_INTERVAL)
            await asyncio.sleep(REFRESH_INTERVAL)

async def flash_border():
    global border_color
    await asyncio.sleep(10)
    border_color = "bright_magenta"

def animate_loading(duration=25):
    """Animate loading with vertically stacked messages - previous blink stops, new one blinks."""
    messages = [
        "INITIALIZING...",
        "TAPPING WIRES...",
        "CONNECTIONS ESTABLISHED...",
        "PULLING LATEST...",
        "GENERATING ALERTS...",
        "STAND BY..."
    ]
    
    # ASCII art with cool neon gradient
    ascii_art = [
        (r"~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~", "#00ffff"),
        (r"~     ______  __  __  ______  ______  __     __  __  ______  ______         ~", "#0099ff"),
        (r"~    /\  ___\/\ \_\ \/\  == \/\  == \/\ \  _ \ \/\ \/\  == \/\  ___\        ~", "#6666ff"),
        ('~    \\ \\ \\___\\ \\____ \\ \\  __<\\ \\  __<\\ \\ \\/ ".\ \\ \\ \\ \\  __<\\ \\  __\\        ~', "#ff00ff"),
        ('~     \\ \\_____\\/\\_____\\ \\_____\\ \\_\\ \\_\\ \\__/".~\\_\\ \\_\\ \\_\\ \\_\\ \\_____\\      ~', "#0099ff"),
        (r"~      \/_____/\/_____/\/_____/\/_/ /_/\/_/   \/_/\/_/\/_/ /_/\/_____/      ~", "#6666ff"),
        (r"~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~", "#00ffff"),
        (r"~~~~~~~~~~~~~~~~~~~~~~~~~***LEGENDARY // EDITION***~~~~~~~~~~~~~~~~~~~~~~~~~~", "#FF00ff"),
        (r"                By: GitHub/QIO1984 // The Hacker known as MADNOTE", "#00ffff"),
    ]
    
    start_time = time.time()
    last_msg_index = -1
    displayed_messages = []
    
    while time.time() - start_time < duration:
        elapsed = time.time() - start_time
        
        # Determine which message to show (roughly every 5 seconds)
        msg_index = int(elapsed / 5)
        if msg_index >= len(messages):
            msg_index = len(messages) - 1
        
        # Add new message when index changes
        if msg_index != last_msg_index:
            message = messages[msg_index]
            displayed_messages.append(message)
            last_msg_index = msg_index
            
            # Clear and redraw all messages with ASCII art
            console.clear()
            
            # Print ASCII art
            for line, color in ascii_art:
                console.print(f"[bold {color}]{line}[/]")
            console.print()
            
            # Print static messages
            for prev_msg in displayed_messages[:-1]:
                console.print(f"[bold #00ff00]{prev_msg}[/]")
            
            # Print current blinking message
            console.print(f"[bold blink #00ff00]{displayed_messages[-1]}[/]")
        
        time.sleep(0.1)

def make_ui():
    global ticker_offset, ticker_counter, recency_hours

    # Main table
    table = Table(box=box.DOUBLE, show_header=False, padding=(0,1), expand=True)
    table.add_column(width=9, justify="right")
    table.add_column(width=10)
    table.add_column()

    now = datetime.now(timezone.utc)
    cutoff_time = now - timedelta(hours=recency_hours)
    
    for a in alert_queue:
        # Filter by recency
        if a.get("ts", now) < cutoff_time:
            continue

        title_parts = []
        # Only tag as NEW if the timestamp is <24h old and not just "now" due to missing/invalid date
        ts = a.get("ts", now)
        # Consider "not NEW" if the timestamp is within 5 seconds of now (likely defaulted)
        if 0 < (now - ts).total_seconds() < 86400 and abs((now - ts).total_seconds()) > 5:
            title_parts.append(Text("[NEW] ", style="bold magenta"))
        title_parts.append(Text(a["title"], style=a["severity"]))
        title_text = Text(a["title"], style=a["severity"])

        if a.get("url"):
            title_text.stylize(f"link {a['url']}")

        table.add_row(a["published"], Text(a["severity"].upper(), style=a["severity"]), title_text)

    # TICKER - Malicious IPs, Zero-Day, Ransomware (all respect recency window)
    # Malicious IPs (no recency filter, as per previous logic)
    malicious_ip_sources = {}
    for a in alert_queue:
        if "TOP MALICIOUS IP" in a.get("title", ""):
            src = a.get("source", "Unknown")
            ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', a.get("title", ""))
            if ip_match:
                if src not in malicious_ip_sources:
                    malicious_ip_sources[src] = []
                malicious_ip_sources[src].append(ip_match.group(1))
    ip_sections = []
    if malicious_ip_sources:
        if len(malicious_ip_sources) == 1:
            src, ips = next(iter(malicious_ip_sources.items()))
            ip_sections.append(f"Top Malicious IPs ({src}): {', '.join(ips)}")
        else:
            for src, ips in malicious_ip_sources.items():
                ip_sections.append(f"Top Malicious IPs ({src}): {', '.join(ips)}")
    ip_section_str = "  ".join(ip_sections)
    if ip_section_str:
        ip_section_str += "  //  "

    # Zero-Day Alerts (respect recency window)
    zeroday_alerts = [
        a for a in alert_queue
        if a["severity"] == "zeroday" and a.get("ts", now) >= cutoff_time
    ]
    if zeroday_alerts:
        zd_section_str = " // ".join([f'Zero-Day Alert: "{a["title"]}"' for a in zeroday_alerts])
    else:
        zd_section_str = "Zero-Day Alert: No alerts at this time"
    zd_section_str += "  //  "

    # Ransomware Alerts (respect recency window)
    ransomware_alerts = [
        a for a in alert_queue
        if a["severity"] == "ransomware" and a.get("ts", now) >= cutoff_time
    ]
    if ransomware_alerts:
        rw_section_str = " // ".join([f'Ransomware Alert: "{a["title"]}"' for a in ransomware_alerts])
    else:
        rw_section_str = "Ransomware Alert: No alerts at this time"

    # Combine ticker parts: IPs, Zero-Day, Ransomware
    ticker_core = ip_section_str + zd_section_str + rw_section_str
    if not ticker_core.strip():
        ticker_core = "--- NO ZERO-DAYS, RANSOMWARE, OR MALICIOUS IPS DETECTED ---"

    # Make ticker wrap seamlessly, always filling the width
    visible_width = console.width
    min_repeats = max(2, (2 * visible_width) // max(1, len(ticker_core + "   ")))
    ticker_str = (ticker_core + "   ") * min_repeats
    ticker_length = len(ticker_core + "   ") * min_repeats

    ticker_counter = (ticker_counter + 1) % ticker_length
    ticker_offset = ticker_counter % len(ticker_core + "   ")
    ticker_display = Text(ticker_str[ticker_offset:ticker_offset + visible_width], style="bold #00ff00 on black")

    # METRICS
    critical_count = len([a for a in alert_queue if a["severity"] == "critical" and a.get("ts", now) >= cutoff_time])
    zeroday_count = len([a for a in alert_queue if a["severity"] == "zeroday" and a.get("ts", now) >= cutoff_time])
    ransomware_count = len([a for a in alert_queue if a["severity"] == "ransomware" and a.get("ts", now) >= cutoff_time])
    apt_count = len([a for a in alert_queue if a["severity"] == "apt" and a.get("ts", now) >= cutoff_time])
    exploit_count = len([a for a in alert_queue if a["severity"] == "exploit" and a.get("ts", now) >= cutoff_time])
    new_count = len([a for a in alert_queue if (now - a.get("ts", now)).total_seconds() < 3600 and a.get("ts", now) >= cutoff_time])
    fresh_kev = len([a for a in alert_queue if a["severity"] == "critical" and (now - a.get("ts", now)).total_seconds() < 86400 and a.get("ts", now) >= cutoff_time])
    uptime = str(datetime.now(timezone.utc) - start_time).split('.')[0]

    # Rate calculation (fixed)
    hour_ago = now - timedelta(hours=1)
    rate = sum(1 for ts, _ in alert_history if ts > hour_ago)

    # Heat level
    total_threats = critical_count + zeroday_count + ransomware_count + apt_count + exploit_count
    filtered_count = len([a for a in alert_queue if a.get("ts", now) >= cutoff_time])
    heat_pct = (total_threats / max(filtered_count, 1)) * 100 if filtered_count > 0 else 0
    heat = ("LOW" if heat_pct < 20 else "MED" if heat_pct < 50 else "HIGH" if heat_pct < 80 else "CRITICAL")
    heat_style = "green" if heat == "LOW" else "bright_yellow" if heat == "MED" else "bright_red" if heat == "HIGH" else "bold reverse red"
    heat_bar = "█" * int(heat_pct / 3) + "░" * (HEAT_BAR_WIDTH - int(heat_pct / 3))
    heat_label = Text(f" {heat} ", style="bold black")

    last_crit_time = min((a.get("ts", now) for a in alert_queue if a["severity"] in ["critical","zeroday"] and a.get("ts", now) >= cutoff_time), default=now)
    time_since_crit = str(now - last_crit_time).split('.')[0]

    metrics = Text()
    metrics.append(f"Total Alerts        : {filtered_count}\n", style="cyan")
    metrics.append(f"Critical/KEV        : {critical_count} (Fresh 24h: {fresh_kev})\n", style="red")
    metrics.append(f"Zero-Day            : {zeroday_count}\n", style="yellow")
    metrics.append(f"Ransomware          : {ransomware_count}\n", style="#ff0066")
    metrics.append(f"APT Activity        : {apt_count}\n", style="#800080")
    metrics.append(f"Exploits/POC        : {exploit_count}\n", style="bright_red")
    
    # IOC Count (moved here, right after Exploits/POC)
    ioc_count = len([a for a in alert_queue if ("IP" in a["title"] or "Hash" in a["title"] or "URL" in a["title"]) and a.get("ts", now) >= cutoff_time])
    metrics.append(f"IOCs Detected       : {ioc_count}\n", style="bright_red")
    
    metrics.append(f"New (<1h)           : {new_count}\n", style="#00ff00")
    metrics.append(f"Rate (last hour)    : {rate}/hr\n", style="bold white")
    metrics.append("Heat Level (High-Threat %):\n", style=heat_style)
    metrics.append(f"{heat_bar}{heat_label}\n", style=heat_style)
    
    # Top Sources
    source_counts = {}
    for a in alert_queue:
        if a.get("ts", now) >= cutoff_time:
            src = a.get("source", "Unknown")
            source_counts[src] = source_counts.get(src, 0) + 1
    top_sources = sorted(source_counts.items(), key=lambda x: x[1], reverse=True)[:TOP_SOURCES_COUNT]
    metrics.append("\nTop Sources:\n", style="bold cyan")
    for src, count in top_sources:
        metrics.append(f"  {src}: {count}\n", style="dim")

    # Flair Quote
    quotes = [
        "Stay paranoid. — @gossithedog",
        "The tape never lies.",
        "Exploit early, patch often.",
        "In the wild = in your network.",
    ]
    metrics.append(f"\n{quotes[filtered_count % len(quotes)]}\n", style="italic dim")
    metrics.append(f"Last Critical       : {time_since_crit} ago\n", style="dim")
    metrics.append(f"Uptime              : {uptime}\n", style="dim")

    rem = int((next_refresh - datetime.now(timezone.utc)).total_seconds())
    m, s = divmod(max(rem, 0), 60)
    status = Text()
    status.append(f"{datetime.now(timezone.utc):%H:%M:%S} UTC", "bold white")
    status.append(f" — {filtered_count} alerts", "bold cyan")
    if any(a["severity"] in ["critical","zeroday"] for a in alert_queue[:3] if a.get("ts", now) >= cutoff_time):
        status.append("  EXPLOIT IN THE WILD!!!", "bold reverse red")
    status.append(f" — Next: {m:02d}:{s:02d}", "bold bright_red")

    layout = Layout()
    layout.split_column(
        Layout(Panel(ticker_display, title="LIVE THREAT TAPE", border_style="cyan", padding=0), size=3),
        Layout(name="bottom", ratio=1)
    )
    layout["bottom"].split_row(
        Layout(Panel(table, title="[bold reverse #00ff00 on black]  C Y B R W I R E 1.0 // LEGENDARY EDITION  [/]", subtitle=status, border_style=border_color, padding=(1,2)), ratio=3),
        Layout(Panel(metrics, title="WAR ROOM DASHBOARD", border_style="bright_blue"))
    )

    return layout

async def main():
    global recency_hours
    console.clear()
    
    # ASCII art with cool neon gradient
    ascii_art = [
        (r"~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~", "#00ffff"),
        (r"~     ______  __  __  ______  ______  __     __  __  ______  ______         ~", "#0099ff"),
        (r"~    /\  ___\/\ \_\ \/\  == \/\  == \/\ \  _ \ \/\ \/\  == \/\  ___\        ~", "#6666ff"),
        ('~    \\ \\ \\___\\ \\____ \\ \\  __<\\ \\  __<\\ \\ \\/ ".\ \\ \\ \\ \\  __<\\ \\  __\\        ~', "#ff00ff"),
        ('~     \\ \\_____\\/\\_____\\ \\_____\\ \\_\\ \\_\\ \\__/".~\\_\\ \\_\\ \\_\\ \\_\\ \\_____\\      ~', "#0099ff"),
        (r"~      \/_____/\/_____/\/_____/\/_/ /_/\/_/   \/_/\/_/\/_/ /_/\/_____/      ~", "#6666ff"),
        (r"~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~", "#00ffff"),
        (r"~~~~~~~~~~~~~~~~~~~~~~~~~***LEGENDARY // EDITION***~~~~~~~~~~~~~~~~~~~~~~~~~~", "#FF00ff"),
        (r"                By: GitHub/QIO1984 // The Hacker known as MADNOTE", "#00ffff"),
    ]
    
    for line, color in ascii_art:
        console.print(f"[bold {color}]{line}[/]")
    
    console.print()
    console.print("[bold cyan]Select data age:[/]")
    console.print("  [bold white]1[/] = Last 24 hours (default)")
    console.print("  [bold white]2[/] = Last 48 hours")
    console.print("  [bold white]3[/] = Last 7 days")
    
    # --- Add this explainer block ---
    console.print(
        "\n[bold bright_cyan]What does the time range affect?[/]\n"
        "[white]- The main table, ticker, and dashboard metrics only show alerts within the selected time window.[/]\n"
        "[white]- The feed always fetches the latest 3 items per source, but only those within your chosen window are displayed.[/]\n"
        "[white]- Malicious IPs, zero-days, ransomware, and all stats reflect your selected time range.[/]\n"
    )
    # --- End explainer block ---

    console.print()
    console.print("[bold #00ff00]Enter Choice:[/] ", end="")
    # --- End explainer block ---


    
    selection = None
    while selection not in {"1", "2", "3"}:
        try:
            if sys.platform.startswith("win"):
                import msvcrt
                if msvcrt.kbhit():
                    selection = msvcrt.getch().decode().lower()
            else:
                import select
                if select.select([sys.stdin], [], [], 0.1)[0]:
                    selection = sys.stdin.read(1).lower()
        except Exception:
            pass
        await asyncio.sleep(0.1)
    
    # Set recency_hours based on selection
    if selection == "1":
        recency_hours = 24
    elif selection == "2":
        recency_hours = 48
    elif selection == "3":
        recency_hours = 168  # 7 days
    
    console.clear()
    asyncio.create_task(refresher())
    
    # Animate loading with ASCII art and messages
    animate_loading(duration=25)
    
    # Wait until feeds are actually loaded before showing main UI
    while len(alert_queue) == 0:
        await asyncio.sleep(0.5)
    
    console.print()  # New line after animation

    with console.screen(hide_cursor=False) as screen:
        while True:
            screen.update(make_ui())
            try:
                if sys.platform.startswith("win"):
                    import msvcrt
                    if msvcrt.kbhit():
                        key = msvcrt.getch().decode()
                    else:
                        key = None
                else:
                    import select
                    if select.select([sys.stdin], [], [], 0)[0]:
                        key = sys.stdin.read(1)
                    else:
                        key = None
            except Exception:
                key = None

            if key in {"r", "R"}:
                next_refresh = datetime.min
            elif key == "1":
                recency_hours = 24
            elif key == "2":
                recency_hours = 48
            elif key == "3":
                recency_hours = 168  # 7 days
            elif key in {"q", "Q"}:
                break
            await asyncio.sleep(0.7)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("\n[bold reverse #ff0066]  C Y B R W I R E Going dark // Stay Legendary...[/]")