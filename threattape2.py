#!/usr/bin/env python3
import asyncio
import feedparser
import httpx
import json
import re
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

HEADERS = {"User-Agent": "ThreatTape/1.0 Legendary Edition"}

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
    {"name": "Kaspersky Hashes", "url": "https://opentip.kaspersky.com/feeds/malwarehashes/", "type": "json"},
    {"name": "Kaspersky Bad URLs", "url": "https://opentip.kaspersky.com/feeds/maliciousurls/", "type": "txt"},
]

alert_queue = []
next_refresh = datetime.now(timezone.utc)
border_color = "bright_magenta"
last_critical = None
ticker_offset = 0
start_time = datetime.now(timezone.utc)
alert_history = []

def critical_sound():
    try:
        if sys.platform.startswith("linux"):
            os.system('paplay /usr/share/sounds/freedesktop/stereo/alarm-clock-elapsed.oga 2>/dev/null || echo -e "\\a"')
        elif sys.platform == "darwin":
            os.system('afplay /System/Library/Sounds/Glass.aiff')
        else:
            print('\a', end='', flush=True)
    except:
        print('\a', end='', flush=True)

def is_recent(s, critical=False):
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00")) if "Z" in s else datetime.strptime(s[:10], "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except:
        try:
            p = feedparser._parse_date(s)
            dt = datetime(*p[:6], tzinfo=timezone.utc) if p else datetime.now(timezone.utc)
        except:
            return True
    now = datetime.now(timezone.utc)
    return (now - dt).days <= 7 if critical else dt.date() == now.date()

def parse_cisa(data):
    return [
        {"title": f"KEV ACTIVE → {v['cveID']}", "summary": v.get("shortDescription","")[:140],
         "published": v["dateAdded"][:10], "severity": "critical",
         "url": f"https://nvd.nist.gov/vuln/detail/{v['cveID']}",
         "ts": datetime.fromisoformat(v["dateAdded"] + "T00:00:00+00:00")}
        for v in data.get("vulnerabilities", [])
        if is_recent(v["dateAdded"], True)
    ]

def parse_rss(text):
    f = feedparser.parse(text)
    items = []
    for e in f.entries[:15]:
        pub = e.get("published") or e.get("updated") or ""
        if not is_recent(pub):
            continue
        title = e.title[:90]
        raw_summary = e.get("summary") or e.get("description") or ""
        summary = re.sub(r'<[^>]*>', '', raw_summary)[:140]
        link = e.get("link", "")
        lower = (title + summary).lower()
        sev = ("ransomware" if any(k in lower for k in ["ransom","lockbit","conti","blackcat","akira","clop"])
               else "apt" if any(k in lower for k in ["apt41","apt28","lazarus","iran","china","russia","dprk"])
               else "zeroday" if any(k in lower for k in ["wormable","0day","zero-day","in the wild","rce","actively exploited"])
               else "exploit" if any(k in lower for k in ["exploit","poc"])
               else "info")
        items.append({"title": title, "summary": summary, "published": pub[:10], "severity": sev, "url": link,
                      "ts": datetime.now(timezone.utc)})
    return items

def parse_txt(text):
    lines = [line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#")]
    items = []
    for line in lines[:10]:
        parts = line.split()
        if len(parts) >= 3:
            ip_net = parts[0]
            attacks = parts[1]
            items.append({"title": f"TOP MALICIOUS IP: {ip_net} ({attacks} attacks)", "summary": "DShield top attacker", "published": datetime.now(timezone.utc).strftime("%Y-%m-%d"), "severity": "exploit", "url": f"https://www.dshield.org/ipinfo.html?ip={ip_net.split('/')[0]}"})
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
                        new.extend(parse_cisa(r.json()))
                    elif src["type"] == "rss":
                        new.extend(parse_rss(r.text))
                    elif src["type"] == "txt":
                        new.extend(parse_txt(r.text))
                except Exception as e:
                    console.print(f"[dim]Failed {src['name']}: {e}[/]")
            seen = set()
            alert_queue = [a for a in sorted(new, key=lambda x: x.get("ts", datetime.min.replace(tzinfo=timezone.utc)), reverse=True)
                          if not (k := a["title"][:70]) in seen and not seen.add(k)]
            alert_history.append(len(alert_queue))

            fresh_critical = any(a["severity"] in ["critical","zeroday"] for a in alert_queue[:3])
            if fresh_critical and (last_critical != (alert_queue[0]["title"] if alert_queue else None)):
                last_critical = alert_queue[0]["title"] if alert_queue else None
                threading.Thread(target=critical_sound, daemon=True).start()
                border_color = "bright_red"
                asyncio.create_task(flash_border())

            next_refresh = datetime.now(timezone.utc) + timedelta(seconds=300)
            await asyncio.sleep(300)

async def flash_border():
    global border_color
    await asyncio.sleep(10)
    border_color = "bright_magenta"

def make_ui():
    global ticker_offset

    # Main table
    table = Table(box=box.DOUBLE, show_header=False, padding=(0,1), expand=True)
    table.add_column(width=11, justify="right")
    table.add_column(width=14)
    table.add_column()

    now = datetime.now(timezone.utc)
    for a in alert_queue:
        title_parts = []
        if (now - a.get("ts", now)).total_seconds() < 3600:
            title_parts.append(Text("[NEW] ", style="new"))
        title_parts.append(Text(a["title"], style=a["severity"]))
        title_text = Text().join(title_parts)

        if a.get("url"):
            title_text.stylize(f"link {a['url']}")

        table.add_row(a["published"], Text(a["severity"].upper(), style=a["severity"]), title_text)
        if a["summary"].strip():
            table.add_row("", "", Text(f"  {a['summary']}", style="dim"))

    # TICKER — fixed to reach left edge
    ticker_items = [f"{a['title'][:60]}  •  " for a in alert_queue[:8]]
    ticker_str = "".join(ticker_items) * 3
    ticker_length = len(ticker_str)
    if ticker_length > 0:
        ticker_offset = (ticker_offset + 1) % ticker_length
        visible_width = console.width # full width
        ticker_display = Text(ticker_str[ticker_offset:ticker_offset + visible_width], style="bold #00ff00 on black")
    else:
        ticker_display = Text("--- THREATTAPE LOADING // STANDBY... ---", style="dim")

    # METRICS — Heat Level with correct colors
    critical_count = len([a for a in alert_queue if a["severity"] == "critical"])
    zeroday_count = len([a for a in alert_queue if a["severity"] == "zeroday"])
    ransomware_count = len([a for a in alert_queue if a["severity"] == "ransomware"])
    apt_count = len([a for a in alert_queue if a["severity"] == "apt"])
    exploit_count = len([a for a in alert_queue if a["severity"] == "exploit"])
    new_count = len([a for a in alert_queue if (now - a.get("ts", now)).total_seconds() < 3600])
    fresh_kev = len([a for a in alert_queue if a["severity"] == "critical" and (now - a.get("ts", now)).total_seconds() < 86400])
    uptime = str(datetime.now(timezone.utc) - start_time).split('.')[0]

    # Rate (last hour)
    hour_ago = now - timedelta(hours=1)
    recent_alerts = len([t for t in alert_history if t > hour_ago.timestamp()]) if alert_history else 0
    rate = recent_alerts

    # Heat level — 100% correct colors
    total_threats = critical_count + zeroday_count + ransomware_count + apt_count + exploit_count
    heat_pct = (total_threats / max(len(alert_queue), 1)) * 100 if alert_queue else 0
    heat = ("LOW" if heat_pct < 20 else "MED" if heat_pct < 50 else "HIGH" if heat_pct < 80 else "CRITICAL")
    heat_style = "green" if heat == "LOW" else "bright_yellow" if heat == "MED" else "bright_red" if heat == "HIGH" else "bold reverse red"
    heat_bar = "█" * int(heat_pct / 3) + "░" * (33 - int(heat_pct / 3))
    heat_label = Text(f" {heat} ", style="bold black")

    last_crit_time = min((a.get("ts", now) for a in alert_queue if a["severity"] in ["critical","zeroday"]), default=now)
    time_since_crit = str(now - last_crit_time).split('.')[0]

    metrics = Text()
    metrics.append(f"Total Alerts        : {len(alert_queue)}\n", style="cyan")
    metrics.append(f"Critical/KEV        : {critical_count} (Fresh 24h: {fresh_kev})\n", style="red")
    metrics.append(f"Zero-Day            : {zeroday_count}\n", style="yellow")
    metrics.append(f"Ransomware          : {ransomware_count}\n", style="#ff0066")
    metrics.append(f"APT Activity        : {apt_count}\n", style="#800080")
    metrics.append(f"Exploits/POC        : {exploit_count}\n", style="bright_red")
    metrics.append(f"New (<1h)           : {new_count}\n", style="#00ff00")
    metrics.append(f"Rate (last hour)    : {rate}/hr\n", style="bold white")
    metrics.append("Heat Level (High-Threat %):\n", style=heat_style)
    metrics.append(f"{heat_bar}{heat_label}\n", style=heat_style)
    metrics.append(f"Last Critical       : {time_since_crit} ago\n", style="dim")
    metrics.append(f"Uptime              : {uptime}\n", style="dim")

    rem = int((next_refresh - datetime.now(timezone.utc)).total_seconds())
    m, s = divmod(max(rem, 0), 60)
    status = Text()
    status.append(f"{datetime.now(timezone.utc):%H:%M:S} UTC", "bold white")
    status.append(f" — {len(alert_queue)} alerts", "bold cyan")
    if any(a["severity"] in ["critical","zeroday"] for a in alert_queue[:3]):
        status.append("  EXPLOIT IN THE WILD!!!", "bold reverse red")
    status.append(f" — Next: {m:02d}:{s:02d}", "bold bright_red")

    layout = Layout()
    layout.split_column(
        Layout(Panel(ticker_display, title="LIVE THREAT TAPE", border_style="cyan", padding=0), size=3),
        Layout(name="bottom", ratio=1)
    )
    layout["bottom"].split_row(
        Layout(Panel(table, title="[bold reverse #00ff00 on black]  THREATTAPE 1.0 // LEGENDARY EDITION  [/]", subtitle=status, border_style=border_color, padding=(1,2)), ratio=3),
        Layout(Panel(metrics, title="WAR ROOM DASHBOARD", border_style="bright_blue"))
    )

    return layout

async def main():
    console.clear()
    console.print("[bold reverse #00ff00 on black]  THREATTAPE 1.0 // LEGENDARY EDITION  — Initializing... please wait up to 30 seconds to load feeds  [/]")
    asyncio.create_task(refresher())
    await asyncio.sleep(25)

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
            except:
                key = None

            if key in {"r", "R"}:
                next_refresh = datetime.min
            elif key in {"q", "Q"}:
                break
            await asyncio.sleep(0.7)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("\n[bold reverse #ff0066]  THREATTAPE LEGENDARY — going dark. Stay dangerous.  [/]")