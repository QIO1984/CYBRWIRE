"""
Plain-text digest for CybrWire: a summary for a terminal, pipe or cron job,
built only from the feeds. No AI provider is called.
"""

from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Dict, List

from .dedupe import group_duplicates
from .incidents import KIND_LABELS, SEVERITY_RANK, age, build_incidents
from .state import alert_key

MAX_ITEMS = 10
SEVERITY_LABELS = [("critical", "Critical/KEV"), ("zeroday", "Zero-day"), ("ransomware", "Ransomware"),
                   ("apt", "APT"), ("exploit", "Exploit"), ("info", "Info")]


def _line(alert: Dict) -> str:
    ev = alert.get("evidence")
    label = ev.tier if ev else alert["severity"].upper()
    text = f"  [{label:<10}] {alert['title'][:110]}\n      {age(alert['ts'])} ago, {alert['source']}  {alert.get('url') or ''}".rstrip()
    if ev:
        text += "\n      Why: " + ", ".join(ev.reasons)
        if ev.action:
            text += f"\n      Action: {ev.action[:200]}"
    return text


def _section(lines: List[str], heading: str, items: List[Dict]) -> None:
    lines += ["", f"{heading} ({len(items)})"]
    lines += [_line(a) for a in items[:MAX_ITEMS]] or ["  None"]
    if len(items) > MAX_ITEMS:
        lines.append(f"  ...and {len(items) - MAX_ITEMS} more")


def build_digest(alerts: List[Dict], hours: int, watchlist, kev_catalog: Dict, failed_feeds: Dict, now: datetime = None) -> str:
    now = now or datetime.now(timezone.utc)
    window = [a for a in alerts if a["ts"] >= now - timedelta(hours=hours)]
    groups = group_duplicates(window)
    stories = [a for a in window if alert_key(a) not in groups.leader_of and a.get("kind") != "indicators"]
    stories.sort(key=lambda a: (SEVERITY_RANK.get(a["severity"], 9), -a["ts"].timestamp()))

    counts = Counter(a["severity"] for a in stories)
    lines = [f"CYBRWIRE DIGEST  last {hours}h  generated {now:%Y-%m-%d %H:%M} UTC",
             f"{len(stories)} stories from {len({a['source'] for a in stories})} sources "
             f"({len(groups.leader_of)} duplicate reports merged)",
             "  ".join(f"{label} {counts[sev]}" for sev, label in SEVERITY_LABELS)]

    _section(lines, "EXPLOITATION EVIDENCE", sorted((a for a in stories if a.get("evidence")),
                                                    key=lambda a: -a["evidence"].score))
    if watchlist.terms:
        _section(lines, "WATCHLIST HITS", [a for a in stories if watchlist.hits(a)])
    claims = sum(1 for a in stories if a["title"].startswith("RANSOMWARE VICTIM"))
    if claims:
        lines += ["", f"RANSOMWARE CLAIMS: {claims}"]

    incidents = build_incidents(window, kev_catalog)
    lines += ["", f"TOP INCIDENTS ({len(incidents)})"]
    for inc in incidents[:MAX_ITEMS]:
        kev = ", KEV" if inc.kev else ""
        lines.append(f"  {KIND_LABELS[inc.kind]} {inc.value}: {len(inc.sources)} source{'s' if len(inc.sources) != 1 else ''}{kev}. {inc.headline[:90]}")
    if not incidents:
        lines.append("  None")

    if failed_feeds:
        lines += ["", f"FEEDS THAT FAILED ({len(failed_feeds)}): " + ", ".join(sorted(failed_feeds))]
    return "\n".join(lines)
