"""
The IOC lookup page: what the box understands, what to suggest, and how results read.

Everything here is plain functions over data, so the layout can be tested without a screen.
"""

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, Iterable, List, Optional, Tuple

from rich.text import Text

from .enrichment import ThreatLevel, detect_indicator_type
from .incidents import age

# Provider key -> (display name, indicator types it can answer, note about the free tier)
PROVIDERS: Dict[str, Tuple[str, Tuple[str, ...], str]] = {
    "abuseipdb": ("AbuseIPDB", ("ip",), "IP addresses only"),
    "virustotal": ("VirusTotal", ("ip", "hash", "domain", "url"), "free tier: 4 lookups a minute, 500 a day"),
    "pulsedive": ("Pulsedive", ("ip", "hash", "domain", "url"), "free tier: a limited indicator database"),
    "abusech": ("Abuse.ch", ("ip", "hash", "domain", "url"), "hashes via MalwareBazaar, the rest via URLhaus"),
}

PLURALS = {"ip": "IPs", "hash": "hashes", "domain": "domains", "url": "URLs"}
LEVEL_ORDER = [ThreatLevel.CLEAN, ThreatLevel.LOW, ThreatLevel.MEDIUM, ThreatLevel.HIGH, ThreatLevel.CRITICAL]
MAX_RECENT = 8
MAX_FEED = 8
MAX_FACTS = 6

# What to show, in order, for the facts providers return (key in details, label)
FACTS = [("country", "Country"), ("isp", "ISP"), ("asn", "ASN"), ("network", "Network"), ("domain", "Domain"),
         ("report_count", "Reports"), ("last_reported", "Last reported"), ("first_reported", "First reported"),
         ("malicious_vendors", "Malicious"), ("suspicious_vendors", "Suspicious"), ("threat", "Threat"),
         ("threat_type", "Threat type"), ("malware_family", "Malware"), ("signature_count", "Signatures"),
         ("submission_count", "Submissions"), ("threat_feed_count", "Feeds"), ("is_whitelisted", "Whitelisted")]


# ---- understanding what was typed or pasted
def refang(text: str) -> str:
    """Undo the 'defanging' reports use so an indicator can't be clicked by accident:
    hxxps://evil[.]com -> https://evil.com, 1[.]2[.]3[.]4 -> 1.2.3.4"""
    value = text.strip().strip("\"'`<>").strip()
    value = re.sub(r"\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}|\[dot\]|\(dot\)", ".", value, flags=re.IGNORECASE)
    value = re.sub(r"\[:\]|\[colon\]", ":", value, flags=re.IGNORECASE)
    value = re.sub(r"^hxxp", "http", value, flags=re.IGNORECASE)
    value = re.sub(r"^fxp", "ftp", value, flags=re.IGNORECASE)
    value = value.replace("[://]", "://").replace("[@]", "@").replace("[at]", "@")
    return value


def describe(indicator: str) -> Tuple[str, str]:
    """(label for the chip, type the providers use), like ('SHA-256', 'hash')"""
    value = indicator.strip()
    if not value:
        return "", ""
    kind = detect_indicator_type(value)
    if kind == "hash":
        label = {32: "MD5", 40: "SHA-1", 64: "SHA-256", 128: "SHA-512"}.get(len(value), "Hash")
    elif kind == "ip":
        label = "IPv6" if ":" in value else "IPv4"
    elif kind == "domain":
        label = "Domain"
    else:
        label = "URL"
    return label, kind


def kind_chip(indicator: str, palette) -> Text:
    """The small label beside the box that says what the app thinks you typed"""
    label, kind = describe(refang(indicator))
    if not label:
        return Text("")
    looks_right = kind != "domain" or "." in indicator
    return Text(f" {label} ", style=f"bold {palette.bg} on {palette.accent if looks_right else palette.muted}")


# ---- what to offer before anything has been typed
@dataclass
class Suggestion:
    origin: str    # "recent" (you looked it up) or "feed" (it arrived in an indicator feed)
    value: str
    note: str


def suggestions(recent: Iterable[str], alerts: List[dict], now: Optional[datetime] = None) -> List[Suggestion]:
    """Your recent lookups first, then the freshest indicators from the feeds, without repeats"""
    now = now or datetime.now(timezone.utc)
    seen, out = set(), []
    for value in list(recent)[:MAX_RECENT]:
        if value not in seen:
            seen.add(value)
            out.append(Suggestion("recent", value, "looked up this session"))
    feed = [a for a in alerts if a.get("kind") == "indicators" and a.get("ioc")]
    feed.sort(key=lambda a: a["ts"], reverse=True)
    taken = 0
    for a in feed:
        value = a["ioc"].split("/")[0] if a.get("ioc_type") == "cidr" else a["ioc"]
        if value in seen:
            continue
        seen.add(value)
        bits = [a.get("threat") or a.get("source", ""), f"{a.get('source', '')} · {age(a['ts'])}" if a.get("threat") else age(a["ts"])]
        out.append(Suggestion("feed", value, " · ".join(b for b in bits if b)))
        taken += 1
        if taken >= MAX_FEED:
            break
    return out


# ---- reading results
def verdict(results: Dict[str, object]) -> Tuple[Optional[ThreatLevel], int, int]:
    """(worst level reported, providers that flag it as malicious, providers that answered)"""
    answered = [r for r in results.values() if r is not None]
    if not answered:
        return None, 0, 0
    worst = max((r.threat_level for r in answered), key=LEVEL_ORDER.index)
    return worst, sum(1 for r in answered if r.is_malicious), len(answered)


def level_color(level: ThreatLevel, palette) -> str:
    return {ThreatLevel.CLEAN: palette.good, ThreatLevel.LOW: palette.info, ThreatLevel.MEDIUM: palette.warn,
            ThreatLevel.HIGH: palette.bad, ThreatLevel.CRITICAL: palette.critical}[level]


def meter(score: Optional[float], palette, color: str, width: int = 12) -> Text:
    filled = round(max(0, min(100, score or 0)) / 100 * width)
    bar = Text("█" * filled, style=color)
    bar.append("░" * (width - filled), style=palette.surface if not palette.monochrome else palette.muted)
    return bar


def _fact_value(value) -> str:
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, (list, tuple)):
        shown = ", ".join(str(v)[:24] for v in value[:3])
        return shown + (f" (+{len(value) - 3})" if len(value) > 3 else "")
    if isinstance(value, dict):
        return f"{len(value)} items"
    return str(value)[:40]


def facts(details: Dict[str, object], limit: int = MAX_FACTS) -> List[Tuple[str, str]]:
    """The few facts worth reading, in a fixed order, skipping anything empty"""
    out = []
    for key, label in FACTS:
        value = details.get(key)
        if value in (None, "", [], {}):
            continue
        out.append((label, _fact_value(value)))
        if len(out) >= limit:
            break
    return out


def providers_line(configured: Iterable[str], kind: str, palette) -> Text:
    """Which providers are on, and which of them can answer this kind of indicator"""
    configured = set(configured)
    line = Text()
    line.append("PROVIDERS  ", style=f"bold {palette.accent}")
    for key, (name, accepts, _note) in PROVIDERS.items():
        if key not in configured:
            line.append(f"○ {name} ", style=palette.muted)
            line.append("(no key)  ", style=palette.muted)
        elif kind and kind not in accepts:
            line.append(f"● {name} ", style=palette.muted)
            line.append(f"(not for {PLURALS.get(kind, kind)})  ", style=palette.muted)
        else:
            line.append(f"● {name}  ", style=palette.good)
    return line


def render_results(query: str, results: Dict[str, object], palette, shown_as: str = "") -> Text:
    """The answer: the indicator and its type, one verdict, then a row per provider with its key facts"""
    out = Text()
    label, kind = describe(query)
    head = Text()
    head.append(query, style=f"bold {palette.text}")
    head.append(f"   {label}", style=palette.accent)
    if shown_as and shown_as != query:
        head.append(f"   (typed as {shown_as})", style=palette.muted)
    out.append_text(head)
    out.append("\n\n")
    worst, flagged, answered = verdict(results)
    if worst is None:
        out.append("NO RESULTS\n", style=f"bold {palette.accent}")
        out.append(f"No provider has a record of {query}.\n", style=palette.muted)
        out.append("That does not mean it is safe, only that nobody here has seen it.\n", style=palette.muted)
        return out
    color = level_color(worst, palette)
    out.append(f" {worst.value.upper()} ", style=f"bold {palette.bg} on {color}")
    out.append(f"   {flagged} of {answered} provider{'s' if answered != 1 else ''} flag it as malicious\n\n", style=palette.text)
    for key, data in results.items():
        if data is None:
            continue
        name = PROVIDERS.get(key, (key,))[0]
        level_style = level_color(data.threat_level, palette)
        row = Text()
        row.append(f"{name:<12}", style=f"bold {palette.text}")
        row.append_text(meter(data.reputation_score, palette, level_style))
        row.append(f" {int(data.reputation_score or 0):>3}/100  ", style=palette.muted)
        row.append(data.threat_level.value.upper(), style=f"bold {level_style}")
        out.append_text(row)
        out.append("\n")
        shown = facts(data.details or {})
        for i in range(0, len(shown), 3):
            out.append("  ")
            for j, (fact_label, value) in enumerate(shown[i:i + 3]):
                if j:
                    out.append("   ·   ", style=palette.muted)
                out.append(f"{fact_label} ", style=palette.muted)
                out.append(value, style=palette.text)
            out.append("\n")
        out.append("\n")
    out.append("CLEAN means a provider has no record of the indicator, not that it is safe.\n", style=palette.muted)
    return out


def render_loading(query: str, count: int, palette) -> Text:
    out = Text()
    out.append("Looking up ", style=palette.muted)
    out.append(query, style=f"bold {palette.text}")
    out.append(f" across {count} provider{'s' if count != 1 else ''}…", style=palette.muted)
    return out


def render_no_providers(palette) -> Text:
    """Shown until the first key is added: what each provider offers and how to turn it on"""
    out = Text()
    out.append("NO PROVIDERS YET\n\n", style=f"bold {palette.warn}")
    out.append("Add a free key and this page looks up any IP address, file hash, domain or URL.\n\n", style=palette.text)
    for key, (name, accepts, note) in PROVIDERS.items():
        out.append(f"  {name:<12}", style=f"bold {palette.accent}")
        out.append(f"{', '.join(accepts) if len(accepts) < 4 else 'IPs, hashes, domains, URLs'}  ", style=palette.text)
        out.append(f"({note})\n", style=palette.muted)
    out.append("\nPress Shift+K, or click Add API keys below.\n", style=palette.muted)
    return out
