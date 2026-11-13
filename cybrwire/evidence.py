"""
How strong is the evidence that something is being attacked right now?

Keywords can't answer that, so every story is judged on outside signals:

    CONFIRMED  On an official exploited list (CISA KEV, ENISA EUVD)
    LIKELY     A high exploit-likelihood score (EPSS), or public exploit code plus a raised score
    REPORTED   News or a CIRCL sighting says it's exploited, without official confirmation

Severity labels, the Alerts filter, the Live Wire, sounds and notifications all
follow from this, so they can't disagree with each other.
"""

import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from typing import Dict, List, Optional

from . import cve_intel
from . import feeds
from .feeds import classify
from .incidents import CVE_RE

CONFIRMED = "CONFIRMED"
LIKELY = "LIKELY"
REPORTED = "REPORTED"

RECENT_DAYS = 30        # An exploited-list entry newer than this calls for action now
EPSS_HIGH = 0.5
EPSS_RAISED = 0.1
EXPLOIT_SOURCES = {"Exploit-DB"}  # Publishing working exploits is what these do
BREACH_SOURCE = "Have I Been Pwned"
NEWS_SCORE = 60
ZERO_DAY_BONUS = 40    # A zero-day being reported today beats a CVE listed weeks ago
TODAY_BONUS = 20

ACTIVE_EXPLOITATION = re.compile(
    r"\b(actively exploited|exploited in (the wild|attacks)|exploited to|under active exploitation|in the wild|"
    r"(attackers?|hackers?|threat actors?) (are )?(actively )?exploit\w*|mass exploitation|active exploitation)\b", re.IGNORECASE)
ZERO_DAY = re.compile(r"\b(zero[- ]day|0[- ]day)\b", re.IGNORECASE)
NOT_EXPLOITED = re.compile(r"\b(no evidence|not (been )?exploited|could be exploited|may be exploited|before .* exploited)\b", re.IGNORECASE)


@dataclass
class Evidence:
    tier: str
    score: int
    reasons: List[str] = field(default_factory=list)
    cve: Optional[str] = None
    name: str = ""       # Vendor and product, when known
    action: str = ""     # What to do about it
    due: str = ""        # CISA's deadline, as YYYY-MM-DD
    recent: bool = False # Newly on an official list
    zero_day: bool = False

    @property
    def urgent(self) -> bool:
        """Worth interrupting someone for"""
        return (self.tier == CONFIRMED and self.recent) or self.zero_day


def _days_ago(day: str, now: datetime) -> Optional[int]:
    try:
        return (now.date() - date.fromisoformat(day)).days
    except ValueError:
        return None


def _ago(days: int) -> str:
    return "today" if days <= 0 else "yesterday" if days == 1 else f"{days}d ago"


def assess_cve(cve: str, now: datetime) -> Optional[Evidence]:
    """What the outside signals say about one CVE, on their own"""
    score, reasons = 0, []
    tier, recent = None, False
    name = action = due = ""

    kev = feeds.KEV_DETAILS.get(cve)
    if kev:
        tier = CONFIRMED
        days = _days_ago(kev.get("dateAdded", ""), now)
        recent = days is not None and days <= RECENT_DAYS
        score += 150 if recent else 15  # A fresh official listing outranks any unconfirmed signal
        if days is not None and recent:
            score -= 2 * days  # Newest first among recent entries
        reasons.append(f"CISA KEV {_ago(days)}" if days is not None else "CISA KEV")
        name = feeds.product_name(kev.get("vendorProject"), kev.get("product"))
        action, due = kev.get("requiredAction", ""), kev.get("dueDate", "")

    exploited_since = feeds.EUVD_EXPLOITED.get(cve)
    if exploited_since:
        days = (now - exploited_since).days
        if not kev:
            recent = days <= RECENT_DAYS
            score += 140 if recent else 15
        else:
            score += 10
        tier = CONFIRMED
        reasons.append("ENISA exploited list")

    if cve in feeds.CIRCL_EXPLOITED and not tier:
        tier = REPORTED
        score += 50
        reasons.append("CIRCL sighting")

    poc = cve in feeds.CIRCL_POC or cve in feeds.METASPLOIT
    if poc:
        score += 15
        reasons.append("Metasploit module" if cve in feeds.METASPLOIT else "exploit public")

    epss = (cve_intel.EPSS.get(cve) or (0, 0))[0]
    if epss >= EPSS_HIGH:
        score += 40
        reasons.append(f"EPSS {epss:.0%}")
    elif epss >= EPSS_RAISED:
        score += 15
        reasons.append(f"EPSS {epss:.0%}")

    if not tier and (epss >= EPSS_HIGH or (poc and epss >= EPSS_RAISED)):
        tier = LIKELY
    if not tier:
        return None
    return Evidence(tier, score, reasons, cve, name, action, due, recent)


def _reported_by_news(alert: Dict) -> Optional[bool]:
    """None if the headline doesn't claim exploitation; otherwise whether it says zero-day"""
    if alert.get("kind") != "news":
        return None
    title = alert["title"]
    if NOT_EXPLOITED.search(title):
        return None
    zero_day = bool(ZERO_DAY.search(title))
    return zero_day if zero_day or ACTIVE_EXPLOITATION.search(title) else None


def assess(alert: Dict, now: datetime) -> Optional[Evidence]:
    title_cves = {m.upper() for m in CVE_RE.findall(alert["title"])}
    summary_cves = {m.upper() for m in CVE_RE.findall(alert.get("summary") or "")}
    best = None
    for cve in title_cves or summary_cves:
        found = assess_cve(cve, now)
        # An old CVE mentioned in passing isn't what this story is about
        if found and not title_cves and found.tier == CONFIRMED and not found.recent:
            continue
        if found and (best is None or found.score > best.score):
            best = found

    news = _reported_by_news(alert)
    if news is None:
        return best
    score = NEWS_SCORE + (ZERO_DAY_BONUS if news else 0)
    if now - alert["ts"] <= timedelta(hours=24):
        score += TODAY_BONUS
    if best is None:
        best = Evidence(REPORTED, score, [f"reported by {alert['source']}"])
    else:
        best.score += score
        best.reasons.insert(1, "in the news")
    best.zero_day = news
    return best


def apply_evidence(alerts: List[Dict], now: Optional[datetime] = None) -> List[Dict]:
    """Judge every story and set its severity from the result. Returns the alerts to keep."""
    now = now or datetime.now(timezone.utc)
    kept = []
    sources_by_cve = defaultdict(set)
    for alert in alerts:
        if alert.get("kind") == "indicators":
            kept.append(alert)
            continue
        if alert.get("signal_cve") in feeds.KEV_DETAILS:
            continue  # KEV already has a row for this one, with more to act on
        kept.append(alert)
        alert["evidence"] = assess(alert, now)
        alert["severity"] = _severity(alert)
        for found in {m.upper() for m in CVE_RE.findall(alert["title"])}:
            sources_by_cve[found].add(alert["source"])
    for alert in kept:  # Independent sources agreeing adds weight
        ev = alert.get("evidence")
        count = len(sources_by_cve.get(ev.cve, ())) if ev and ev.cve else 0
        if count > 1:
            ev.score += min(30, 10 * (count - 1))
            ev.reasons.append(f"{count} sources")
    return kept


def _severity(alert: Dict) -> str:
    ev = alert.get("evidence")
    if ev:
        if ev.tier == CONFIRMED:
            return "critical" if ev.recent else "exploit"
        return "zeroday" if ev.zero_day else "exploit"
    if alert["source"] in EXPLOIT_SOURCES or any(m.upper() in feeds.CIRCL_POC or m.upper() in feeds.METASPLOIT for m in CVE_RE.findall(alert["title"])):
        return "exploit"
    # With no evidence, only who is behind it can still be read from a headline
    label = classify(alert["title"])
    return label if label in ("ransomware", "apt") else "info"


def is_claim(alert: Dict) -> bool:
    """One ransomware gang's claim about one victim: useful in bulk, noise one at a time"""
    return alert["title"].startswith("RANSOMWARE VICTIM")


def is_breach(alert: Dict) -> bool:
    return alert["source"].startswith(BREACH_SOURCE)


def is_alert(alert: Dict, watch_hits: List[str]) -> bool:
    """What the default Alerts filter shows: something happening that you may need to act on"""
    if alert.get("kind") == "outage":
        return not alert.get("resolved")  # Something broken now; the all-clear is history
    if alert.get("evidence") or watch_hits or is_breach(alert):
        return True
    if alert["severity"] == "ransomware":
        return not is_claim(alert)
    return alert["severity"] in ("critical", "zeroday", "apt")


def due_text(ev: Evidence, now: datetime) -> str:
    if not ev.due:
        return ""
    days = _days_ago(ev.due, now)
    if days is None or days > 0:
        return ""  # A deadline that passed is no help to anyone but the original agencies
    return f"CISA deadline {date.fromisoformat(ev.due):%d %b}"
