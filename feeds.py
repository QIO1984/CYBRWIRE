"""
Feed parsing for CybrWire

Each parser turns one feed response into a list of alert dicts:
    title, summary, published, severity, source, source_file, url, ts
"""

import csv
import html
import logging
import re
from datetime import datetime, timedelta, timezone

import feedparser
import httpx

MAX_TITLE_LEN = 200  # The feed table truncates to fit the screen

# Full CISA KEV catalog (CVE ID -> description), refreshed with the KEV feed.
# The feed list only keeps the newest entries; incidents check against all of them.
KEV_CATALOG = {}
MAX_SUMMARY_LEN = 300

# Marketing, events and other non-intel posts. Only applied to RSS items with
# no threat keyword at all, so a vendor post about an exploited CVE is kept.
NON_INTEL_KEYWORDS = [
    "webinar", "podcast", "livestream", "fireside chat", "ask me anything",
    "award", "named a leader", "named one of", "recognized as a leader", "magic quadrant",
    "customer story", "success story", "case study", "ebook", "e-book", "white paper",
    "whitepaper", "infographic", "newsletter", "we're hiring", "careers at", "join us at",
    "register now", "save the date", "event recap", "booth", "partner program",
    "product update", "release notes", "now available", "new feature", "pricing",
]

THREAT_KEYWORDS = [
    "cve-", "vulnerab", "vuln", "patch", "flaw", "zero-day", "0-day", "zeroday",
    "exploit", "poc", "proof of concept", "in the wild", "malware", "ransomware",
    "trojan", "worm", "botnet", "rootkit", "backdoor", "infostealer", "stealer", "loader",
    "phishing", "apt", "threat actor", "threat group", "campaign", "breach", "attack",
    "compromise", "hacked", "leak", "stolen", "ioc", "indicator", "c2", "command and control",
    "advisory", "alert", "security update", "hotfix", "espionage", "supply chain",
]


# Severity keywords, matched as whole words so "conti" doesn't match "continue"
SEVERITY_RULES = [
    ("ransomware", re.compile(r"\b(ransom\w*|lockbit|conti|blackcat|alphv|akira|cl[o0]p|qilin|play ransomware|black basta|rhysida|medusa)\b")),
    ("apt", re.compile(r"\b(apt\s?\d+|lazarus|kimsuky|sandworm|turla|volt typhoon|salt typhoon|\w+ typhoon|\w+ blizzard|"
                       r"nation[- ]state|state[- ]sponsored|iran(ian)?|chin(a|ese)|russia(n)?|north korea(n)?|dprk)\b")),
    ("zeroday", re.compile(r"\b(zero[- ]day|0[- ]?day|wormable|in the wild|actively exploited|exploited in attacks|under active exploitation)\b")),
    ("exploit", re.compile(r"\b(exploit\w*|poc|proof[- ]of[- ]concept|rce|remote code execution|code injection|"
                           r"authentication bypass|privilege escalation)\b")),
]


def classify(text: str) -> str:
    """Severity tag for free text: the first matching rule wins, otherwise info"""
    lower = text.lower()
    return next((sev for sev, rule in SEVERITY_RULES if rule.search(lower)), "info")


def is_blog_post_content(title: str, summary: str, source_name: str = "") -> bool:
    """True for marketing/event posts that carry no threat intelligence"""
    text = f"{title} {summary}".lower()
    if any(kw in text for kw in THREAT_KEYWORDS):
        return False
    return any(kw in text for kw in NON_INTEL_KEYWORDS)


BROKEN_ENTITY = re.compile(r"&#;x([0-9a-fA-F]+);")


def clean_html(text: str) -> str:
    """Strip tags, decode entities (some feeds escape twice) and collapse whitespace"""
    text = text or ""
    for _ in range(8):
        # Repair malformed numeric entities seen in some feeds ("&#;x26;" -> "&#x26;")
        decoded = html.unescape(BROKEN_ENTITY.sub(r"&#x\1;", text))
        if decoded == text:
            break
        text = decoded
    text = text.replace("\u00c2\u00a0", " ")  # UTF-8 non-breaking space decoded as Latin-1
    return re.sub(r"\s+", " ", re.sub(r"<[^>]*>", " ", text)).strip()


DOOMSDAY_URL = "https://thebulletin.org/doomsday-clock/"
DOOMSDAY_PATTERN = re.compile(r"It is (?:now )?(\d+(?:\.\d+)?) (seconds|minutes) to midnight", re.IGNORECASE)


async def fetch_doomsday_seconds() -> int:
    """Read the current Doomsday Clock setting from the Bulletin's page description"""
    async with httpx.AsyncClient(timeout=20, follow_redirects=True,
                                 headers={"User-Agent": "Mozilla/5.0 (CybrWire)"}) as c:
        r = await c.get(DOOMSDAY_URL)
        r.raise_for_status()
    match = DOOMSDAY_PATTERN.search(r.text)
    if not match:
        raise ValueError("Doomsday Clock value not found on page")
    value = float(match.group(1))
    return int(value * 60 if match.group(2).lower() == "minutes" else value)


def parse_cisa(data, source_name, source_file):
    KEV_CATALOG.update({v["cveID"]: v.get("shortDescription", "") for v in data.get("vulnerabilities", []) if v.get("cveID")})
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
            "ts": ts,
            "kind": "advisory",
        })
    return items

# Formats feedparser doesn't recognize but some vendors publish
EXTRA_DATE_FORMATS = ["%b %d, %Y %H:%M:%S%z", "%B %d, %Y %H:%M:%S%z", "%b %d, %Y", "%B %d, %Y", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"]


def entry_time(entry):
    """Publish time of a feed entry in UTC, or None if it has no readable date"""
    # feedparser normalizes every format it understands to a UTC struct_time
    parsed = entry.get("published_parsed") or entry.get("updated_parsed")
    if parsed:
        return datetime(*parsed[:6], tzinfo=timezone.utc)
    raw = (entry.get("published") or entry.get("updated") or "").strip()
    for fmt in EXTRA_DATE_FORMATS:
        try:
            ts = datetime.strptime(raw, fmt)
        except ValueError:
            continue
        return ts.astimezone(timezone.utc) if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
    return None


def parse_rss(text, source_name, source_file):
    f = feedparser.parse(text)
    items = []
    for e in f.entries[:100]:  # Some feeds (e.g. MSRC) return thousands of entries
        ts = entry_time(e)
        undated = ts is None or ts > datetime.now(timezone.utc) + timedelta(days=1)  # Future = placeholder
        if undated:
            ts = datetime.now(timezone.utc)
        title = clean_html(e.get("title", ""))[:MAX_TITLE_LEN]
        summary = clean_html(e.get("summary") or e.get("description") or "")[:MAX_SUMMARY_LEN]
        link = e.get("link", "")
        
        # Filter out blog posts and non-threat content
        if is_blog_post_content(title, summary, source_name):
            continue  # Skip this item - it's a blog post, not threat intel
        
        sev = classify(f"{title} {summary}")
        items.append({"title": title, "summary": summary, "published": ts.strftime("%a, %d %b"), 
                      "severity": sev, "source": source_name, "source_file": source_file, "url": link, "ts": ts,
                      "undated": undated})
    return items

def _parse_iso(value):
    """Parse an ISO-8601 timestamp, assuming UTC when no offset is given"""
    try:
        ts = datetime.fromisoformat(str(value).replace("Z", "+00:00").replace(" UTC", "+00:00"))
        return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return datetime.now(timezone.utc)

def parse_ransomware_live(data, source_name, source_file):
    """Parse ransomware.live /v2/recentvictims (a list of victim posts)"""
    items = []
    for v in data:
        ts = _parse_iso(v.get("discovered") or v.get("attackdate"))
        group = v.get("group", "unknown")
        country = f" [{v['country']}]" if v.get("country") else ""
        items.append({
            "title": f"RANSOMWARE VICTIM: {v.get('victim', 'Unknown')} ({group}){country}"[:MAX_TITLE_LEN],
            "summary": f"{group} ransomware claim. Sector: {v.get('activity') or 'Unknown'}"[:MAX_SUMMARY_LEN],
            "published": ts.strftime("%a, %d %b"),
            "severity": "ransomware",
            "source": source_name,
            "source_file": source_file,
            "url": v.get("url", ""),
            "ts": ts,
            "kind": "ransomware",
        })
    return items

def parse_otx(data, source_name, source_file):
    """Parse AlienVault OTX pulse listings ({"results": [pulse, ...]})"""
    items = []
    for p in data.get("results", []):
        ts = _parse_iso(p.get("modified") or p.get("created"))
        sev = classify(f"{p.get('name', '')} {p.get('description', '')}")
        if sev == "info" and p.get("adversary"):
            sev = "apt"
        items.append({
            "title": f"OTX: {p.get('name', 'Untitled pulse')}"[:MAX_TITLE_LEN],
            "summary": (p.get("description") or "")[:MAX_SUMMARY_LEN],
            "published": ts.strftime("%a, %d %b"),
            "severity": sev,
            "source": source_name,
            "source_file": source_file,
            "url": f"https://otx.alienvault.com/pulse/{p.get('id', '')}",
            "ts": ts,
        })
    return items

def parse_ghsa(data, source_name, source_file):
    """GitHub reviewed security advisories (open-source packages)"""
    items = []
    for adv in data:
        ts = _parse_iso(adv.get("published_at"))
        ecosystems = sorted({v["package"]["ecosystem"] for v in adv.get("vulnerabilities") or [] if v.get("package")})
        packages = sorted({v["package"]["name"] for v in adv.get("vulnerabilities") or [] if v.get("package")})
        summary = clean_html(adv.get("summary") or "")
        cve = f"{adv['cve_id']} " if adv.get("cve_id") and adv["cve_id"] not in summary else ""
        title = f"{cve}{summary} [{', '.join(ecosystems)}]" if ecosystems else f"{cve}{summary}"
        # Advisory bodies are Markdown; drop heading marks and emphasis for the one-line summary
        detail = re.sub(r"(^|\s)#+\s*|\*\*|`", " ", clean_html(adv.get("description") or ""))
        detail = re.sub(r"\s+", " ", detail).strip()
        items.append({
            "title": title[:MAX_TITLE_LEN],
            "summary": f"{adv.get('severity', '').title()} severity in {', '.join(packages[:3])}. {detail}"[:MAX_SUMMARY_LEN],
            "published": ts.strftime("%a, %d %b"),
            "severity": classify(f"{summary} {detail}"),
            "source": source_name,
            "source_file": source_file,
            "url": adv.get("html_url", ""),
            "ts": ts,
            "kind": "advisory",
        })
    return items

def parse_threatfox(data, source_name, source_file, limit=20):
    """abuse.ch ThreatFox: newest high-confidence indicators with their malware family"""
    labels = {"botnet_cc": "C2", "payload_delivery": "PAYLOAD", "payload": "PAYLOAD"}
    iocs = [x for x in data.get("data") or [] if (x.get("confidence_level") or 0) >= 75]
    iocs.sort(key=lambda x: x.get("first_seen") or "", reverse=True)
    items = []
    for x in iocs[:limit]:
        ts = _parse_iso(x.get("first_seen"))
        ioc_type = (x.get("ioc_type") or "").split(":")[0]  # "ip:port" -> "ip"
        value = x.get("ioc", "")
        malware = x.get("malware_printable") or "unknown malware"
        label = labels.get(x.get("threat_type"), "IOC")
        items.append({
            "title": f"{label} {ioc_type.upper()}: {value} ({malware})"[:MAX_TITLE_LEN],
            "summary": f"ThreatFox: {x.get('threat_type_desc') or x.get('threat_type', '')}, {malware}, confidence {x.get('confidence_level')}%"[:MAX_SUMMARY_LEN],
            "published": ts.strftime("%a, %d %b"),
            "severity": "exploit",
            "source": source_name,
            "source_file": source_file,
            "url": f"https://threatfox.abuse.ch/ioc/{x.get('id')}/",
            "ts": ts,
            "kind": "indicators",
            "ioc": value.split(":")[0] if ioc_type == "ip" else value,
            "ioc_type": ioc_type,
            "threat": malware,
        })
    return items

def parse_json(data, source_name, source_file):
    """Pick a JSON parser based on the shape of the response"""
    if isinstance(data, dict) and "vulnerabilities" in data:
        return parse_cisa(data, source_name, source_file)
    if isinstance(data, dict) and "results" in data:
        return parse_otx(data, source_name, source_file)
    if isinstance(data, list) and data and isinstance(data[0], dict) and "victim" in data[0]:
        return parse_ransomware_live(data, source_name, source_file)
    if isinstance(data, list) and data and isinstance(data[0], dict) and "ghsa_id" in data[0]:
        return parse_ghsa(data, source_name, source_file)
    logging.warning(f"No parser for JSON feed '{source_name}'")
    return []

IP_OR_CIDR = re.compile(r'^\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?$')

def parse_txt(text, source_name, source_file):
    """Parse plain-text indicator lists: IP/CIDR lists, URL lists, DShield block, URLhaus CSV"""
    lines = [line.strip() for line in text.splitlines()
             if line.strip() and not line.lstrip().startswith(("#", ";"))]
    now = datetime.now(timezone.utc)
    items = []
    for line in lines[:20]:  # Indicator lists can have thousands of lines
        ts = now
        severity = "exploit"
        if line.startswith('"'):
            # URLhaus CSV: id, dateadded, url, url_status, last_online, threat, tags, urlhaus_link, reporter
            cols = next(csv.reader([line]))
            if len(cols) < 8:
                continue
            ts = _parse_iso(cols[1])
            title = f"MALWARE URL: {cols[2]} ({cols[5]})"
            summary = f"URLhaus: {cols[5]}, status {cols[3]}"
            link = cols[7]
            ioc, ioc_type, threat = cols[2], "url", cols[5].replace("_", " ")
        else:
            parts = re.split(r'[\s;]+', line)
            first = parts[0]
            if first.startswith(("http://", "https://")):
                title = f"PHISHING URL: {first}"
                summary = f"Reported by {source_name}"
                link = ""
                ioc, ioc_type, threat = first, "url", "phishing"
            elif IP_OR_CIDR.match(first):
                # DShield block.txt: start, end, netblock, attacks, name, country, email
                if len(parts) >= 4 and IP_OR_CIDR.match(parts[1]) and parts[2].isdigit():
                    title = f"TOP MALICIOUS IP: {first}/{parts[2]} ({parts[3]} attacks)"
                    ioc, ioc_type, threat = f"{first}/{parts[2]}", "cidr", f"{parts[3]} attacks"
                else:
                    title = f"TOP MALICIOUS IP: {first}"
                    ioc, ioc_type, threat = first, "cidr" if "/" in first else "ip", "listed"
                summary = f"Listed by {source_name}"
                link = f"https://isc.sans.edu/ipinfo.html?ip={first.split('/')[0]}"
            else:
                continue
        items.append({"title": title[:MAX_TITLE_LEN],
                      "undated": not line.startswith('"'),  # Only URLhaus CSV rows carry a date
                      "summary": summary[:MAX_SUMMARY_LEN],
                      "published": ts.strftime("%a, %d %b"),
                      "severity": severity,
                      "source": source_name,
                      "source_file": source_file,
                      "url": link,
                      "ts": ts,
                      "kind": "indicators",
                      "ioc": ioc,
                      "ioc_type": ioc_type,
                      "threat": threat})
    return items
