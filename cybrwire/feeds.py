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
# CVE ID -> the full KEV record (vendor, product, dates, required action) for the CVE card
KEV_DETAILS = {}
EUVD_EXPLOITED = {}    # CVE -> when ENISA says exploitation began
CIRCL_EXPLOITED = set()  # CVEs with a reported sighting of exploitation
CIRCL_POC = set()        # CVEs with public exploit code reported
METASPLOIT = set()       # CVEs that have a Metasploit exploit module
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
    ("apt", None),  # Needs two checks, see is_apt
    ("zeroday", re.compile(r"\b(zero[- ]day|0[- ]?day|wormable|in the wild|actively exploited|exploited in attacks|under active exploitation)\b")),
    ("exploit", re.compile(r"\b(exploit\w*|poc|proof[- ]of[- ]concept|rce|remote code execution|code injection|"
                           r"authentication bypass|privilege escalation)\b")),
]


# A named group or "nation-state" is enough on its own. A country name only counts next to
# hacking wording, otherwise police arrests and drone strikes read as APT activity.
APT_GROUP = re.compile(
    r"\b(apt\s?\d+|lazarus|kimsuky|sandworm|turla|gamaredon|mustang panda|charming kitten|muddywater|oilrig|"
    r"fancy bear|cozy bear|(volt|salt|silk|flax|linen|violet|mulberry|granite) typhoon|"
    r"(forest|midnight|seashell|star|aqua|cadet) blizzard|nation[- ]state|state[- ]sponsored)\b")
APT_COUNTRY = re.compile(r"\b(iran(ian)?|chin(a|ese)|russia(n)?|north korea(n)?|dprk)\b")
APT_CYBER = re.compile(
    r"\b(cyber\w*|hack\w*|malware|espionage|spyware|backdoor|phishing|intrusions?|threat actors?|apt|ddos|"
    r"state[- ]backed|breach\w*)\b")


def is_apt(lower: str) -> bool:
    return bool(APT_GROUP.search(lower) or (APT_COUNTRY.search(lower) and APT_CYBER.search(lower)))


def classify(text: str) -> str:
    """Severity tag for free text: the first matching rule wins, otherwise info"""
    lower = text.lower()
    for sev, rule in SEVERITY_RULES:
        if (is_apt(lower) if sev == "apt" else rule.search(lower)):
            return sev
    return "info"


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
                                 headers={"User-Agent": "CybrWire/1.0 (+https://github.com/QIO1984/CYBRWIRE)"}) as c:
        r = await c.get(DOOMSDAY_URL)
        r.raise_for_status()
    match = DOOMSDAY_PATTERN.search(r.text)
    if not match:
        raise ValueError("Doomsday Clock value not found on page")
    value = float(match.group(1))
    return int(value * 60 if match.group(2).lower() == "minutes" else value)


def product_name(vendor, product):
    """'WordPress' + 'WordPress Core' reads as 'WordPress Core', not the vendor twice"""
    vendor, product = (vendor or "").strip(), (product or "").strip()
    if vendor and product.lower().startswith(vendor.lower()):
        return product
    return " ".join(x for x in (vendor, product) if x)


def parse_cisa(data, source_name, source_file):
    KEV_CATALOG.update({v["cveID"]: v.get("shortDescription", "") for v in data.get("vulnerabilities", []) if v.get("cveID")})
    KEV_DETAILS.update({v["cveID"]: v for v in data.get("vulnerabilities", []) if v.get("cveID")})
    items = []
    for v in data.get("vulnerabilities", []):
        date_added = v.get("dateAdded", "")
        try:
            ts = datetime.fromisoformat(date_added + "T00:00:00+00:00") if date_added else datetime.now(timezone.utc)
        except Exception:
            ts = datetime.now(timezone.utc)
        product = product_name(v.get("vendorProject"), v.get("product"))
        items.append({
            "title": f"KEV ACTIVE → {v['cveID']}" + (f": {product}" if product else ""),
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

def parse_circl(data, source_name, source_file):
    """
    CIRCL sightings are signals only. On their own they're a bare CVE number with no
    product, often years old, so they raise the stories that mention them instead.
    """
    for sighting in data.get("data", []):
        cve = (sighting.get("vulnerability") or "").upper()
        if cve.startswith("CVE-"):
            if sighting.get("type") == "published-proof-of-concept":
                CIRCL_POC.add(cve)
            elif sighting.get("type") == "exploited":
                CIRCL_EXPLOITED.add(cve)
    return []


def parse_metasploit(data, source_name, source_file):
    """
    Metasploit's module list (Rapid7, BSD-3-Clause). A module is public, working exploit code, so
    like CIRCL this only raises stories that mention the CVE. It adds no rows of its own.
    """
    for module in (data.values() if isinstance(data, dict) else data):
        if not isinstance(module, dict) or module.get("type") != "exploit":
            continue
        for ref in module.get("references") or []:
            ref = str(ref).upper()
            if ref.startswith("CVE-"):
                METASPLOIT.add(ref)
    return []


SCHEDULED = re.compile(r"\b(scheduled|maintenance|lifecycle update|planned)\b", re.IGNORECASE)
RESOLVED = re.compile(r"\b(resolved|operating normally|completed|has been fixed|recovered|no (operational )?impact)\b", re.IGNORECASE)
OUTAGE_ACTIVE_HOURS = 48  # An incident with no update for this long is history, whatever its last status says


def parse_status(text, source_name, source_file):
    """
    A service's own status page (Atom or RSS): what is broken right now. Planned maintenance is
    left out, and so are future-dated entries, which are announcements, not outages.
    """
    service = re.sub(r"\s+status$", "", source_name, flags=re.IGNORECASE)
    now = datetime.now(timezone.utc)
    newest = {}  # Status pages post every update as its own entry: keep the latest per incident
    for e in feedparser.parse(text).entries[:60]:
        ts = entry_time(e)
        raw_title = clean_html(e.get("title", ""))
        summary = clean_html(e.get("summary") or e.get("description") or "")
        if ts is None or ts > now + timedelta(minutes=5) or SCHEDULED.search(raw_title):
            continue
        # The newest update comes first in the text, so its status word is the current state
        resolved = bool(RESOLVED.search(f"{raw_title} {summary[:160]}")) or now - ts > timedelta(hours=OUTAGE_ACTIVE_HOURS)
        title = re.sub(r"^(Service is operating normally|Informational message|Service impact|Service disruption): ?", "", raw_title, flags=re.IGNORECASE)
        title = re.sub(r"^\[?RESOLVED\]?:? ?", "", title, flags=re.IGNORECASE)
        key = title.lower()
        if key in newest and newest[key][0] >= ts:
            continue
        newest[key] = (ts, title, summary, e.get("link", ""), resolved)
    items = []
    for ts, title, summary, link, resolved in newest.values():
        label = "RESOLVED" if resolved else "OUTAGE"
        items.append({"title": f"{label} · {service}: {title}"[:MAX_TITLE_LEN], "summary": summary[:MAX_SUMMARY_LEN],
                      "published": ts.strftime("%a, %d %b"), "severity": "info", "source": source_name,
                      "source_file": source_file, "url": link, "ts": ts, "kind": "outage", "resolved": resolved})
    return items


def parse_euvd(data, source_name, source_file):
    """ENISA's list of exploited vulnerabilities"""
    items = []
    for v in data if isinstance(data, list) else data.get("items", []):
        cve = next((a.strip().upper() for a in (v.get("aliases") or "").split("\n") if a.strip().upper().startswith("CVE-")), None)
        if not cve:
            continue
        ts = None
        raw = (v.get("exploitedSince") or "").replace("\u202f", " ")
        try:
            ts = datetime.strptime(raw, "%b %d, %Y, %I:%M:%S %p").replace(tzinfo=timezone.utc)
        except ValueError:
            ts = datetime.now(timezone.utc)
        EUVD_EXPLOITED[cve] = ts
        items.append({"title": f"Exploited (ENISA) → {cve}", "summary": clean_html(v.get("description") or "")[:MAX_SUMMARY_LEN],
                      "published": ts.strftime("%a, %d %b"), "severity": "critical", "source": source_name,
                      "source_file": source_file, "url": f"https://euvd.enisa.europa.eu/vulnerability/{v.get('id', '')}",
                      "ts": ts, "kind": "advisory", "signal_cve": cve})
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

def parse_urlhaus(data, source_name, source_file, limit=20):
    """abuse.ch URLhaus API: newest malware distribution URLs"""
    items = []
    for x in (data.get("urls") or [])[:limit]:
        url = x.get("url", "")
        threat = (x.get("threat") or "malware").replace("_", " ")
        ts = _parse_iso((x.get("date_added") or "").replace(" UTC", "+00:00"))
        items.append({
            "title": f"MALWARE URL: {url} ({threat})"[:MAX_TITLE_LEN],
            "summary": f"URLhaus: {threat}, status {x.get('url_status', 'unknown')}"[:MAX_SUMMARY_LEN],
            "published": ts.strftime("%a, %d %b"),
            "severity": "exploit",
            "source": source_name,
            "source_file": source_file,
            "url": x.get("urlhaus_reference", ""),  # The report page, never the malware URL itself
            "ts": ts,
            "kind": "indicators",
            "ioc": url,
            "ioc_type": "url",
            "threat": threat,
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
