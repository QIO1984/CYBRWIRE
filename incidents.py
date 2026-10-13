"""
Incident correlation for CybrWire

Groups alerts that point at the same thing. An incident is only created when
the evidence is independent - the same CVE, IP or hash reported by at least two
different sources - or when a named threat actor shows up in several alerts.
"""

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional

SEVERITY_RANK = {"critical": 0, "zeroday": 1, "ransomware": 2, "apt": 3, "exploit": 4, "info": 5}

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
HASH_RE = re.compile(r"\b(?:[a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32})\b", re.IGNORECASE)
RANSOM_GROUP_RE = re.compile(r"^RANSOMWARE VICTIM: .* \(([^)]+)\)")

# Well-known actor names and their common aliases -> canonical display name
ACTORS = {
    "lazarus": "Lazarus Group", "kimsuky": "Kimsuky", "andariel": "Andariel",
    "apt28": "APT28 (Fancy Bear)", "fancy bear": "APT28 (Fancy Bear)", "forest blizzard": "APT28 (Fancy Bear)",
    "apt29": "APT29 (Cozy Bear)", "cozy bear": "APT29 (Cozy Bear)", "midnight blizzard": "APT29 (Cozy Bear)",
    "sandworm": "Sandworm", "seashell blizzard": "Sandworm", "turla": "Turla", "gamaredon": "Gamaredon",
    "apt41": "APT41", "volt typhoon": "Volt Typhoon", "salt typhoon": "Salt Typhoon", "silk typhoon": "Silk Typhoon",
    "mustang panda": "Mustang Panda", "charming kitten": "Charming Kitten", "apt35": "Charming Kitten",
    "muddywater": "MuddyWater", "oilrig": "OilRig", "apt34": "OilRig",
    "scattered spider": "Scattered Spider", "fin7": "FIN7", "fin8": "FIN8", "ta505": "TA505",
    "lockbit": "LockBit", "blackcat": "ALPHV/BlackCat", "alphv": "ALPHV/BlackCat", "clop": "Cl0p", "cl0p": "Cl0p",
    "akira": "Akira", "black basta": "Black Basta", "qilin": "Qilin", "rhysida": "Rhysida",
    "medusa": "Medusa", "play ransomware": "Play", "8base": "8Base", "bianlian": "BianLian",
    "ransomhub": "RansomHub", "conti": "Conti",
}
ACTOR_RE = re.compile(r"\b(" + "|".join(re.escape(k) for k in sorted(ACTORS, key=len, reverse=True)) + r")\b", re.IGNORECASE)

KIND_LABELS = {"cve": "CVE", "ip": "IP", "hash": "HASH", "actor": "ACTOR"}


@dataclass
class Incident:
    kind: str                       # cve | ip | hash | actor
    value: str                      # CVE ID, IP, hash or actor name
    alerts: List[dict] = field(default_factory=list)
    kev: Optional[str] = None       # CISA KEV description, when the CVE is known exploited

    @property
    def sources(self) -> List[str]:
        return sorted({a.get("source", "Unknown") for a in self.alerts})

    @property
    def severity(self) -> str:
        return min((a.get("severity", "info") for a in self.alerts), key=lambda s: SEVERITY_RANK.get(s, 99))

    @property
    def first_seen(self) -> datetime:
        return min(a["ts"] for a in self.alerts)

    @property
    def last_seen(self) -> datetime:
        return max(a["ts"] for a in self.alerts)

    @property
    def timeline(self) -> List[dict]:
        return sorted(self.alerts, key=lambda a: a["ts"], reverse=True)

    @property
    def headline(self) -> str:
        """The most descriptive alert title, excluding bare feed boilerplate"""
        titles = [a["title"] for a in self.timeline if not a["title"].startswith(("KEV ACTIVE", "TOP MALICIOUS IP"))]
        return titles[0] if titles else self.timeline[0]["title"]

    @property
    def what(self) -> str:
        """One-paragraph explanation of what this incident is about"""
        if self.kev:
            return self.kev
        if self.kind == "ip":
            return f"{self.value} appears on {len(self.sources)} independent blocklists or reports."
        if self.kind == "actor":
            victims = [a for a in self.alerts if a["title"].startswith("RANSOMWARE VICTIM")]
            if victims:
                return f"{self.value} claimed {len(victims)} victim(s) in this window; also referenced in {len(self.alerts) - len(victims)} report(s)."
            return f"{self.value} is referenced in {len(self.alerts)} reports from {len(self.sources)} sources."
        summaries = [a["summary"] for a in self.alerts if a.get("summary")]
        # Prefer text that actually mentions this indicator over a neighbouring CVE's summary
        specific = [s for s in summaries if self.value.lower() in s.lower()]
        return max(specific or summaries, key=len) if summaries else self.headline

    @property
    def why(self) -> str:
        names = ", ".join(self.sources[:5]) + (f" +{len(self.sources) - 5} more" if len(self.sources) > 5 else "")
        noun = {"cve": "this CVE", "ip": "this IP", "hash": "this file hash", "actor": "this actor"}[self.kind]
        return f"{len(self.sources)} source(s) mention {noun}: {names}"

    def related(self, all_incidents: List["Incident"]) -> List[str]:
        """Other correlated indicators that share alerts with this incident"""
        mine = {id(a) for a in self.alerts}
        return [f"{KIND_LABELS[o.kind]} {o.value}" for o in all_incidents
                if o is not self and mine & {id(a) for a in o.alerts}][:4]

    @property
    def url(self) -> str:
        return next((a.get("url") for a in self.timeline if a.get("url")), "")


def _is_public_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


def _indicators(alert: dict):
    text = f"{alert.get('title', '')} {alert.get('summary', '')}"
    for cve in set(m.upper() for m in CVE_RE.findall(text)):
        yield "cve", cve
    for ip in set(IP_RE.findall(text)):
        if _is_public_ip(ip):
            yield "ip", ip
    for h in set(m.lower() for m in HASH_RE.findall(text)):
        yield "hash", h
    actors = {ACTORS[m.lower()] for m in ACTOR_RE.findall(text)}
    group = RANSOM_GROUP_RE.match(alert.get("title", ""))
    if group:
        actors.add(ACTORS.get(group.group(1).lower(), group.group(1).title()))
    for actor in actors:
        yield "actor", actor


def build_incidents(alerts: List[dict], kev_catalog: Optional[Dict[str, str]] = None) -> List[Incident]:
    kev_catalog = kev_catalog or {}
    groups: Dict[tuple, Incident] = {}
    for alert in alerts:
        for kind, value in _indicators(alert):
            inc = groups.setdefault((kind, value), Incident(kind, value))
            inc.alerts.append(alert)
            if kind == "cve" and value in kev_catalog:
                inc.kev = kev_catalog[value] or "Listed in the CISA Known Exploited Vulnerabilities catalog."

    incidents = [
        inc for inc in groups.values()
        if len(inc.sources) >= 2 or (inc.kind == "actor" and len(inc.alerts) >= 2)
    ]
    incidents.sort(key=lambda i: (SEVERITY_RANK.get(i.severity, 99), -len(i.sources), -i.last_seen.timestamp()))
    return incidents


def age(ts: datetime, now: Optional[datetime] = None) -> str:
    """Compact relative time: 5m, 3h, 2d"""
    seconds = max(0, ((now or datetime.now(timezone.utc)) - ts).total_seconds())
    if seconds < 3600:
        return f"{int(seconds // 60)}m"
    if seconds < 86400:
        return f"{int(seconds // 3600)}h"
    return f"{int(seconds // 86400)}d"
