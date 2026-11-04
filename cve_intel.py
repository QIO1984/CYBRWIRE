"""
CVE scoring for CybrWire: EPSS exploit likelihood (FIRST.org) and CVSS severity (NVD)

EPSS is fetched in batches after each feed refresh. CVSS comes from the NVD API,
whose free tier allows 5 requests per 30 seconds, so it is fetched only for the
CVEs a user is looking at and cached permanently in the app state.
"""

import asyncio
import logging
import time
from datetime import datetime, timezone
from typing import Dict, Iterable, Optional, Tuple

import httpx

EPSS_URL = "https://api.first.org/data/v1/epss"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_BATCH = 100        # CVEs per EPSS request
EPSS_MAX_BATCHES = 5    # per refresh
NVD_INTERVAL = 6.5      # seconds between NVD requests without a key (5 per 30s)
NVD_INTERVAL_KEYED = 0.7
MAX_REFERENCES = 8      # Stored per CVE; some have hundreds
MAX_AFFECTED = 10
MAX_CWES = 4

# CVE -> (probability of exploitation in 30 days, percentile), refreshed daily
EPSS: Dict[str, Tuple[float, float]] = {}
_epss_day: Optional[str] = None


async def fetch_epss(cves: Iterable[str]):
    """Fetch EPSS scores for CVEs not yet scored today"""
    global _epss_day
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    if _epss_day != today:
        EPSS.clear()
        _epss_day = today
    missing = sorted({c for c in cves if c not in EPSS})
    if not missing:
        return
    async with httpx.AsyncClient(timeout=20) as client:
        for i in range(0, min(len(missing), EPSS_BATCH * EPSS_MAX_BATCHES), EPSS_BATCH):
            batch = missing[i:i + EPSS_BATCH]
            try:
                r = await client.get(EPSS_URL, params={"cve": ",".join(batch)})
                r.raise_for_status()
                for row in r.json().get("data") or []:
                    EPSS[row["cve"]] = (float(row["epss"]), float(row["percentile"]))
            except Exception as e:
                logging.warning(f"EPSS lookup failed: {e}")
                return


def parse_nvd(cve: dict) -> dict:
    """The fields CybrWire keeps from one NVD 2.0 'cve' record ({} = NVD has no record)"""
    score = severity = vector = None
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            # NVD's own assessment when there is one, otherwise the reporting CNA's
            m = next((x for x in metrics[key] if x.get("type") == "Primary"), metrics[key][0])
            score = m["cvssData"].get("baseScore")
            severity = m["cvssData"].get("baseSeverity") or m.get("baseSeverity")
            vector = m["cvssData"].get("vectorString")
            break

    description = next((d.get("value") for d in cve.get("descriptions") or [] if d.get("lang") == "en"), None)

    cwes = []
    for weakness in cve.get("weaknesses") or []:
        for d in weakness.get("description") or []:
            value = d.get("value") or ""
            if value.startswith("CWE-") and value not in cwes:
                cwes.append(value)

    affected = []
    for config in cve.get("configurations") or []:
        for node in config.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                parts = (match.get("criteria") or "").split(":")  # cpe:2.3:a:vendor:product:...
                if match.get("vulnerable") and len(parts) > 4:
                    name = f"{parts[3]} {parts[4]}".replace("_", " ")
                    if name not in affected:
                        affected.append(name)

    references = [{"url": r["url"], "tags": r.get("tags") or []} for r in cve.get("references") or [] if r.get("url")]
    references.sort(key=lambda r: "Exploit" not in r["tags"])  # Stable: exploits first, order otherwise kept

    return {
        "score": score, "severity": severity, "vector": vector,
        "description": description, "cwes": cwes[:MAX_CWES],
        "affected": affected[:MAX_AFFECTED], "affected_total": len(affected),
        "references": references[:MAX_REFERENCES], "references_total": len(references),
        "exploit_refs": sum("Exploit" in r["tags"] for r in references),
        "published": cve.get("published"), "status": cve.get("vulnStatus"),
    }


class NvdClient:
    """Rate-limited CVSS lookups, cached in a dict the caller persists"""

    def __init__(self, cache: Dict[str, dict], api_key: Optional[str] = None):
        self.cache = cache
        self.api_key = api_key
        self.pending = set()
        self.failed = set()  # Last lookup failed (network, rate limit); the CVE card says so
        self._lock = asyncio.Lock()
        self._last = 0.0

    def get(self, cve: str) -> Optional[dict]:
        return self.cache.get(cve)

    async def fetch(self, cve: str, detail: bool = False) -> Optional[dict]:
        """Look up one CVE; returns the cached entry. detail=True also replaces
        entries cached before descriptions and references were stored."""
        if detail:
            while cve in self.pending:  # Started by the alert preview; the card waits for the answer
                await asyncio.sleep(0.2)
        cached = self.cache.get(cve)
        if cve in self.pending or (cached and (not detail or "description" in cached)):
            return cached
        self.pending.add(cve)
        self.failed.discard(cve)
        try:
            async with self._lock:
                wait = (NVD_INTERVAL_KEYED if self.api_key else NVD_INTERVAL) - (time.monotonic() - self._last)
                if wait > 0:
                    await asyncio.sleep(wait)
                self._last = time.monotonic()
                headers = {"apiKey": self.api_key} if self.api_key else {}
                async with httpx.AsyncClient(timeout=20) as client:
                    r = await client.get(NVD_URL, params={"cveId": cve}, headers=headers)
                r.raise_for_status()
                vulns = r.json().get("vulnerabilities") or []
            record = vulns[0]["cve"] if vulns else {}
            # Unscored CVEs are cached too, but re-checked after a day
            self.cache[cve] = {**parse_nvd(record), "checked": datetime.now(timezone.utc).isoformat()}
            return self.cache[cve]
        except Exception as e:
            logging.warning(f"NVD lookup for {cve} failed: {e}")
            self.failed.add(cve)
            return cached
        finally:
            self.pending.discard(cve)

    def prune_unscored(self, max_age_hours: int = 24):
        """Forget 'not yet scored' answers older than a day so they get re-checked"""
        now = datetime.now(timezone.utc)
        for cve, entry in list(self.cache.items()):
            if entry.get("score") is None and (now - datetime.fromisoformat(entry["checked"])).total_seconds() > max_age_hours * 3600:
                del self.cache[cve]
