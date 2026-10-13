"""
Threat enrichment engine for CybrWire
Integrates with external threat intelligence APIs to enrich alerts with reputation, IOC data, etc.
"""

import asyncio
import base64
import logging
import httpx
import re
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)

class ThreatLevel(Enum):
    """Threat severity levels"""
    CLEAN = "clean"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

def detect_indicator_type(indicator: str) -> str:
    """
    Auto-detect indicator type (IP, hash, domain, URL)
    
    Args:
        indicator: The IOC string to analyze
    
    Returns:
        Type string: "ip", "hash", "domain", or "url"
    """
    
    indicator = indicator.strip()
    
    # Check for URL (contains ://)
    if "://" in indicator or indicator.startswith("http") or indicator.startswith("ftp"):
        return "url"
    
    # Check for hash (hex string of specific lengths)
    if re.match(r"^[a-fA-F0-9]{32}$", indicator):
        return "hash"  # MD5
    elif re.match(r"^[a-fA-F0-9]{40}$", indicator):
        return "hash"  # SHA-1
    elif re.match(r"^[a-fA-F0-9]{64}$", indicator):
        return "hash"  # SHA-256
    elif re.match(r"^[a-fA-F0-9]{128}$", indicator):
        return "hash"  # SHA-512
    
    # Check for IPv4 address
    if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", indicator):
        # Validate IP octets
        octets = indicator.split(".")
        if all(0 <= int(octet) <= 255 for octet in octets):
            return "ip"
    
    # Check for IPv6 address
    if ":" in indicator:
        try:
            # Simple IPv6 check - if it has colons and hex chars, likely IPv6
            if re.match(r"^[a-fA-F0-9:]+$", indicator):
                return "ip"
        except:
            pass
    
    # Default to domain if it looks like a domain (has dots, no spaces)
    if "." in indicator and " " not in indicator and "@" not in indicator:
        return "domain"
    
    # Default to domain as fallback
    return "domain"

@dataclass
class EnrichmentData:
    """Structured enrichment result"""
    indicator: str
    indicator_type: str  # "ip", "hash", "domain", "url"
    provider: str
    threat_level: ThreatLevel
    reputation_score: Optional[float]  # 0-100
    is_malicious: bool
    details: Dict[str, Any]
    timestamp: datetime
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization"""
        return {
            "indicator": self.indicator,
            "type": self.indicator_type,
            "provider": self.provider,
            "threat_level": self.threat_level.value,
            "score": self.reputation_score,
            "malicious": self.is_malicious,
            "details": self.details,
            "timestamp": self.timestamp.isoformat()
        }

class EnrichmentProvider:
    """Base class for threat enrichment providers"""
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.timeout = httpx.Timeout(10.0)
    
    async def enrich(self, indicator: str, indicator_type: str) -> Optional[EnrichmentData]:
        """Query API and return enrichment data"""
        raise NotImplementedError
    
    def _determine_threat_level(self, score: float) -> ThreatLevel:
        """Convert numeric score to threat level - tightened thresholds"""
        if score >= 70:
            return ThreatLevel.CRITICAL
        elif score >= 40:
            return ThreatLevel.HIGH
        elif score >= 20:
            return ThreatLevel.MEDIUM
        elif score >= 5:
            return ThreatLevel.LOW
        return ThreatLevel.CLEAN

class AbuseIPDBProvider(EnrichmentProvider):
    """AbuseIPDB IP reputation provider"""
    
    BASE_URL = "https://api.abuseipdb.com/api/v2"
    
    async def enrich(self, indicator: str, indicator_type: str = "ip") -> Optional[EnrichmentData]:
        """
        Check IP reputation via AbuseIPDB
        
        Args:
            indicator: IP address to check
            indicator_type: "ip" (AbuseIPDB only does IPs)
        
        Returns:
            EnrichmentData with reputation info or None if error
        """
        
        if indicator_type != "ip":
            logger.debug(f"AbuseIPDB only handles IP indicators, skipping {indicator_type}")
            return None
        
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                headers = {
                    "Key": self.api_key,
                    "Accept": "application/json"
                }
                
                params = {
                    "ipAddress": indicator,
                    "maxAgeInDays": 90,
                    "verbose": ""
                }
                
                response = await client.get(
                    f"{self.BASE_URL}/check",
                    headers=headers,
                    params=params
                )
                response.raise_for_status()
                
                data = response.json()
                abuse_data = data.get("data", {})
                
                # Extract key fields
                abuse_score = abuse_data.get("abuseConfidenceScore", 0)
                report_count = abuse_data.get("totalReports", 0)
                threat_types = abuse_data.get("usageType", "")
                last_reported = abuse_data.get("lastReportedAt", "Never")
                
                # Determine if malicious: consider both abuse_score AND report_count
                # High report count = suspicious even if confidence is low (may be false reports)
                is_malicious = abuse_score >= 25 or report_count >= 10
                
                # Calculate composite threat score from both metrics
                # abuse_score is primary (0-100), report_count is secondary indicator
                # Normalize report count: 10+ reports = 25%, 50+ = 50%, 100+ = 75%, 500+ = 100%
                report_threat = min(100, (report_count / 5)) if report_count > 0 else 0
                
                # Weighted composite: 70% abuse_score, 30% report-based threat
                composite_threat_score = (abuse_score * 0.7) + (report_threat * 0.3)
                
                # Build details dictionary with all available data
                # Extract report categories for better context
                report_categories = abuse_data.get("reports", [])
                most_recent_category = None
                if report_categories:
                    # Get most recent report's category
                    most_recent_category = report_categories[0].get("category", "Unknown") if isinstance(report_categories, list) else "Unknown"
                
                details = {
                    "abuse_score": abuse_score,
                    "report_count": report_count,
                    "threat_type": threat_types,
                    "last_reported": last_reported,
                    "isp": abuse_data.get("isp", "Unknown"),
                    "usage_type": abuse_data.get("usageType", "Unknown"),
                    "domain": abuse_data.get("domain", "Unknown"),
                    "country": abuse_data.get("countryCode", "Unknown"),
                    "is_whitelisted": abuse_data.get("isWhitelisted", False),
                    "is_private": abuse_data.get("isPrivate", False),
                    "total_reports": report_count,
                    "first_reported": abuse_data.get("firstReportedAt", "Unknown"),
                    "most_recent_category": most_recent_category,
                }
                
                threat_level = self._determine_threat_level(composite_threat_score)
                
                return EnrichmentData(
                    indicator=indicator,
                    indicator_type="ip",
                    provider="AbuseIPDB",
                    threat_level=threat_level,
                    reputation_score=abuse_score,
                    is_malicious=is_malicious,
                    details=details,
                    timestamp=datetime.now()
                )
                
        except httpx.HTTPError as e:
            logger.error(f"AbuseIPDB API error for {indicator}: {e}")
            return None
        except Exception as e:
            logger.error(f"Error enriching {indicator} via AbuseIPDB: {e}")
            return None

class VirusTotalProvider(EnrichmentProvider):
    """
    VirusTotal multi-indicator provider
    
    Free (public) API: IPs, hashes, domains and URLs; 4 lookups/min, 500/day quota.
    A 404 means VirusTotal has no record of the indicator.
    """
    
    BASE_URL = "https://www.virustotal.com/api/v3"
    
    async def enrich(self, indicator: str, indicator_type: str = "ip") -> Optional[EnrichmentData]:
        """
        Check indicator via VirusTotal
        
        Args:
            indicator: IOC to check (IP, hash, domain, URL)
            indicator_type: "ip", "hash", "domain", "url"
        
        Returns:
            EnrichmentData with VT detection info or None if error
        """
        
        logger.info(f"VirusTotal query started: indicator={indicator}, type={indicator_type}")
        
        # Map indicator type to VT endpoint. URLs are looked up by their
        # unpadded base64url identifier, not the raw URL.
        url_id = base64.urlsafe_b64encode(indicator.encode()).decode().rstrip("=")
        endpoint_map = {
            "ip": f"ip_addresses/{indicator}",
            "hash": f"files/{indicator}",
            "domain": f"domains/{indicator}",
            "url": f"urls/{url_id}",
        }
        
        endpoint = endpoint_map.get(indicator_type)
        if not endpoint:
            logger.debug(f"VirusTotal unsupported type: {indicator_type}")
            return None
        
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                headers = {
                    "x-apikey": self.api_key,
                    "Accept": "application/json"
                }
                
                url = f"{self.BASE_URL}/{endpoint}"
                logger.info(f"VirusTotal request: GET {url}")
                logger.debug(f"VirusTotal headers: x-apikey={'*'*(len(self.api_key)-4) + self.api_key[-4:]}")
                
                response = await client.get(url, headers=headers)
                
                logger.info(f"VirusTotal response status: {response.status_code}")
                
                # Handle 404 - indicator not in VirusTotal database
                if response.status_code == 404:
                    logger.info(f"VirusTotal: {indicator_type} '{indicator}' not found in database (treating as CLEAN)")
                    status_note = "Indicator not in VirusTotal database"
                    return EnrichmentData(
                        indicator=indicator,
                        indicator_type=indicator_type,
                        provider="VirusTotal",
                        threat_level=ThreatLevel.CLEAN,
                        reputation_score=0,
                        is_malicious=False,
                        details={"status": "not_found", "note": status_note},
                        timestamp=datetime.now()
                    )
                
                # Handle 401 - authentication failure
                if response.status_code == 401:
                    logger.error(f"VirusTotal 401 Unauthorized - API key invalid or expired")
                    logger.debug(f"VirusTotal 401 response: {response.text}")
                    return EnrichmentData(
                        indicator=indicator,
                        indicator_type=indicator_type,
                        provider="VirusTotal",
                        threat_level=ThreatLevel.CLEAN,
                        reputation_score=0,
                        is_malicious=False,
                        details={"status": "auth_failed", "note": "VirusTotal API key invalid or expired"},
                        timestamp=datetime.now()
                    )
                
                response.raise_for_status()
                
                data = response.json()
                attributes = data.get("data", {}).get("attributes", {})
                
                # Get detection stats
                stats = attributes.get("last_analysis_stats", {})
                malicious_count = stats.get("malicious", 0)
                suspicious_count = stats.get("suspicious", 0)
                total_vendors = sum(stats.values())
                
                # Calculate threat score - heavily weight malicious detections
                # Each malicious = 100 points, each suspicious = 50 points, normalized by vendor count
                reputation_score = ((malicious_count * 100 + suspicious_count * 50) / (max(total_vendors, 1) * 100)) * 100 if total_vendors > 0 else 0
                is_malicious = malicious_count > 0
                
                # Build details with ALL available data from VirusTotal
                # Extract last analysis results for deeper threat intel
                last_analysis_results = attributes.get("last_analysis_results", {})
                
                # Count vendors with specific detections
                undetected_count = stats.get("undetected", 0)
                timeout_count = stats.get("timeout", 0)
                
                details = {
                    "malicious_vendors": malicious_count,
                    "suspicious_vendors": suspicious_count,
                    "undetected_vendors": undetected_count,
                    "timeout_vendors": timeout_count,
                    "total_vendors": total_vendors,
                    "last_analysis_date": attributes.get("last_analysis_date", "Unknown"),
                    "reputation": attributes.get("reputation", 0),
                    "analysis_stats": stats,
                    "type_description": attributes.get("type_description", "Unknown"),
                    "meaningful_name": attributes.get("meaningful_name", "Unknown"),
                    "sandbox_verdicts": attributes.get("sandbox_verdicts", {}),
                    "triage_verdicts": attributes.get("triage_verdicts", {}),
                }
                
                if indicator_type == "ip":
                    details.update({
                        "country": attributes.get("country", "Unknown"),
                        "asn": attributes.get("asn", "Unknown"),
                        "network": attributes.get("network", "Unknown"),
                        "whois": attributes.get("whois", "Unknown"),
                    })
                elif indicator_type == "hash":
                    details.update({
                        "file_size": attributes.get("size", "Unknown"),
                        "file_type": attributes.get("type_description", "Unknown"),
                        "magic": attributes.get("magic", "Unknown"),
                        "names": attributes.get("names", [])[:5],  # Top 5 file names
                    })
                elif indicator_type == "domain":
                    details.update({
                        "tld": attributes.get("tld", "Unknown"),
                        "categories": attributes.get("categories", {}),
                        "registrar": attributes.get("registrar", "Unknown"),
                    })
                
                threat_level = self._determine_threat_level(reputation_score)
                
                return EnrichmentData(
                    indicator=indicator,
                    indicator_type=indicator_type,
                    provider="VirusTotal",
                    threat_level=threat_level,
                    reputation_score=reputation_score,
                    is_malicious=is_malicious,
                    details=details,
                    timestamp=datetime.now()
                )
                
        except httpx.HTTPError as e:
            logger.error(f"VirusTotal API error for {indicator}: {e}")
            logger.debug(f"  Endpoint used: {self.BASE_URL}/{endpoint}")
            logger.debug(f"  Indicator type: {indicator_type}")
            logger.debug(f"  Status code: {e.response.status_code if hasattr(e, 'response') else 'unknown'}")
            return None
        except Exception as e:
            logger.error(f"Error enriching {indicator} via VirusTotal: {e}")
            logger.debug(f"  Endpoint used: {self.BASE_URL}/{endpoint}")
            return None

class PulsediveProvider(EnrichmentProvider):
    """Pulsedive threat intelligence provider"""
    
    BASE_URL = "https://pulsedive.com/api/info.php"
    
    # Pulsedive reports risk as a label rather than a number
    RISK_SCORES = {"none": 0, "unknown": 0, "low": 10, "medium": 30, "high": 60, "critical": 90}
    
    async def enrich(self, indicator: str, indicator_type: str = "ip") -> Optional[EnrichmentData]:
        """
        Check indicator via Pulsedive
        
        Args:
            indicator: IOC to check
            indicator_type: "ip", "hash", "domain", "url"
        
        Returns:
            EnrichmentData with Pulsedive threat score or None if error
        """
        
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(
                    self.BASE_URL,
                    params={"indicator": indicator, "key": self.api_key}
                )
                
                if response.status_code == 404:
                    return EnrichmentData(
                        indicator=indicator,
                        indicator_type=indicator_type,
                        provider="Pulsedive",
                        threat_level=ThreatLevel.CLEAN,
                        reputation_score=0,
                        is_malicious=False,
                        details={"status": "not_found"},
                        timestamp=datetime.now()
                    )
                response.raise_for_status()
                
                result = response.json()
                risk = str(result.get("risk", "unknown")).lower()
                threat_score = self.RISK_SCORES.get(risk, 0)
                
                threats = [t.get("name", "?") for t in result.get("threats") or []]
                feeds = [f.get("name", "?") for f in result.get("feeds") or []]
                geo = (result.get("properties") or {}).get("geo") or {}
                countries = geo.get("country") or []
                
                details = {
                    "risk": risk,
                    "threat": threats,
                    "threat_feed_count": len(feeds),
                    "feeds": feeds[:10],
                    "risk_factors": [r.get("description", "") for r in result.get("riskfactors") or []],
                    "country": countries[0] if isinstance(countries, list) and countries else countries or "Unknown",
                    "asn": geo.get("asn", "Unknown"),
                    "last_seen": result.get("stamp_seen", "Unknown"),
                }
                
                return EnrichmentData(
                    indicator=indicator,
                    indicator_type=indicator_type,
                    provider="Pulsedive",
                    threat_level=self._determine_threat_level(threat_score),
                    reputation_score=threat_score,
                    is_malicious=threat_score >= 60,  # high or critical
                    details=details,
                    timestamp=datetime.now()
                )
                
        except httpx.HTTPError as e:
            logger.error(f"Pulsedive API error for {indicator}: {e}")
            return None
        except Exception as e:
            logger.error(f"Error enriching {indicator} via Pulsedive: {e}")
            return None

class AbusechProvider(EnrichmentProvider):
    """Abuse.ch threat database provider (MalwareBazaar for hashes, URLhaus for URLs/hosts)"""
    
    MALWARE_BAZAAR_URL = "https://mb-api.abuse.ch/api/v1/"
    URLHAUS_URL_LOOKUP = "https://urlhaus-api.abuse.ch/v1/url/"
    URLHAUS_HOST_LOOKUP = "https://urlhaus-api.abuse.ch/v1/host/"
    
    async def enrich(self, indicator: str, indicator_type: str = "ip") -> Optional[EnrichmentData]:
        """
        Check indicator via Abuse.ch services
        
        Args:
            indicator: IOC to check
            indicator_type: "ip", "hash", "domain", "url"
        
        Returns:
            EnrichmentData with Abuse.ch threat intel or None if error
        """
        
        if indicator_type == "hash":
            endpoint, data = self.MALWARE_BAZAAR_URL, {"query": "get_info", "hash": indicator}
        elif indicator_type == "url":
            endpoint, data = self.URLHAUS_URL_LOOKUP, {"url": indicator}
        elif indicator_type in ("ip", "domain"):
            endpoint, data = self.URLHAUS_HOST_LOOKUP, {"host": indicator}
        else:
            return None
        
        try:
            # Both APIs require a (free) Auth-Key and only accept POST
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(endpoint, data=data, headers={"Auth-Key": self.api_key})
                response.raise_for_status()
                result = response.json()
            
            status = result.get("query_status", "unknown")
            is_malicious = False
            threat_score = 0
            details = {"status": status}
            
            if status == "ok" and indicator_type == "hash":
                sample = (result.get("data") or [{}])[0]
                is_malicious = True
                threat_score = 90
                details = {
                    "malware_family": sample.get("signature") or "Unknown",
                    "file_type": sample.get("file_type", "Unknown"),
                    "file_name": sample.get("file_name", "Unknown"),
                    "tags": sample.get("tags") or [],
                    "first_seen": sample.get("first_seen", "Unknown"),
                    "last_seen": sample.get("last_seen", "Unknown"),
                    "reporter": sample.get("reporter", "Unknown"),
                }
            elif status == "ok" and indicator_type == "url":
                is_malicious = True
                threat_score = 90 if result.get("url_status") == "online" else 75
                details = {
                    "threat": result.get("threat", "Unknown"),
                    "url_status": result.get("url_status", "Unknown"),
                    "tags": result.get("tags") or [],
                    "date_added": result.get("date_added", "Unknown"),
                    "host": result.get("host", "Unknown"),
                    "urlhaus_link": result.get("urlhaus_reference", "Unknown"),
                }
            elif status == "ok":  # ip / domain host lookup
                urls = result.get("urls") or []
                online = sum(1 for u in urls if u.get("url_status") == "online")
                is_malicious = bool(urls)
                threat_score = 90 if online else 70 if urls else 0
                details = {
                    "malware_urls": result.get("url_count", len(urls)),
                    "online_urls": online,
                    "first_seen": result.get("firstseen", "Unknown"),
                    "threat": sorted({u.get("threat", "") for u in urls if u.get("threat")}),
                    "urlhaus_link": result.get("urlhaus_reference", "Unknown"),
                }
            
            return EnrichmentData(
                indicator=indicator,
                indicator_type=indicator_type,
                provider="Abuse.ch",
                threat_level=self._determine_threat_level(threat_score),
                reputation_score=threat_score,
                is_malicious=is_malicious,
                details=details,
                timestamp=datetime.now()
            )
                
        except (httpx.ConnectError, OSError) as e:
            logger.warning(f"Abuse.ch network error (DNS/connectivity) for {indicator}: {e}")
            return None
        except httpx.HTTPError as e:
            logger.error(f"Abuse.ch API error for {indicator}: {e}")
            return None
        except Exception as e:
            logger.error(f"Error enriching {indicator} via Abuse.ch: {e}")
            return None

class EnrichmentEngine:
    """Central enrichment engine managing multiple providers"""
    
    def __init__(self):
        self.providers: Dict[str, EnrichmentProvider] = {}
        self.cache: Dict[str, Dict[str, EnrichmentData]] = {}
        self.cache_times: Dict[str, datetime] = {}
        self.cache_ttl = timedelta(hours=24)
        
    def register_provider(self, name: str, provider: EnrichmentProvider):
        """Register an enrichment provider"""
        self.providers[name] = provider
        logger.info(f"Registered enrichment provider: {name}")
    
    def _is_cached(self, indicator: str) -> bool:
        """Check if indicator has fresh cached data"""
        if indicator not in self.cache:
            return False
        
        return datetime.now() - self.cache_times[indicator] < self.cache_ttl
    
    async def enrich(self, indicator: str, indicator_type: str = None) -> Dict[str, EnrichmentData]:
        """
        Enrich an indicator using all registered providers
        
        Args:
            indicator: The IOC to enrich (IP, hash, domain, etc)
            indicator_type: Type of indicator - if None, auto-detect
        
        Returns:
            Dict of provider_name -> EnrichmentData
        """
        
        # Auto-detect indicator type if not provided
        if indicator_type is None:
            indicator_type = detect_indicator_type(indicator)
            logger.info(f"Auto-detected indicator type: {indicator} -> {indicator_type}")
        
        # Check cache first
        if self._is_cached(indicator):
            logger.debug(f"Using cached enrichment for {indicator}")
            return self.cache[indicator]
        
        results = {}
        
        # Query all providers in parallel
        tasks = []
        for name, provider in self.providers.items():
            tasks.append(self._enrich_with_provider(name, provider, indicator, indicator_type))
        
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        for response in responses:
            if isinstance(response, tuple):
                provider_name, enrichment = response
                if enrichment:
                    results[provider_name] = enrichment
        
        if results:
            self.cache[indicator] = results
            self.cache_times[indicator] = datetime.now()
        return results
    
    async def _enrich_with_provider(self, name: str, provider: EnrichmentProvider, 
                                   indicator: str, indicator_type: str):
        """Enrich with single provider"""
        try:
            result = await provider.enrich(indicator, indicator_type)
            return (name, result)
        except Exception as e:
            logger.error(f"Provider {name} failed for {indicator}: {e}")
            return (name, None)
    
    def batch_enrich(self, indicators: List[Dict[str, str]]) -> Dict[str, Dict[str, EnrichmentData]]:
        """
        Synchronously enrich multiple indicators
        
        Args:
            indicators: List of {"value": "X.X.X.X", "type": "ip"} dicts
        
        Returns:
            Dict of indicator -> {provider -> EnrichmentData}
        """
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        
        results = {}
        for ind_dict in indicators:
            result = loop.run_until_complete(
                self.enrich(ind_dict["value"], ind_dict.get("type", "ip"))
            )
            results[ind_dict["value"]] = result
        
        return results

# Global enrichment engine instance
enrichment_engine = EnrichmentEngine()

def initialize_enrichment(config: Dict[str, Any]):
    """
    Initialize enrichment engine with providers from config
    
    Args:
        config: Dict with API keys, e.g. {"abuseipdb": {"api_key": "..."}}
    """
    
    # Initialize AbuseIPDB if configured
    if "abuseipdb" in config and config["abuseipdb"].get("api_key"):
        try:
            provider = AbuseIPDBProvider(config["abuseipdb"]["api_key"])
            enrichment_engine.register_provider("abuseipdb", provider)
        except Exception as e:
            logger.error(f"Failed to initialize AbuseIPDB: {e}")
    
    # Initialize VirusTotal if configured
    if "virustotal" in config and config["virustotal"].get("api_key"):
        try:
            provider = VirusTotalProvider(config["virustotal"]["api_key"])
            enrichment_engine.register_provider("virustotal", provider)
        except Exception as e:
            logger.error(f"Failed to initialize VirusTotal: {e}")
    
    # Initialize Pulsedive if configured
    if "pulsedive" in config and config["pulsedive"].get("api_key"):
        try:
            provider = PulsediveProvider(config["pulsedive"]["api_key"])
            enrichment_engine.register_provider("pulsedive", provider)
        except Exception as e:
            logger.error(f"Failed to initialize Pulsedive: {e}")
    
    # Initialize Abuse.ch if configured
    if "abusech" in config and config["abusech"].get("api_key"):
        try:
            provider = AbusechProvider(config["abusech"]["api_key"])
            enrichment_engine.register_provider("abusech", provider)
        except Exception as e:
            logger.error(f"Failed to initialize Abuse.ch: {e}")
    
    logger.info(f"Enrichment engine initialized with {len(enrichment_engine.providers)} provider(s)")

