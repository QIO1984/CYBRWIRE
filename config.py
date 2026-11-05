"""
Configuration loading for CybrWire

All YAML files are read once here. Precedence for AI settings:
cybrwire_local.yaml (private, gitignored) > usrwire.yaml.
Keys come from keystore.py, which still honors any left in those files.
"""

import logging
import os
import re
import stat
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import yaml

from keystore import SLOTS_BY_ID, KeyStore

APP_DIR = os.path.dirname(os.path.abspath(__file__))

# Feed files and the category their sources fall under when the YAML key is missing
FEED_FILES = [
    ("cybrwire.yaml", "curated"),
    ("usrwire.yaml", "custom"),
    ("comwire.yaml", "community"),
    ("cybrwire_local.yaml", "custom"),
]

# enrichment YAML key -> (engine provider name, display name)
ENRICHMENT_KEYS = {
    "abuseipdb_api_key": ("abuseipdb", "ABUSEIPDB"),
    "virustotal_api_key": ("virustotal", "VIRUSTOTAL"),
    "pulsedive_api_key": ("pulsedive", "PULSEDIVE"),
    "abuse_ch_api_key": ("abusech", "ABUSE.CH"),
    "nvd_api_key": ("nvd", "NVD"),  # optional: raises NVD's CVSS lookup rate limit
}

# Keys that register an enrichment provider; the NVD key goes to the CVSS client instead
ENRICHMENT_SLOTS = {k: v for k, v in ENRICHMENT_KEYS.items() if k != "nvd_api_key"}

FALLBACK_SOURCES = [
    {"name": "CISA KEV", "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "type": "json"},
    {"name": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/", "type": "rss"},
    {"name": "TheHackerNews", "url": "https://feeds.feedburner.com/TheHackersNews", "type": "rss"},
    {"name": "Krebs on Security", "url": "https://krebsonsecurity.com/feed/", "type": "rss"},
    {"name": "SANS ISC Diary", "url": "https://isc.sans.edu/rssfeed.xml", "type": "rss"},
    {"name": "Cisco Talos", "url": "https://blog.talosintelligence.com/feed/", "type": "rss"},
]


# Everything secret that was loaded, so it can be masked out of logs and error text
SECRETS: set = set()
SECRET_PARAM_RE = re.compile(r"([?&](?:key|api_?key|token|auth)=)[^&\s'\"]+", re.IGNORECASE)
MIN_SECRET_LEN = 6  # Shorter values would mask ordinary words


def redact(text: str) -> str:
    """Mask loaded secrets and any secret-looking URL parameter"""
    for secret in SECRETS:
        text = text.replace(secret, "***")
    return SECRET_PARAM_RE.sub(r"\1***", text)


class RedactingFormatter(logging.Formatter):
    """Applies to the whole log line, including tracebacks"""

    def format(self, record: logging.LogRecord) -> str:
        return redact(super().format(record))


def secure_file(path: str) -> None:
    """Make a file readable only by its owner, if it exists and isn't already"""
    try:
        if stat.S_IMODE(os.stat(path).st_mode) & 0o077:
            os.chmod(path, 0o600)
    except OSError as e:
        logging.warning(f"Could not restrict permissions on {path}: {e}")


def _remember_secrets(config: "Config") -> None:
    values = [entry.get("api_key") for entry in config.enrichment.values()]
    values.append(config.ai.get("api_key"))
    values += [config.notifications.get(k) for k in ("ntfy_url", "ntfy_token", "discord_webhook", "slack_webhook")]
    for src in config.sources:
        values += list((src.get("headers") or {}).values())
    SECRETS.update(str(v) for v in values if v and len(str(v)) >= MIN_SECRET_LEN)


@dataclass
class Config:
    sources: List[Dict[str, Any]] = field(default_factory=list)
    enrichment: Dict[str, Dict[str, str]] = field(default_factory=dict)  # provider -> {"api_key": ...}
    ai: Dict[str, Any] = field(default_factory=dict)
    watchlist: List[str] = field(default_factory=list)
    notifications: Dict[str, Any] = field(default_factory=dict)
    keys: Optional[KeyStore] = None
    key_sources: Dict[str, str] = field(default_factory=dict)  # slot id -> where its value came from

    def key_value(self, slot_id: str) -> Optional[str]:
        """The value the app is using for a key slot"""
        slot = SLOTS_BY_ID[slot_id]
        if slot.section == "ai":
            return self.ai.get(slot.yaml_key)
        if slot.section == "notifications":
            return self.notifications.get(slot.yaml_key)
        provider = ENRICHMENT_KEYS[slot.yaml_key][0]
        return (self.enrichment.get(provider) or {}).get("api_key")

    def set_key_value(self, slot_id: str, value: Optional[str], source: Optional[str] = None) -> None:
        """Put a key where the rest of the app reads it; None clears it"""
        slot = SLOTS_BY_ID[slot_id]
        if slot.section == "enrichment":
            provider = ENRICHMENT_KEYS[slot.yaml_key][0]
            if value:
                self.enrichment[provider] = {"api_key": value}
            else:
                self.enrichment.pop(provider, None)
        else:
            block = self.ai if slot.section == "ai" else self.notifications
            if value:
                block[slot.yaml_key] = value
            else:
                block.pop(slot.yaml_key, None)
        if value and source:
            self.key_sources[slot_id] = source
            if len(value) >= MIN_SECRET_LEN:
                SECRETS.add(value)
        else:
            self.key_sources.pop(slot_id, None)

    @property
    def configured_api_names(self) -> List[str]:
        """Display names of every configured API, for the loading screen"""
        names = []
        if self.ai.get("provider"):
            names.append(self.ai["provider"].upper())
        names += [display for provider, display in ENRICHMENT_KEYS.values() if provider in self.enrichment]
        return names


def _read_yaml(filename: str) -> Dict[str, Any]:
    path = os.path.join(APP_DIR, filename)
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r") as f:
            return yaml.safe_load(f) or {}
    except Exception as e:
        logging.error(f"Failed to load {path}: {e}")
        return {}


def load_config() -> Config:
    secure_file(os.path.join(APP_DIR, "cybrwire_local.yaml"))
    files = {name: _read_yaml(name) for name, _ in FEED_FILES}
    config = Config()

    for name, category in FEED_FILES:
        for key, value in files[name].items():
            if key in ("enrichment", "ai", "watchlist", "notifications") or not isinstance(value, list):
                continue
            for src in value:
                if isinstance(src, dict) and src.get("name") and src.get("url"):
                    config.sources.append({**src, "source_file": key if key in ("curated", "custom", "community") else category})

    if not config.sources:
        logging.warning("No YAML sources loaded, using fallback sources")
        config.sources = [{**s, "source_file": "curated"} for s in FALLBACK_SOURCES]

    # Lowest precedence first so local values win
    enrichment: Dict[str, Any] = {}
    ai: Dict[str, Any] = {}
    for name in ("usrwire.yaml", "cybrwire_local.yaml"):
        enrichment.update({k: v for k, v in (files[name].get("enrichment") or {}).items() if v})
        ai.update({k: v for k, v in (files[name].get("ai") or {}).items() if v})

    for yaml_key, (provider, _) in ENRICHMENT_KEYS.items():
        if enrichment.get(yaml_key):
            config.enrichment[provider] = {"api_key": enrichment[yaml_key]}

    config.ai = ai

    # Terms from both files apply; a single value instead of a list is taken as one term
    for name in ("usrwire.yaml", "cybrwire_local.yaml"):
        terms = files[name].get("watchlist") or []
        config.watchlist += terms if isinstance(terms, list) else [terms]

    # Same precedence as keys: local values win. False and [] are real settings here.
    for name in ("usrwire.yaml", "cybrwire_local.yaml"):
        config.notifications.update(files[name].get("notifications") or {})

    # Keys found in the YAML above are replaced by whatever outranks them in the key store
    config.keys = KeyStore(APP_DIR)
    for slot_id, (value, source) in config.keys.resolve_all(config.keys.read_yaml_values()).items():
        config.set_key_value(slot_id, value, source)

    _remember_secrets(config)
    return config
