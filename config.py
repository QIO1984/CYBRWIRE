"""
Configuration loading for CybrWire

All YAML files are read once here. Precedence for keys and AI settings:
cybrwire_local.yaml (private, gitignored) > usrwire.yaml.
"""

import logging
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List

import yaml

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
}

FALLBACK_SOURCES = [
    {"name": "CISA KEV", "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "type": "json"},
    {"name": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/", "type": "rss"},
    {"name": "TheHackerNews", "url": "https://feeds.feedburner.com/TheHackersNews", "type": "rss"},
    {"name": "Krebs on Security", "url": "https://krebsonsecurity.com/feed/", "type": "rss"},
    {"name": "SANS ISC Diary", "url": "https://isc.sans.edu/rssfeed.xml", "type": "rss"},
    {"name": "Cisco Talos", "url": "https://blog.talosintelligence.com/feed/", "type": "rss"},
]


@dataclass
class Config:
    sources: List[Dict[str, Any]] = field(default_factory=list)
    enrichment: Dict[str, Dict[str, str]] = field(default_factory=dict)  # provider -> {"api_key": ...}
    ai: Dict[str, Any] = field(default_factory=dict)

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
    files = {name: _read_yaml(name) for name, _ in FEED_FILES}
    config = Config()

    for name, category in FEED_FILES:
        for key, value in files[name].items():
            if key in ("enrichment", "ai") or not isinstance(value, list):
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

    return config
