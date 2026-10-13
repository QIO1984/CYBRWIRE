"""
Persistent local state for CybrWire: UI settings, seen alerts, cached lookups

Stored as JSON in cybrwire_state.json next to the app (gitignored).
"""

import json
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from config import APP_DIR

STATE_PATH = os.path.join(APP_DIR, "cybrwire_state.json")
SEEN_RETENTION = timedelta(days=30)


def alert_key(alert: Dict[str, Any]) -> str:
    """Stable identity for an alert across refreshes and restarts"""
    return alert.get("url") or f"{alert.get('source', '')}|{alert.get('title', '')}"


class AppState:
    def __init__(self):
        self.settings: Dict[str, Any] = {}
        self.first_seen: Dict[str, str] = {}   # alert key -> ISO timestamp
        self.read: Dict[str, str] = {}         # alert key -> ISO timestamp opened
        self.doomsday: Dict[str, Any] = {}
        self.briefing: Dict[str, Any] = {}     # last AI briefing: {"text", "time"}
        self.cvss: Dict[str, Any] = {}         # CVE -> {"score", "severity", "checked"} from NVD
        self.previous_launch: Optional[datetime] = None
        self._load()
        self.launch_time = datetime.now(timezone.utc)

    def _load(self):
        try:
            with open(STATE_PATH, "r") as f:
                data = json.load(f)
        except FileNotFoundError:
            return
        except Exception as e:
            logging.warning(f"Ignoring unreadable state file {STATE_PATH}: {e}")
            return
        self.settings = data.get("settings", {})
        self.first_seen = data.get("first_seen", {})
        self.read = data.get("read", {})
        self.doomsday = data.get("doomsday", {})
        self.briefing = data.get("briefing", {})
        self.cvss = data.get("cvss", {})
        if data.get("last_launch"):
            self.previous_launch = datetime.fromisoformat(data["last_launch"])

    def save(self):
        cutoff = (datetime.now(timezone.utc) - SEEN_RETENTION).isoformat()
        self.first_seen = {k: v for k, v in self.first_seen.items() if v >= cutoff}
        self.read = {k: v for k, v in self.read.items() if v >= cutoff}
        data = {
            "settings": self.settings,
            "last_launch": self.launch_time.isoformat(),
            "first_seen": self.first_seen,
            "read": self.read,
            "doomsday": self.doomsday,
            "briefing": self.briefing,
            "cvss": self.cvss,
        }
        tmp = STATE_PATH + ".tmp"
        try:
            with open(tmp, "w") as f:
                json.dump(data, f)
            os.replace(tmp, STATE_PATH)
        except OSError as e:
            logging.error(f"Could not save state to {STATE_PATH}: {e}")

    @property
    def has_saved_settings(self) -> bool:
        return bool(self.settings)

    def record_alerts(self, alerts):
        """Remember when each alert was first seen. On the very first run
        everything is treated as already seen so the feed isn't all NEW."""
        baseline = not self.first_seen
        now = datetime.now(timezone.utc).isoformat()
        for a in alerts:
            key = alert_key(a)
            if key not in self.first_seen:
                self.first_seen[key] = now
                if baseline:
                    self.read[key] = now

    def is_new(self, alert) -> bool:
        """New = first seen since the previous launch, and not opened yet"""
        key = alert_key(alert)
        if key in self.read:
            return False
        seen = self.first_seen.get(key)
        if not seen:
            return True
        since = self.previous_launch or self.launch_time
        return datetime.fromisoformat(seen) >= since

    def mark_read(self, alert):
        self.read[alert_key(alert)] = datetime.now(timezone.utc).isoformat()
