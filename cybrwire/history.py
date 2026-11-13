"""
Alert history for CybrWire: everything ever seen, in a local SQLite file

Feeds only keep their newest items, so search looks here for anything that has
since dropped off. History is a convenience: errors are logged, never raised.
"""

import logging
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List

from .config import APP_DIR, secure_file
from .state import alert_key

HISTORY_PATH = os.path.join(APP_DIR, "cybrwire_history.db")
RETENTION_DAYS = 365
MAX_RESULTS = 500
FIELDS = ("title", "summary", "source", "source_file", "severity", "kind", "url", "ioc", "ioc_type", "threat")
SEARCHED = ("title", "summary", "source", "severity", "ioc", "threat")


class History:
    def __init__(self, path: str = None):
        self.path = path or HISTORY_PATH

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path)
        try:
            conn.execute("CREATE TABLE IF NOT EXISTS alerts (key TEXT PRIMARY KEY, ts TEXT NOT NULL, undated INTEGER, "
                         + ", ".join(f"{f} TEXT" for f in FIELDS) + ")")
            conn.execute("CREATE INDEX IF NOT EXISTS alerts_ts ON alerts (ts)")
        except sqlite3.Error:
            conn.close()
            raise
        secure_file(self.path)
        return conn

    def record(self, alerts: Iterable[Dict[str, Any]]) -> None:
        """Save new alerts and forget ones past the retention period. Safe to run in a thread."""
        rows = [(alert_key(a), a["ts"].isoformat(), int(bool(a.get("undated"))), *(a.get(f) for f in FIELDS))
                for a in alerts]
        cutoff = (datetime.now(timezone.utc) - timedelta(days=RETENTION_DAYS)).isoformat()
        marks = ", ".join("?" * (3 + len(FIELDS)))
        try:
            conn = self._connect()
            try:
                with conn:
                    conn.executemany(f"INSERT OR IGNORE INTO alerts VALUES ({marks})", rows)
                    conn.execute("DELETE FROM alerts WHERE ts < ?", (cutoff,))
            finally:
                conn.close()
        except sqlite3.Error as e:
            logging.error(f"Could not save alert history: {e}")

    def search(self, query: str) -> List[Dict[str, Any]]:
        """Alerts containing every word in the query, newest first"""
        words = query.lower().split()
        if not words:
            return []
        haystack = " || ' ' || ".join(f"COALESCE({f}, '')" for f in SEARCHED)
        where = " AND ".join(f"LOWER({haystack}) LIKE ? ESCAPE '\\'" for _ in words)
        patterns = ["%" + w.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%" for w in words]
        try:
            conn = self._connect()
            conn.row_factory = sqlite3.Row
            try:
                rows = conn.execute(f"SELECT * FROM alerts WHERE {where} ORDER BY ts DESC LIMIT ?",
                                    (*patterns, MAX_RESULTS)).fetchall()
            finally:
                conn.close()
        except sqlite3.Error as e:
            logging.error(f"Could not search alert history: {e}")
            return []
        return [{**{f: row[f] for f in FIELDS if row[f] is not None},
                 "ts": datetime.fromisoformat(row["ts"]), "undated": bool(row["undated"]), "archived": True}
                for row in rows]
