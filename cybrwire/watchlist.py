"""
Watchlist and search matching for CybrWire

Watchlist terms match whole words in an alert's title and description, in any
case, so "ssl" doesn't flag every OpenSSL story; a trailing * matches a prefix
("citrix*" finds CitrixBleed).
Search is a plain substring match; every word in the query has to appear.
"""

import re
from typing import Any, Dict, Iterable, List

from .state import alert_key

SEARCH_FIELDS = ("title", "summary", "source", "severity", "ioc", "threat")
WATCH_FIELDS = ("title", "summary")


def _alert_text(alert: Dict[str, Any], fields=SEARCH_FIELDS) -> str:
    return " ".join(str(alert.get(f) or "") for f in fields)


def _compile(term: str) -> "re.Pattern":
    body = re.escape(term).replace(r"\*", r"\w*")
    return re.compile(rf"(?<!\w){body}(?!\w)", re.IGNORECASE)


def _clean(terms: Iterable[Any]) -> List[str]:
    """Strip blanks and duplicates (ignoring case), keeping the first spelling"""
    seen = {}
    for term in terms or []:
        term = "" if term is None else str(term).strip()  # A bare "- " in YAML is None
        if term and term.lower() not in seen:
            seen[term.lower()] = term
    return list(seen.values())


class Watchlist:
    """Terms from YAML (read-only here) plus terms added in the app (saved in the state)"""

    def __init__(self, configured: Iterable[Any] = (), added: Iterable[Any] = ()):
        self.configured = _clean(configured)
        self.added = [t for t in _clean(added) if t.lower() not in {c.lower() for c in self.configured}]
        self._rebuild()

    def _rebuild(self):
        self._patterns = [(t, _compile(t)) for t in self.terms]
        self._memo: Dict[str, List[str]] = {}  # Matched on every redraw, so remember the answer

    @property
    def terms(self) -> List[str]:
        return self.configured + self.added

    def toggle(self, term: str) -> str:
        """Add a term, or remove it if already there. Returns added, removed or configured."""
        term = term.strip()
        lower = term.lower()
        if lower in {c.lower() for c in self.configured}:
            return "configured"
        if lower in {a.lower() for a in self.added}:
            self.added = [a for a in self.added if a.lower() != lower]
            result = "removed"
        else:
            self.added.append(term)
            result = "added"
        self._rebuild()
        return result

    def hits(self, alert: Dict[str, Any]) -> List[str]:
        """The terms this alert matches"""
        if not self._patterns:
            return []
        key = alert_key(alert)
        if key not in self._memo:
            text = _alert_text(alert, WATCH_FIELDS)
            self._memo[key] = [t for t, pattern in self._patterns if pattern.search(text)]
        return self._memo[key]


def matches_search(alert: Dict[str, Any], query: str) -> bool:
    text = _alert_text(alert).lower()
    return all(word in text for word in query.lower().split())
