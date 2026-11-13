"""
Duplicate-story grouping for CybrWire

The same story from several feeds collapses into one row. Grouping errs towards
keeping stories apart: two items must come from different sources, within three
days, name the same CVEs in their titles, and have mostly the same title words.
"""

import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Dict, List

from .incidents import CVE_RE, SEVERITY_RANK
from .state import alert_key

MAX_GAP = timedelta(days=3)
MIN_WORDS = 4         # Shorter titles don't carry enough words to compare
MIN_SIMILARITY = 0.6  # Shared words / all words across both titles
COMMON_WORD_LIMIT = 40  # A word in more titles than this doesn't help find candidates

WORD_RE = re.compile(r"[a-z0-9][a-z0-9.+_-]*")
STOP_WORDS = frozenset("a an and are as at be by for from has have in into is it its of on or the to was were with "
                       "after new over says via this that their".split())


def _words(title: str) -> frozenset:
    return frozenset(w for w in WORD_RE.findall(CVE_RE.sub(" ", title).lower()) if w not in STOP_WORDS)


def _title_cves(title: str) -> frozenset:
    return frozenset(c.upper() for c in CVE_RE.findall(title))


@dataclass
class _Group:
    members: List[dict] = field(default_factory=list)
    words: frozenset = frozenset()
    cves: frozenset = frozenset()

    def accepts(self, alert: dict, words: frozenset, cves: frozenset) -> bool:
        if cves != self.cves or alert["source"] in {m["source"] for m in self.members}:
            return False
        if any(abs(alert["ts"] - m["ts"]) > MAX_GAP for m in self.members):
            return False
        return len(words & self.words) / len(words | self.words) >= MIN_SIMILARITY


@dataclass
class Groups:
    leader_of: Dict[str, str] = field(default_factory=dict)      # member key -> leader key
    others: Dict[str, List[dict]] = field(default_factory=dict)  # leader key -> its other members


def group_duplicates(alerts: List[dict]) -> Groups:
    """Find duplicate stories; the most severe (then newest) report leads each group"""
    candidates = [a for a in alerts
                  if a.get("kind") not in ("indicators", "ransomware") and not a.get("undated")]
    usable = [(a, _words(a["title"])) for a in candidates]
    usable = [(a, w) for a, w in usable if len(w) >= MIN_WORDS]

    frequency = defaultdict(int)
    for _, words in usable:
        for word in words:
            frequency[word] += 1

    groups: List[_Group] = []
    by_word = defaultdict(list)  # Rare word -> groups containing it, so few comparisons are needed
    for alert, words in sorted(usable, key=lambda item: item[0]["ts"], reverse=True):
        cves = _title_cves(alert["title"])
        rare = [w for w in words if frequency[w] <= COMMON_WORD_LIMIT]
        match = next((g for w in rare for g in by_word[w] if g.accepts(alert, words, cves)), None)
        if match is None:
            match = _Group(words=words, cves=cves)
            groups.append(match)
            for w in rare:
                by_word[w].append(match)
        match.members.append(alert)

    result = Groups()
    for group in groups:
        if len(group.members) < 2:
            continue
        ranked = sorted(group.members, key=lambda a: (SEVERITY_RANK.get(a["severity"], 9), -a["ts"].timestamp()))
        leader = alert_key(ranked[0])
        result.others[leader] = ranked[1:]
        for member in ranked[1:]:
            result.leader_of[alert_key(member)] = leader
    return result
