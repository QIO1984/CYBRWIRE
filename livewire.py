"""
The Live Wire: the bar across the top that shows what the app is really doing

It never invents activity. The title follows the real feed checks, anything first
seen during this session is announced, and when nothing is arriving the most
severe current items take turns.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable, Dict, List, Optional

from rich.text import Text
from textual import events
from textual.widgets import Static

from incidents import SEVERITY_RANK, age
from state import alert_key

ARRIVAL_SECONDS = 6       # How long an arrival stays up
QUIET_SECONDS = 8         # How long each item stays up when nothing is arriving
FRESH_SECONDS = 90        # How long an arrival wears the LIVE badge in the feed
MAX_ARRIVALS_SHOWN = 5    # Per check; a bigger burst is counted as "+N more"
MAX_ARRIVAL_AGE = timedelta(hours=48)  # A newly added feed's backlog isn't news
QUIET_ITEMS = 10
MAX_QUIET_PER_SOURCE = 3  # So one busy source can't take over the bar
TYPE_RATE = 60            # Cold War: characters per second
PULSE_SECONDS = 0.4       # Dot flip while a check runs
SETTLE_SECONDS = 2        # Dot stays bright this long after a check
SOUND_LABEL_WIDTH = 24    # Clickable end of the bottom border


def rank(alert: Dict, watchlist) -> tuple:
    """Most severe first, watchlist hits first within a severity, then newest"""
    return (SEVERITY_RANK.get(alert.get("severity"), 99), not watchlist.hits(alert), -alert["ts"].timestamp())


def eligible(alert: Dict, leader_of: Dict) -> bool:
    """Stories only: not indicators, and not the second report of a grouped story"""
    return alert.get("kind") != "indicators" and alert_key(alert) not in leader_of


def quiet_items(alerts: List[Dict], watchlist, leader_of: Dict, recency_hours: int, now: Optional[datetime] = None) -> List[Dict]:
    now = now or datetime.now(timezone.utc)
    cutoff = now - timedelta(hours=recency_hours)
    candidates = [a for a in alerts if a["ts"] >= cutoff and eligible(a, leader_of) and not a.get("undated")]
    picked, per_source = [], {}
    for a in sorted(candidates, key=lambda a: rank(a, watchlist)):
        if per_source.get(a["source"], 0) < MAX_QUIET_PER_SOURCE:
            per_source[a["source"]] = per_source.get(a["source"], 0) + 1
            picked.append(a)
            if len(picked) == QUIET_ITEMS:
                break
    return picked


@dataclass
class Shown:
    alert: Dict
    arrival: bool
    since: float
    more: int = 0


class LiveWire:
    def __init__(self):
        self.sweeping = False
        self.total = 0
        self.checked = 0
        self.current_feed = ""
        self.last_check: Optional[datetime] = None
        self.last_check_clock = 0.0
        self.baseline_done = False  # The first check of a session only sets the baseline
        self.session_count = 0
        self.queue: List[Dict] = []
        self.more = 0
        self.fresh: Dict[str, float] = {}
        self.shown: Optional[Shown] = None
        self.quiet_index = -1
        self.pending_clock = 0.0

    # The feed check

    def begin_sweep(self, total: int) -> None:
        self.sweeping, self.total, self.checked, self.current_feed = True, total, 0, ""

    def feed_started(self, name: str) -> None:
        self.current_feed = name

    def feed_done(self) -> None:
        self.checked += 1

    def end_sweep(self, first_seen_now: List[Dict], watchlist, leader_of: Dict, clock: float,
                  now: Optional[datetime] = None) -> List[Dict]:
        """Queue what's new and return it"""
        now = now or datetime.now(timezone.utc)
        self.sweeping = False
        self.last_check, self.last_check_clock = now, clock
        if not self.baseline_done:
            self.baseline_done = True
            return []
        arrivals = [a for a in first_seen_now if eligible(a, leader_of) and not a.get("undated")
                    and now - a["ts"] <= MAX_ARRIVAL_AGE]
        arrivals.sort(key=lambda a: rank(a, watchlist))
        self.session_count += len(arrivals)
        self.fresh.update({alert_key(a): clock for a in arrivals})
        self.queue.extend(arrivals[:MAX_ARRIVALS_SHOWN])
        self.more += max(0, len(arrivals) - MAX_ARRIVALS_SHOWN)
        return arrivals

    # What's on the bar

    def tick(self, clock: float, quiet: Callable[[], List[Dict]]) -> None:
        """Move to the next item when the current one has had its time"""
        shown = self.shown
        if shown:
            limit = ARRIVAL_SECONDS if shown.arrival else QUIET_SECONDS
            # An arrival doesn't wait for a quiet item to finish its turn
            if clock - shown.since < limit and (shown.arrival or not self.queue):
                return
        if self.queue:
            alert = self.queue.pop(0)
            more = self.more if not self.queue else 0
            if not self.queue:
                self.more = 0
            self.shown = Shown(alert, True, clock, more)
            return
        items = quiet()
        if not items:
            self.shown = None
            return
        self.quiet_index = (self.quiet_index + 1) % len(items)
        self.shown = Shown(items[self.quiet_index], False, clock)

    def is_fresh(self, alert: Dict) -> bool:
        return alert_key(alert) in self.fresh

    def expire_fresh(self, clock: float) -> bool:
        """Drop LIVE badges past their time. True if any went, so the feed can redraw."""
        expired = [k for k, seen in self.fresh.items() if clock - seen >= FRESH_SECONDS]
        for key in expired:
            del self.fresh[key]
        return bool(expired)


def clock_text(seconds: int) -> str:
    return f"{seconds}s" if seconds < 60 else f"{seconds // 60}m"


class LiveWirePanel(Static):
    """Clicking it jumps to the alert on show. The sound setting is at the end of the bottom border."""

    DEFAULT_CSS = """
    LiveWirePanel {
        height: 3;
        border: round $primary;
        border-title-align: left;
        border-subtitle-align: right;
        padding: 0 1;
    }
    """

    drawn = None

    def title_text(self, clock: float) -> Text:
        app = self.app
        wire = app.wire
        p = app.palette
        if wire.sweeping:
            dot = "●" if int(clock / PULSE_SECONDS) % 2 == 0 else "○"
            status = f"checking {wire.checked}/{wire.total}" + (f" · {wire.current_feed}" if wire.current_feed else "")
            dot_style = f"bold {p.warn}"
        else:
            dot = "●"
            dot_style = f"bold {p.accent}" if clock - wire.last_check_clock < SETTLE_SECONDS else p.good
            if wire.last_check:
                now = datetime.now(timezone.utc)
                since = max(0, int((now - wire.last_check).total_seconds()))
                remaining = max(0, int((app.next_refresh - now).total_seconds()))
                status = f"last check {clock_text(since)} ago · next in {remaining // 60}:{remaining % 60:02d}"
            else:
                status = "first check starting"
            failed = app.failed_feed_count()
            if failed:
                status += f" · {failed} feed{'s' if failed != 1 else ''} failed"
        text = Text(f" {dot} ", style=dot_style)
        text.append(p.title("LIVE WIRE"), style=f"bold {p.text}")
        text.append(f" · {status} ", style=p.muted)
        return text

    def subtitle_text(self) -> Text:
        app = self.app
        wire = app.wire
        p = app.palette
        text = Text(" ")
        if wire.session_count:
            text.append(f"{wire.session_count} new this session · ", style=p.accent)
        text.append(f"b sound: {app.sound_label()} ", style=p.muted)
        return text

    def body_text(self, clock: float) -> Text:
        app = self.app
        p = app.palette
        shown = app.wire.shown
        text = Text(no_wrap=True, overflow="ellipsis")
        if not shown:
            text.append("All quiet: nothing to report in this data window", style=p.muted)
            return text
        alert = shown.alert
        sev = alert["severity"]
        if shown.arrival:
            text.append(" JUST IN ", style=f"bold {p.bg} on {p.accent}")
            text.append(" ")
        text.append(f"{age(alert['ts']):>3}  ", style=p.muted)
        urgent = sev in ("critical", "zeroday")
        text.append(f" {p.severity_name(sev)} " if urgent else p.severity_name(sev), style=p.badge(sev))
        text.append("  ")
        if app.watchlist.hits(alert):
            text.append("★ ", style=f"bold {p.warn}")
        text.append(alert["title"], style=f"bold {p.text}" if urgent or shown.arrival else p.text)
        text.append(f"  · {alert['source']}", style=p.muted)
        if shown.more:
            text.append(f"  +{shown.more} more", style=f"bold {p.accent}")
        if p.monochrome:  # A teletype prints as you watch
            text.truncate(int((clock - shown.since) * TYPE_RATE) + 1)
        return text

    def redraw(self, clock: float) -> None:
        app = self.app
        p = app.palette
        title, subtitle, body = self.title_text(clock), self.subtitle_text(), self.body_text(clock)
        shown = app.wire.shown
        state = (p.key, title.markup, subtitle.markup, body.markup)
        if state == self.drawn:
            return
        self.drawn = state
        self.border_title = title
        self.border_subtitle = subtitle
        self.styles.border = ("round", p.accent if shown and shown.arrival else p.border)
        self.update(body)

    def on_click(self, event: events.Click) -> None:
        if event.button != 1:
            return
        event.stop()
        if event.y == self.size.height + 1 and event.x >= self.outer_size.width - SOUND_LABEL_WIDTH:
            self.app.action_cycle_sound()
        else:
            self.app.action_jump_to_wire()
