"""
World clock strip: your local time plus a few reference cities.

Local time follows the TZ environment variable (for Docker, set TZ in cybrwire.env), or
`timezone:` in usrwire.yaml, or else the machine's own zone. The reference cities can be
changed with `clocks:` in usrwire.yaml, for example:

    clocks:
      - "NYC: America/New_York"
      - "TYO: Asia/Tokyo"
"""

import logging
import os
from datetime import datetime, timezone, tzinfo
from typing import Any, List, Optional, Tuple
from zoneinfo import ZoneInfo

from rich.text import Text

# St Petersburg shares Moscow's zone
DEFAULT_CLOCKS: List[Tuple[str, str]] = [
    ("NYC", "America/New_York"), ("LAX", "America/Los_Angeles"), ("LON", "Europe/London"),
    ("ROM", "Europe/Rome"), ("SPB", "Europe/Moscow"), ("TYO", "Asia/Tokyo"),
]


def _zone(name: str) -> Optional[ZoneInfo]:
    try:
        return ZoneInfo(str(name).strip())
    except Exception:  # Unknown name, or no zone database on this machine
        return None


def local_zone(configured: Optional[str] = None) -> tzinfo:
    """The zone for LOC: TZ, then the configured name, then whatever the machine says"""
    for name in (os.environ.get("TZ"), configured):
        if name and (zone := _zone(name)):
            return zone
        if name:
            logging.warning(f"Unknown time zone '{name}', trying the next choice")
    return datetime.now().astimezone().tzinfo or timezone.utc


def _entries(raw: Any):
    """Each item may be 'NYC: America/New_York', {label, zone} or {NYC: America/New_York}"""
    if isinstance(raw, dict):
        raw = [{k: v} for k, v in raw.items()]
    for item in raw if isinstance(raw, list) else []:
        if isinstance(item, str) and ":" in item:
            label, _, zone = item.partition(":")
            yield label.strip(), zone.strip()
        elif isinstance(item, dict) and "zone" in item:
            yield str(item.get("label") or item["zone"].split("/")[-1]), item["zone"]
        elif isinstance(item, dict) and len(item) == 1:
            label, zone = next(iter(item.items()))
            yield str(label), str(zone)


def parse_clocks(raw: Any) -> List[Tuple[str, ZoneInfo]]:
    """The reference clocks to show; unknown zones are skipped, and nothing usable means the defaults"""
    found = []
    for label, name in _entries(raw):
        zone = _zone(name)
        if zone and label:
            found.append((label.upper()[:4], zone))
        else:
            logging.warning(f"Skipping clock '{label}': unknown time zone '{name}'")
    if found or raw:
        return found or parse_clocks(None)
    return [(label, ZoneInfo(name)) for label, name in DEFAULT_CLOCKS if _zone(name)]


def _line(now: datetime, local: tzinfo, clocks: List[Tuple[str, ZoneInfo]], palette, sep: str, zone_name: bool) -> Text:
    here = now.astimezone(local)
    text = Text(no_wrap=True, overflow="ellipsis", justify="center")
    text.append("LOC ", style=f"bold {palette.accent}")
    text.append(f"{here:%H:%M}", style=f"bold {palette.text}")
    if zone_name and here.tzname():
        text.append(f" {here.tzname()}", style=palette.muted)
    for label, zone in clocks:
        there = now.astimezone(zone)
        text.append(sep, style=palette.muted)
        text.append(f"{label} ", style=palette.muted)
        text.append(f"{there:%H:%M}", style=palette.text)
        days = (there.date() - here.date()).days
        if days:
            text.append(f"{days:+d}", style=palette.muted)  # A different calendar day from yours
    return text


def render(now: datetime, local: tzinfo, clocks: List[Tuple[str, ZoneInfo]], palette, width: int = 0) -> Text:
    """One line: LOC 22:48 EST · NYC 22:48 · TYO 12:48+1, squeezed to fit a narrow window"""
    text = None
    for sep, zone_name in (("  ·  ", True), ("  ", True), ("  ", False), (" ", False)):
        text = _line(now, local, clocks, palette, sep, zone_name)
        if not width or text.cell_len <= width:
            break
    return text
