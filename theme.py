"""
Color palettes for CybrWire

Every color the UI draws comes from a Palette role, so a theme is one table.
Design rules the panels follow:
  - borders are quiet; only the focused panel uses the accent
  - titles are normal text, metadata is muted
  - strong color is reserved for severity, shown as a tag rather than a painted row
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict


@dataclass(frozen=True)
class Palette:
    key: str
    name: str
    bg: str            # screen background
    surface: str       # selected row / input background
    border: str        # unfocused panel borders
    focus: str         # focused panel border and title bar
    text: str          # primary text
    muted: str         # metadata, hints, secondary text
    accent: str        # headings, NEW badge, interactive hints
    critical: str
    zeroday: str
    ransomware: str
    apt: str
    exploit: str
    info: str
    good: str
    warn: str
    bad: str
    monochrome: bool = False  # Cold War: one hue; urgency shown by brightness and reverse video
    # Optional flavor: panel names, severity names and a timestamp style for this palette
    titles: Dict[str, str] = field(default_factory=dict)
    severity_names: Dict[str, str] = field(default_factory=dict)
    military_time: bool = False
    banner: str = ""

    def severity(self, sev: str) -> str:
        return getattr(self, sev, self.info) if sev in SEVERITIES else self.info

    def severity_name(self, sev: str) -> str:
        return self.severity_names.get(sev, sev.upper())

    def title(self, text: str) -> str:
        """Panel title in this palette's vocabulary"""
        for plain, flavored in self.titles.items():
            if text.startswith(plain):
                return flavored + text[len(plain):]
        return text

    def stamp(self, ts: datetime, long: bool = False) -> str:
        """Short date for tables, or a full timestamp for the preview"""
        if self.military_time:
            # Date-time group: day, hour, minute in Zulu (UTC), e.g. 130614Z OCT 26
            return f"{ts:%d%H%MZ %b %y}".upper() if long else f"{ts:%d%H%MZ}"
        return f"{ts:%a %d %b %H:%M} UTC" if long else f"{ts:%a %d %b}"

    def level(self, pct: float) -> str:
        """Color for a 0-100 'how bad is it' value"""
        return self.good if pct < 20 else self.warn if pct < 50 else self.bad

    def badge(self, sev: str) -> str:
        """Style for a severity tag: filled (reverse video) for the two most urgent levels"""
        color = self.severity(sev)
        if sev in ("critical", "zeroday"):
            return f"bold {self.bg} on {color}"
        return f"bold {color}" if sev != "info" else color


SEVERITIES = ("critical", "zeroday", "ransomware", "apt", "exploit", "info")

PALETTES: Dict[str, Palette] = {p.key: p for p in [
    # Warm charcoal and cream with an amber accent (Gruvbox-inspired)
    Palette(
        key="retro_warm", name="Retro Warm",
        bg="#1d1b19", surface="#3a3530", border="#5a524a", focus="#d8a657",
        text="#ddc7a1", muted="#928374", accent="#d8a657",
        critical="#ea6962", zeroday="#e78a4e", ransomware="#d3869b",
        apt="#7daea3", exploit="#d8a657", info="#a89984",
        good="#a9b665", warn="#d8a657", bad="#ea6962",
    ),
    # Amber phosphor monochrome; red is kept only for critical
    Palette(
        key="amber_crt", name="Amber CRT",
        bg="#120c04", surface="#33220a", border="#6b4714", focus="#ffb000",
        text="#ffb000", muted="#a8700f", accent="#ffd27a",
        critical="#ff5a36", zeroday="#ffd27a", ransomware="#ffc040",
        apt="#e8a33a", exploit="#ffb000", info="#a8700f",
        good="#ffcc66", warn="#ffb000", bad="#ff5a36",
    ),
    # 1980s neon, toned down: deep navy with soft magenta and cyan
    Palette(
        key="synthwave", name="Synthwave",
        bg="#16152b", surface="#2c2852", border="#4a4380", focus="#ff7edb",
        text="#e6e1ff", muted="#8f89c0", accent="#72f1e8",
        critical="#fe4f5e", zeroday="#fede5d", ransomware="#ff7edb",
        apt="#b893ce", exploit="#f97e72", info="#8f89c0",
        good="#72f1b8", warn="#fede5d", bad="#fe4f5e",
    ),
]}

# Cold War: a green phosphor terminal. One hue, with hierarchy from brightness
# levels and reverse video, plus period message-traffic conventions.
COLD_WAR = Palette(
    key="cold_war", name="Cold War",
    bg="#020904", surface="#0c3418", border="#0f5a22", focus="#5cff6e",
    text="#29d94a", muted="#1a8f33", accent="#5cff6e",
    critical="#5cff6e", zeroday="#5cff6e", ransomware="#5cff6e",
    apt="#5cff6e", exploit="#5cff6e", info="#1a8f33",
    good="#29d94a", warn="#5cff6e", bad="#5cff6e",
    monochrome=True,
    titles={
        "GLOBAL THREAT FEED": "SIGINT INTERCEPTS",
        "WAR ROOM DASHBOARD": "SITUATION ROOM",
        "WAR ROOM": "INTELLIGENCE BRIEFING",
        "CORRELATED INCIDENTS": "CASE FILES",
        "FEED STATUS": "STATION STATUS",
        "API TOOLS": "TRACE REQUEST",
        "LIVE THREAT TAPE": "TELETYPE",
    },
    # Military message precedence, most to least urgent
    severity_names={
        "critical": "FLASH", "zeroday": "FLASH", "ransomware": "IMMEDIATE",
        "apt": "IMMEDIATE", "exploit": "PRIORITY", "info": "ROUTINE",
    },
    military_time=True,
    banner="TOP SECRET // CYBRWIRE // EYES ONLY",
)

DEFAULT_PALETTE = "synthwave"
