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
    pure: bool = False        # A period simulation (Cold War, Amber CRT): no mood tinting or other colour effects added on top
    boot: tuple = ()          # Optional flavour lines for the loading screen, in place of the usual ones
    blurb: str = ""           # One short line describing the look, shown in the theme picker
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
    # Near-black with vivid neon: hot pink focus, cyan accent, electric blue and violet for the quiet roles
    Palette(
        key="neon", name="Neon Noir",
        blurb="default: pink, cyan and violet on near-black",
        bg="#07070d", surface="#16162e", border="#33335a", focus="#ff4fd8",
        text="#e6e6f0", muted="#8a8ab0", accent="#00e5ff",
        critical="#ff3b6b", zeroday="#ffd23f", ransomware="#ff4fd8",
        apt="#a98bff", exploit="#ff8a3d", info="#6c8cff",
        good="#39ff88", warn="#ffb000", bad="#ff5470",
    ),
    # Rain-soaked night city: warm amber focus against teal, on blue-black
    Palette(
        key="blade_runner", name="Blade Runner",
        blurb="amber and teal, a rain-soaked night city",
        bg="#07090f", surface="#141b27", border="#2b3a4a", focus="#ff9d2e",
        text="#dfe6ee", muted="#7d8fa3", accent="#2fe0d0",
        critical="#ff4d3d", zeroday="#ffd23f", ransomware="#ff7aa8",
        apt="#8aa4ff", exploit="#ff9d2e", info="#5db7ff",
        good="#3df2a5", warn="#ffb000", bad="#ff5470",
        boot=("RUNNING VOIGHT-KAMPFF...", "TRACING REPLICANT NETWORKS...", "READING THE RAIN...", "MORE HUMAN THAN HUMAN...", "ENHANCE..."),
    ),
    # Electric cyan grid on pure black with one orange accent
    Palette(
        key="tron", name="Tron",
        blurb="electric cyan grid, one orange accent",
        bg="#02060a", surface="#0a1b29", border="#124560", focus="#00f0ff",
        text="#d4f1ff", muted="#5e9ab8", accent="#ff8a00",
        critical="#ff4a4a", zeroday="#ffe14d", ransomware="#ff6ad5",
        apt="#8f7bff", exploit="#ff8a00", info="#4fb8ff",
        good="#38ffa0", warn="#ffb300", bad="#ff5470",
        boot=("ENTERING THE GRID...", "DEREZZING STALE FEEDS...", "CHARGING IDENTITY DISC...", "SYNCING WITH THE MCP...", "GREETINGS, PROGRAM."),
    ),
    # Cold teal and mint with magenta flashes on near-black green
    Palette(
        key="ghost_shell", name="Ghost Shell",
        blurb="teal and mint with magenta flashes",
        bg="#040c0e", surface="#0b2025", border="#1c4e54", focus="#3dffd0",
        text="#d2f6ef", muted="#5f9d97", accent="#ff4f9a",
        critical="#ff4f6e", zeroday="#f6ff6a", ransomware="#ff4f9a",
        apt="#9d8cff", exploit="#ffa04d", info="#52d6ff",
        good="#3dffd0", warn="#ffc24d", bad="#ff5470",
        boot=("DIVING THE NET...", "GHOST-HACKING THE FEEDS...", "SYNCING WITH THE SHELL...", "THE NET IS VAST...", "STAND ALONE COMPLEX..."),
    ),
    # Soft pink, lavender and mint on deep purple
    Palette(
        key="vaporwave", name="Vaporwave",
        blurb="pastel pink, lavender and mint on purple",
        bg="#0f0819", surface="#221540", border="#4a2f7a", focus="#ff71ce",
        text="#f2e9ff", muted="#a98fd8", accent="#01cdfe",
        critical="#ff4f7b", zeroday="#fffb96", ransomware="#ff71ce",
        apt="#b967ff", exploit="#ff9a76", info="#7fb4ff",
        good="#05ffa1", warn="#ffd166", bad="#ff5c8a",
        boot=("A E S T H E T I C...", "LOADING THE MALL...", "RENDERING PALM TREES...", "WINDOWS 95 STARTUP...", "ｖａｐｏｒｗａｖｅ"),
    ),
    # Cool whites and blues on dark slate: calm for a screen that stays on
    Palette(
        key="arctic", name="Arctic",
        blurb="ice blues on slate, calm all day",
        bg="#080e15", surface="#142130", border="#2b425a", focus="#8fd3ff",
        text="#e8f4ff", muted="#7f9bb3", accent="#5cc8ff",
        critical="#ff5c6e", zeroday="#ffe27a", ransomware="#ff8fc8",
        apt="#a9b8ff", exploit="#ffa86b", info="#7cc4ff",
        good="#5af0b4", warn="#ffc857", bad="#ff6b7f",
        boot=("CHECKING THE ICE...", "READING THE AURORA...", "COOLING THE CORE...", "ALL QUIET AT THE POLE...", "CLEAR SKIES..."),
    ),
    # A war-room glow: deep reds and oranges on black
    Palette(
        key="ember", name="Ember",
        blurb="war-room reds and oranges",
        bg="#0b0605", surface="#241210", border="#4d241a", focus="#ff5a2e",
        text="#f4ded4", muted="#a47e70", accent="#ffb347",
        critical="#ff3350", zeroday="#ffe066", ransomware="#ff7aa2",
        apt="#c792ff", exploit="#ff8a3d", info="#ffa07a",
        good="#9be564", warn="#ffb347", bad="#ff4d4d",
        boot=("STOKING THE FIRE...", "READING THE EMBERS...", "WAR ROOM ON STANDBY...", "STAY HOT...", "WATCHING THE SMOKE..."),
    ),
    # Green on black, but severity keeps its own colours (Cold War mode is the fully mono one)
    Palette(
        key="matrix", name="Matrix",
        blurb="green on black, severity keeps its colour",
        bg="#010803", surface="#06260f", border="#0f5124", focus="#00ff55",
        text="#b8ffcb", muted="#3f9e5d", accent="#7dffa0",
        critical="#ff3b3b", zeroday="#eaff4a", ransomware="#ff5ad1",
        apt="#5ad1ff", exploit="#ffa63a", info="#58d68d",
        good="#00ff55", warn="#ffd23f", bad="#ff5470",
        boot=("WAKE UP...", "THE MATRIX HAS YOU...", "FOLLOW THE WHITE RABBIT...", "FREE YOUR FEEDS...", "THERE IS NO SPOON."),
    ),
    # Black, white and grey: only severity gets colour, so anything coloured is news
    Palette(
        key="newsroom", name="Newsroom",
        blurb="black and white, only severity in colour",
        bg="#0a0a0a", surface="#1c1c1c", border="#383838", focus="#f2f2f2",
        text="#e6e6e6", muted="#8c8c8c", accent="#ffffff",
        critical="#ff3b30", zeroday="#ffd60a", ransomware="#ff6fae",
        apt="#b79cff", exploit="#ff9f0a", info="#9a9a9a",
        good="#4cd964", warn="#ffd60a", bad="#ff453a",
        boot=("GOING TO PRESS...", "CHECKING THE WIRE...", "VERIFYING SOURCES...", "STOP THE PRESSES...", "READ ALL ABOUT IT..."),
    ),
    # 1980s neon, toned down: deep navy with soft magenta and cyan
    Palette(
        key="synthwave", name="Synthwave",
        blurb="toned-down 80s neon on deep navy",
        bg="#16152b", surface="#2c2852", border="#4a4380", focus="#ff7edb",
        text="#e6e1ff", muted="#8f89c0", accent="#72f1e8",
        critical="#fe4f5e", zeroday="#fede5d", ransomware="#ff7edb",
        apt="#b893ce", exploit="#f97e72", info="#8f89c0",
        good="#72f1b8", warn="#fede5d", bad="#fe4f5e",
    ),
    # Warm charcoal and cream with an amber accent (Gruvbox-inspired)
    Palette(
        key="retro_warm", name="Retro Warm",
        blurb="warm charcoal and amber, Gruvbox-style",
        bg="#1d1b19", surface="#3a3530", border="#5a524a", focus="#d8a657",
        text="#ddc7a1", muted="#928374", accent="#d8a657",
        critical="#ea6962", zeroday="#e78a4e", ransomware="#d3869b",
        apt="#7daea3", exploit="#d8a657", info="#a89984",
        good="#a9b665", warn="#d8a657", bad="#ea6962",
    ),
    # Amber phosphor monochrome; red is kept only for critical
    Palette(
        key="amber_crt", name="Amber CRT",
        blurb="period simulation: amber phosphor, one hue",
        bg="#120c04", surface="#33220a", border="#6b4714", focus="#ffb000",
        text="#ffb000", muted="#a8700f", accent="#ffd27a",
        critical="#ff5a36", zeroday="#ffd27a", ransomware="#ffc040",
        apt="#e8a33a", exploit="#ffb000", info="#a8700f",
        good="#ffcc66", warn="#ffb000", bad="#ff5a36",
        pure=True,
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
    pure=True,
    blurb="Cold War mode: green phosphor (on c)",
    titles={
        "GLOBAL THREAT FEED": "SIGINT INTERCEPTS",
        "WAR ROOM DASHBOARD": "SITUATION ROOM",
        "WAR ROOM": "INTELLIGENCE BRIEFING",
        "CORRELATED INCIDENTS": "CASE FILES",
        "FEED STATUS": "STATION STATUS",
        "API TOOLS": "TRACE REQUEST",
        "LIVE WIRE": "TELETYPE",
        "THREAT MAP": "THEATRE MAP",
    },
    # Military message precedence, most to least urgent
    severity_names={
        "critical": "FLASH", "zeroday": "FLASH", "ransomware": "IMMEDIATE",
        "apt": "IMMEDIATE", "exploit": "PRIORITY", "info": "ROUTINE",
    },
    military_time=True,
    banner="TOP SECRET // CYBRWIRE // EYES ONLY",
)

DEFAULT_PALETTE = "neon"
