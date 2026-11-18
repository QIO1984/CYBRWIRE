"""
The world map: land drawn as braille dots, with pulsing markers for ransomware victims and outages.

The land is a 200 x 80 dot mask (1.8 degrees per dot, 84N to 60S) made from Natural Earth's 110m
land outlines, which are public domain. A terminal cell holds 2 x 4 braille dots, so the map keeps
fine coastlines. Markers step through a few glyphs and shades to pulse, each out of step with the others.
"""

import base64
import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from rich.text import Text

DOTS_WIDE, DOTS_HIGH = 200, 80
LAT_TOP, LAT_BOTTOM = 84.0, -60.0
MIN_ROWS = 5
MIN_LABEL_COLS = 60  # A smaller map has no room to name its markers; the legend lists them

_MASK_B64 = (
    "AAAAAAAAAPwAH/4AAAAAAAAAAAAAAAAAAAAAAAAAAD/+f//++AAAAAAAAAAAAAAAAAAAAAAAAAH/4P///8AAPsAAAAAA8AAA"
    "AAAAAAAAAAYDF4////+AAAyAAAAAAAAAAAAAAAAAAAAdnMAAP///gAAAAAAHgAD/4ADgAAAAAAAB4AGAAAf//wAAAAAAMAAP"
    "/4AAAAAAAAAAA//dPsAH//0AAAAAAGAwf///8HwAAAAfAAAH45/8A//8AAAAeAAAd///////+AAA////9gDuPAH/+AAAB/+A"
    "S7v/////////+H///////B+D/4AAAA//4f/3/////////zH///////h+gfwA8AA/Pj////////////8EP//////IDQD4AAAA"
    "/v/////////////+AP//////AHAAcAAAAfz////////////l8AA+g////gB4AAAAAAH8D///////////xgAADAA///8Af4AA"
    "AABAOD//////////wBwAABAAH///4H/AAAAAQFD//////////wA8AAAAAB////z/8AAAAbBH//////////8AGAAAAAAH///+"
    "//gAAAE7////////////8BAAAAAAA//////oAAAAZ////////////9AAAAAAAAL////9HAAAAB/////////////AAAAAAAAB"
    "/////wIAAAAf//+/////////kAAAAAAAAf/////AAAAAH+/zfH///////wAAAAAAAAH////4AAAAAZ838Dz///////4YAAAA"
    "AAAB////+AAAAAH8GfMeP//////wAAAAAAAAAf///+AAAAAB8AGf/z/////84CAAAAAAAAD///+AAAAAAfAIn/4//////HBA"
    "AAAAAAAA////wAAAAAAPwAr///////4wwAAAAAAAAH///4AAAAAA/8AA///////+JwAAAAAAAAAf//8AAAAAAf/wAf//////"
    "/ggAAAAAAAAAF//+AAAAAAH//f////////8AAAAAAAAAAAv+AgAAAAAD/////v//////AAAAAAAAAAAN/AIAAAAAB////v5/"
    "/////gAAAAAAAAAAAfwAAAAAAA////5/h/////wAAAAAAAAAAAB8AAAAAAAf////f/A////5AAAAAAAAAAAAfAGAAAAAH///"
    "/z/4H/n/4AAAAAAABAAAAHwgYAAAAB////+/8A/w/gAAAAAAAAAAAAA+4BkAAAAf////n+AH4P4BAAAAAAAAAAAAB+AAAAAA"
    "H////8+AB8D/AQAAAAAAAAAAAAB8AAAAAD/////vAAcAP4EAAAAAAAAAAAAAHAAAAAAf////+AADgB+AAAAAAAAAAAAAAAgU"
    "AAAAD/////MAAwAHAAAAAAAAAAAAAAAEv8AAAA//////AAOAAgAAAAAAAAAAAAAAAH/gAAAH/////wAAgBAAwAAAAAAAAAAA"
    "AAB//AAAA/H///4AAAAIDAAAAAAAAAAAAAAAf/8AAAAAf//8AAAAKBgAAAAAAAAAAAAAAP//AAAAAH//+AAAABQ8AAAAAAAA"
    "AAAAAAD//wAAAAB///AAAAAceAAAAAAAAAAAAAAB///gAAAAf//gAAAADHsGAAAAAAAAAAAAAf///AAAAD//wAAAAAY7O+CA"
    "AAAAAAAAAAH///8AAAAf/8AAAAACAgD4gAAAAAAAAAAB////gAAAH//AAAAAAcAAfAAAAAAAAAAAAP///4AAAB//wAAAAAAF"
    "QDQAAAAAAAAAAAB///8AAAAf/8AAAAAAAAABAAAAAAAAAAAAf//+AAAAH//gAAAAAAAHEAAAAAAAAAAAAD///AAAAB//4QAA"
    "AAAALhAAAAAAAAAAAAAf//wAAAAf/8cAAAAAAH8YAAAAAAAAAAAAD//8AAAAH/+OAAAAAAD/+AAAAAAAAAAAAAf//AAAAB//"
    "BgAAAAAB//wAAAAAAAAAAAAH//gAAAAP/w4AAAAAD//+AAAAAAAAAAAAB//wAAAAD/8OAAAAAB///wAAAAAAAAAAAAf/wAAA"
    "AA/+DAAAAAAf//+AAAAAAAAAAAAH/4AAAAAP/AAAAAAAH///gAAAAAAAAAAAD/+AAAAAB/wAAAAAAA///4AAAAAAAAAAAA//"
    "AAAAAAP4AAAAAAAP//+AAAAAAAAAAAAP/gAAAAAD8AAAAAAAD+P/gAAAAAAAAAAAD/wAAAAAA0AAAAAAAA6B/wAAAAAAAAAA"
    "AA/wAAAAAAAAAAAAAAAAAH8ACAAAAAAAAAAf8AAAAAAAAAAAAAAAAAA+AAQAAAAAAAAAH4AAAAAAAAAAAAAAAAAAAAAEAAAA"
    "AAAAAB+AAAAAAAAAAAAAAAAAAAwADAAAAAAAAAAPAAAAAAAAAAAAAAAAAAAEABAAAAAAAAAAHwAAAAAAAAAAAAAAAAAAAABg"
    "AAAAAAAAAD4AAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAA+AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAPAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAADwwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAcAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
)
_MASK = base64.b64decode("".join(_MASK_B64.split()) if isinstance(_MASK_B64, str) else _MASK_B64)

PULSE = ("●", "◉", "◎", "○")  # Bright to faint, then around again
PULSE_SHADE = (1.0, 0.85, 0.6, 0.4)  # How much of the colour each step keeps (the rest fades to the background)

# Country centres (latitude, longitude), for placing a ransomware victim's country code
COUNTRIES: Dict[str, Tuple[float, float]] = {
    "US": (39, -98), "CA": (56, -106), "MX": (23, -102), "BR": (-10, -52), "AR": (-35, -65), "CL": (-33, -71),
    "CO": (4, -73), "PE": (-10, -76), "VE": (7, -66), "EC": (-1, -78), "UY": (-33, -56), "PY": (-23, -58),
    "BO": (-17, -65), "CR": (10, -84), "PA": (9, -80), "GT": (15, -90), "HN": (15, -87), "DO": (19, -70),
    "CU": (22, -79), "PR": (18, -66), "JM": (18, -77), "GB": (54, -2), "IE": (53, -8), "FR": (46, 2),
    "DE": (51, 10), "IT": (42, 12), "ES": (40, -4), "PT": (39, -8), "NL": (52, 5), "BE": (51, 4),
    "LU": (50, 6), "CH": (47, 8), "AT": (47, 14), "SE": (62, 15), "NO": (62, 9), "DK": (56, 10),
    "FI": (64, 26), "IS": (65, -18), "PL": (52, 19), "CZ": (49, 15), "SK": (49, 19), "HU": (47, 19),
    "RO": (46, 25), "BG": (43, 25), "GR": (39, 22), "HR": (45, 16), "RS": (44, 21), "SI": (46, 15),
    "BA": (44, 18), "AL": (41, 20), "MK": (41, 22), "EE": (59, 25), "LV": (57, 25), "LT": (55, 24),
    "BY": (53, 28), "UA": (49, 32), "MD": (47, 29), "RU": (60, 90), "TR": (39, 35), "CY": (35, 33),
    "MT": (36, 14), "GE": (42, 43), "AM": (40, 45), "AZ": (40, 48), "KZ": (48, 68), "UZ": (41, 64),
    "IL": (31, 35), "JO": (31, 36), "LB": (34, 36), "SA": (24, 45), "AE": (24, 54), "QA": (25, 51),
    "KW": (29, 48), "BH": (26, 50), "OM": (21, 57), "IQ": (33, 44), "IR": (32, 53), "SY": (35, 38),
    "YE": (15, 48), "EG": (27, 30), "LY": (27, 17), "TN": (34, 9), "DZ": (28, 3), "MA": (32, -6),
    "NG": (9, 8), "GH": (8, -1), "KE": (0, 38), "ET": (9, 40), "TZ": (-6, 35), "UG": (1, 32),
    "ZA": (-29, 24), "ZW": (-19, 30), "ZM": (-13, 28), "BW": (-22, 24), "NA": (-22, 17), "AO": (-12, 18),
    "SN": (14, -14), "CI": (7, -5), "CM": (6, 12), "CD": (-3, 23), "MU": (-20, 57), "IN": (22, 79),
    "PK": (30, 70), "BD": (24, 90), "LK": (7, 81), "NP": (28, 84), "CN": (35, 104), "HK": (22, 114),
    "TW": (24, 121), "JP": (36, 138), "KR": (36, 128), "MN": (47, 105), "TH": (15, 101), "VN": (16, 108),
    "MY": (4, 102), "SG": (1, 104), "ID": (-2, 118), "PH": (13, 122), "KH": (12, 105), "MM": (21, 96),
    "AU": (-25, 134), "NZ": (-41, 173), "PG": (-6, 147), "FJ": (-18, 178), "KP": (40, 127),
}

# Where each status-page service lives, since an outage has no single place on the map
SERVICE_HOMES: Dict[str, Tuple[str, float, float]] = {
    "aws": ("N. Virginia", 38.9, -77.4), "azure": ("Redmond", 47.6, -122.1),
    "google cloud": ("Mountain View", 37.4, -122.1), "google workspace": ("Mountain View", 37.4, -122.1),
    "cloudflare": ("San Francisco", 37.8, -122.4), "github": ("San Francisco", 37.8, -122.4),
    "slack": ("San Francisco", 37.8, -122.4), "discord": ("San Francisco", 37.8, -122.4),
    "openai": ("San Francisco", 37.8, -122.4), "zoom": ("San Jose", 37.3, -121.9),
}


# Nation-state attribution in headlines: the country named (or the country a well-known group works for)
ORIGIN_PATTERNS: Dict[str, "re.Pattern"] = {code: re.compile(pattern, re.IGNORECASE) for code, pattern in {
    "CN": r"\b(china|chinese|prc|beijing|apt ?(1|3|10|27|31|40|41)|volt typhoon|salt typhoon|flax typhoon|mustang panda)\b",
    "RU": r"\b(russia\w*|moscow|kremlin|gru|fsb|svr|apt ?(28|29)|fancy bear|cozy bear|sandworm|turla|midnight blizzard|forest blizzard)\b",
    "KP": r"\b(north korea\w*|dprk|pyongyang|lazarus|kimsuky|apt ?(37|38)|andariel)\b",
    "IR": r"\b(iran\w*|tehran|irgc|muddywater|oilrig|charming kitten|apt ?(33|34|35))\b",
}.items()}

# Which country an advisory source speaks for (matched at the start of the feed's name)
SOURCE_COUNTRIES: Dict[str, str] = {
    "cisa": "US", "us-cert": "US", "nist": "US", "ncsc uk": "GB", "cyber.gc.ca": "CA", "jpcert": "JP",
    "cert-eu": "BE", "enisa": "GR", "cert-fr": "FR", "anssi": "FR", "bsi": "DE", "cert-bund": "DE",
    "ncsc-nl": "NL", "ncsc nl": "NL", "cert nz": "NZ", "cert-nz": "NZ", "krcert": "KR", "cert-in": "IN",
    "singcert": "SG", "csa singapore": "SG", "incibe": "ES", "acn": "IT",
}

# What a marker is called in the legend, its glyph, and which palette role colours it. Earlier entries are drawn first.
LAYERS = (
    ("outage", "◆", "Active outages", "warn"),
    ("victim", "●", "Ransomware victims", "ransomware"),
    ("actor", "▲", "Attributed activity", "apt"),
    ("advisory", "■", "National advisories", "info"),
)
PRIORITY = {name: i for i, (name, *_rest) in enumerate(LAYERS)}


@dataclass
class Spot:
    lat: float
    lon: float
    kind: str          # "victim", "outage", "actor" (attributed to this country) or "advisory"
    label: str         # "US" or "Cloudflare, GitHub"
    count: int = 1


def is_land(row: int, col: int) -> bool:
    if not (0 <= row < DOTS_HIGH and 0 <= col < DOTS_WIDE):
        return False
    i = row * DOTS_WIDE + col
    return bool(_MASK[i >> 3] >> (7 - (i & 7)) & 1)


def fit(width: int, height: int) -> Tuple[int, int]:
    """(columns, rows) of the biggest map that fits: it needs 5 columns for every row to keep its shape"""
    rows = max(MIN_ROWS, min(height, width // 5))
    return rows * 5, rows


def _blend(color: str, ground: str, keep: float) -> str:
    c = [int(color[i:i + 2], 16) for i in (1, 3, 5)]
    g = [int(ground[i:i + 2], 16) for i in (1, 3, 5)]
    return "#" + "".join(f"{round(g[i] + (c[i] - g[i]) * keep):02x}" for i in range(3))


def _cell_dots(cols: int, rows: int) -> List[List[Tuple[int, bool]]]:
    """For each cell: (braille bits, touches the coast). A dot is land if any mask dot it covers is land."""
    sx, sy = DOTS_WIDE / (cols * 2), DOTS_HIGH / (rows * 4)
    bits = ((0, 0, 0x01), (0, 1, 0x02), (0, 2, 0x04), (1, 0, 0x08), (1, 1, 0x10), (1, 2, 0x20), (0, 3, 0x40), (1, 3, 0x80))
    grid = []
    for r in range(rows):
        line = []
        for c in range(cols):
            value, coast = 0, False
            for dx, dy, bit in bits:
                x0, y0 = int((c * 2 + dx) * sx), int((r * 4 + dy) * sy)
                x1, y1 = max(x0 + 1, int((c * 2 + dx + 1) * sx)), max(y0 + 1, int((r * 4 + dy + 1) * sy))
                covered = [(y, x) for y in range(y0, min(y1, DOTS_HIGH)) for x in range(x0, min(x1, DOTS_WIDE))]
                if any(is_land(y, x) for y, x in covered):
                    value |= bit
                    coast = coast or not all(is_land(y, x) for y, x in covered) or not all(
                        is_land(y + a, x + b) for y, x in covered[:1] for a, b in ((1, 0), (-1, 0), (0, 1), (0, -1)))
            line.append((value, coast))
        grid.append(line)
    return grid


_grid_cache: Dict[Tuple[int, int], List[List[Tuple[int, bool]]]] = {}


def cell_of(spot: Spot, cols: int, rows: int) -> Optional[Tuple[int, int]]:
    if not (LAT_BOTTOM <= spot.lat <= LAT_TOP):
        return None
    col = int((spot.lon + 180) / 360 * cols)
    row = int((LAT_TOP - spot.lat) / (LAT_TOP - LAT_BOTTOM) * rows)
    return min(row, rows - 1), min(max(col, 0), cols - 1)


def render(cols: int, rows: int, spots: List[Spot], step: int, palette) -> Text:
    """The map as styled text. `step` counts pulse steps; each spot is out of step with the others."""
    if (cols, rows) not in _grid_cache:
        _grid_cache.clear()
        _grid_cache[(cols, rows)] = _cell_dots(cols, rows)
    grid = _grid_cache[(cols, rows)]
    # A slow radar sweep brightens the land in a band that moves across the map, one pass every ~50 steps
    sweep = (step % (cols + 14)) - 7
    cells = []
    for line in grid:
        row = []
        for c, (v, coast) in enumerate(line):
            glow = max(0.0, 1 - abs(c - sweep) / 6)
            keep = (0.7 + 0.3 * glow) if coast else (0.38 + 0.55 * glow)
            row.append((chr(0x2800 + v) if v else " ", _blend(palette.accent, palette.bg, keep)))
        cells.append(row)
    placed: Dict[Tuple[int, int], Spot] = {}
    nudges = ((0, 1), (0, -1), (1, 0), (-1, 0), (1, 1), (-1, -1), (1, -1), (-1, 1))
    for spot in sorted(spots, key=lambda s: (PRIORITY.get(s.kind, 9), -s.count)):  # Outages first, then busiest
        cell = cell_of(spot, cols, rows)
        if not cell:
            continue
        for dr, dc in ((0, 0), *nudges):  # A shared cell is nudged to a free neighbour so every layer shows
            r, c = cell[0] + dr, cell[1] + dc
            if 0 <= r < rows and 0 <= c < cols and (r, c) not in placed:
                placed[(r, c)] = spot
                break
    roles = {name: role for name, _glyph, _label, role in LAYERS}
    for (r, c), spot in placed.items():
        color = getattr(palette, roles[spot.kind])
        phase = (step + r * 3 + c) % len(PULSE)
        if spot.kind == "victim":
            glyph, keep = PULSE[phase], PULSE_SHADE[phase]
        elif spot.kind == "actor":
            glyph, keep = ("▲" if phase < 2 else "△"), 1.0
        else:
            glyph, keep = ("◆" if spot.kind == "outage" else "■"), 1.0
        cells[r][c] = (glyph, _blend(color, palette.bg, keep))
    # Labels for the busiest few: to the right of the marker, else the left, else a row above or below
    taken = set(placed)
    labelled = [kv for kv in placed.items() if kv[1].kind != "advisory"]
    for (r, c), spot in sorted(labelled, key=lambda kv: -kv[1].count)[:10 if cols >= MIN_LABEL_COLS else 0]:
        text = spot.label.split(",")[0][:12] + (f" {spot.count}" if spot.kind in ("victim", "actor") and spot.count > 1 else "")
        for row, start in ((r, c + 2), (r, c - 1 - len(text)), (r - 1, c + 2), (r + 1, c + 2)):
            span = [(row, x) for x in range(start - 1, start + len(text) + 1)]
            if 0 <= row < rows and start >= 0 and start + len(text) <= cols and not any(cell in taken for cell in span):
                for i, ch in enumerate(text):
                    cells[row][start + i] = (ch, palette.text)
                taken.update(span)
                break
    out = Text(no_wrap=True)
    for r, line in enumerate(cells):
        for glyph, color in line:
            out.append(glyph, style=color)
        if r < rows - 1:
            out.append("\n")
    return out


def gather_spots(alerts: List[dict], now, days: int = 7) -> List[Spot]:
    """Markers for the last few days, in four layers: ransomware victims by country, active outages by
    service home, attributed activity by the country named in a headline, and advisories by issuing country"""
    from collections import Counter
    from datetime import timedelta

    from .panel_dashboard import RANSOM_VICTIM_RE

    cutoff = now - timedelta(days=days)
    victims, actors, advisories = Counter(), Counter(), Counter()
    outages: Dict[str, Tuple[float, float, List[str]]] = {}
    for alert in alerts:
        if alert["ts"] < cutoff:
            continue
        if alert.get("kind") == "outage":
            if alert.get("resolved"):
                continue
            service = alert["source"].removesuffix(" Status")
            home = SERVICE_HOMES.get(service.lower())
            if home:
                place, lat, lon = home
                names = outages.setdefault(place, (lat, lon, []))[2]
                if service not in names:
                    names.append(service)
            continue
        match = RANSOM_VICTIM_RE.match(alert["title"])
        if match:
            if match.group(2) in COUNTRIES:
                victims[match.group(2)] += 1
            continue
        if alert.get("severity") == "apt":
            for code, pattern in ORIGIN_PATTERNS.items():
                if pattern.search(alert["title"]):
                    actors[code] += 1
                    break
        source = alert.get("source", "").lower()
        code = next((c for prefix, c in SOURCE_COUNTRIES.items() if source.startswith(prefix)), None)
        if code in COUNTRIES:
            advisories[code] += 1
    spots = [Spot(*COUNTRIES[code], "victim", code, n) for code, n in victims.items()]
    spots += [Spot(*COUNTRIES[code], "actor", code, n) for code, n in actors.items()]
    spots += [Spot(*COUNTRIES[code], "advisory", code, n) for code, n in advisories.items()]
    spots += [Spot(lat, lon, "outage", ", ".join(names), len(names)) for lat, lon, names in outages.values()]
    return spots


def _top(spots: List[Spot], n: int) -> str:
    from .panel_dashboard import COUNTRY_NAMES
    names = {"CN": "China", "RU": "Russia", "KP": "North Korea", "IR": "Iran", "BE": "EU (CERT-EU)", "GR": "EU (ENISA)"}
    ranked = sorted(spots, key=lambda s: -s.count)[:n]
    return " · ".join(f"{names.get(s.label) or COUNTRY_NAMES.get(s.label, s.label)} {s.count}" for s in ranked)


def legend(spots: List[Spot], palette, top: int = 3, width: int = 80) -> List[Text]:
    """One line per layer under the map: its marker, total and the busiest places, clipped to the width"""
    lines = []
    for name, glyph, label, role in LAYERS:
        layer = [s for s in spots if s.kind == name]
        total = sum(s.count for s in layer)
        line = Text()
        line.append(f"{glyph} ", style=getattr(palette, role))
        line.append(f"{label}  {total}", style=palette.text)
        if name == "outage" and layer:
            detail = "; ".join(s.label for s in layer)
        else:
            detail = _top(layer, top if width >= 70 else max(1, top - 1)) if layer else ""
        if detail:
            line.append("   " + detail, style=palette.muted)
        if line.cell_len > width:
            line.truncate(width - 1, overflow="ellipsis")
        lines.append(line)
    note = "Outages sit at the service's home" if width < 70 else "Outage markers sit at the service's home; advisories at the country that issues them"
    lines.append(Text(note[:width], style=palette.muted))
    return lines
