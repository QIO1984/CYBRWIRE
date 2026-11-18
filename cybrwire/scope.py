"""An oscilloscope-style trace of alerts per hour: braille dots joined into a line, with a bright
point sweeping along it and the trace fading behind the point."""

from datetime import datetime, timedelta
from typing import List

from rich.text import Text

from .worldmap import _blend

_BITS = ((0, 0, 0x01), (0, 1, 0x02), (0, 2, 0x04), (1, 0, 0x08), (1, 1, 0x10), (1, 2, 0x20), (0, 3, 0x40), (1, 3, 0x80))
HOURS = 24


def hourly_counts(alerts, now: datetime, hours: int = HOURS) -> List[int]:
    """Alerts per hour for the last `hours` hours, oldest first"""
    counts = [0] * hours
    for alert in alerts:
        ago = int((now - alert["ts"]) / timedelta(hours=1))
        if 0 <= ago < hours:
            counts[hours - 1 - ago] += 1
    return counts


def trace(counts: List[int], width: int, rows: int) -> List[int]:
    """One dot height per dot column (0 = top), interpolated between the hourly counts"""
    columns = width * 2
    high = max(1, max(counts, default=1))
    heights = []
    for x in range(columns):
        pos = x / max(1, columns - 1) * (len(counts) - 1) if len(counts) > 1 else 0
        lo = int(pos)
        hi = min(lo + 1, len(counts) - 1)
        value = (counts[lo] + (counts[hi] - counts[lo]) * (pos - lo)) if counts else 0
        heights.append(round((1 - value / high) * (rows * 4 - 1)))
    return heights


def render(counts: List[int], width: int, rows: int, step: int, palette) -> List[Text]:
    """A heading line then `rows` lines of trace. `step` moves the sweep point along."""
    width = max(10, width)
    heights = trace(counts, width, rows)
    cells = [[0] * width for _ in range(rows)]
    for x, y in enumerate(heights):
        lo, hi = sorted((y, heights[x - 1] if x else y))  # Join this column to the previous one
        for dot_y in range(lo, hi + 1):
            cell_row, within = divmod(dot_y, 4)
            col, dx = divmod(x, 2)
            bit = next(b for ddx, ddy, b in _BITS if ddx == dx and ddy == within)
            cells[cell_row][col] |= bit
    sweep = step % width
    lines = []
    head = Text()
    head.append("ALERTS / HOUR", style=f"bold {palette.accent}")
    head.append(f"   last {len(counts)}h · peak {max(counts, default=0)}", style=palette.muted)
    lines.append(head)
    for r in range(rows):
        line = Text(no_wrap=True)
        for c in range(width):
            behind = (sweep - c) % width
            keep = 1.0 if behind < 3 else max(0.22, 1 - behind / (width * 0.7))
            bits = cells[r][c]
            point = c == sweep and bits
            if point:
                line.append("●", style=palette.focus)
            else:
                line.append(chr(0x2800 + bits) if bits else " ", style=_blend(palette.accent, palette.bg, keep))
        lines.append(line)
    return lines
