"""
Full-detail CVE card for CybrWire: severity, exploit likelihood and exploit
evidence for one CVE, opened with 'i' from an alert or incident.
"""

import textwrap
from .links import open_link
from typing import List

from rich.text import Text
from textual.app import ComposeResult
from textual.containers import VerticalScroll
from textual.containers import Horizontal

from .widgets import Card, CardButton
from textual.widgets import Static

from . import cve_intel
from .feeds import KEV_DETAILS
from .incidents import age

NVD_DETAIL_URL = "https://nvd.nist.gov/vuln/detail/"
MAX_MENTIONS = 8
CARD_WIDTH = 84  # Text wrap width: the CSS width less border, padding and scrollbar


def exploit_status(kev: dict, detail: dict) -> tuple:
    """(level, wording). NVD not tagging an exploit doesn't mean none exists, so say only what is known."""
    if kev:
        return "bad", f"KNOWN EXPLOITED - in the CISA KEV catalog since {kev.get('dateAdded', '?')}"
    if detail.get("exploit_refs"):
        return "warn", f"PUBLIC EXPLOIT REFERENCED - {detail['exploit_refs']} exploit link(s) on NVD"
    return "muted", "No known exploitation in CISA KEV and no exploit links on NVD"


class CveCard(Card):
    """One CVE at a time; left/right steps through the CVEs named in the alert"""

    DEFAULT_CSS = """
    CveCard { align: center middle; }
    #cve-buttons { height: 1; margin-top: 1; }
    #cve-card-scroll {
        width: 94; max-width: 100%; height: auto; max-height: 90%;
        padding: 1 2; border: round $primary; background: $background;
    }
    """

    BINDINGS = [
        ("escape", "close", "Close"),
        ("q", "close", "Close"),
        ("i", "close", "Close"),
        ("enter", "open_nvd", "Open on NVD"),
        ("x", "open_exploit", "Open exploit link"),
        ("left", "step(-1)", "Previous CVE"),
        ("right", "step(1)", "Next CVE"),
    ]

    def __init__(self, cves: List[str]):
        super().__init__()
        self.cves = cves
        self.index = 0

    @property
    def cve(self) -> str:
        return self.cves[self.index]

    def compose(self) -> ComposeResult:
        with VerticalScroll(id="cve-card-scroll"):
            yield Static(id="cve-card")
            with Horizontal(id="cve-buttons"):
                yield CardButton("◀ Prev", id="cve-prev")
                yield CardButton("Next ▶", id="cve-next")
                yield CardButton("Open on NVD", id="cve-nvd")
                yield CardButton("Exploit link", id="cve-exploit")
                yield CardButton("Close", id="cve-close")

    def on_mount(self) -> None:
        self.query_one("#cve-card-scroll").focus()
        self.load()

    def load(self) -> None:
        """Draw what's known now, then again once any lookups finish"""
        self.redraw()
        self.run_worker(self._fetch(self.cve))

    async def _fetch(self, cve: str) -> None:
        await self.app.fetch_cve_detail(cve)
        if cve == self.cve:
            self.redraw()

    def on_button_pressed(self, event) -> None:
        event.stop()
        actions = {"cve-prev": lambda: self.action_step(-1), "cve-next": lambda: self.action_step(1),
                   "cve-nvd": self.action_open_nvd, "cve-exploit": self.action_open_exploit, "cve-close": self.action_close}
        actions[event.button.id]()

    def redraw(self) -> None:
        self.query_one("#cve-card", Static).update(self.render_card())
        many = len(self.cves) > 1
        self.query_one("#cve-prev").display = many
        self.query_one("#cve-next").display = many
        detail = self.app.nvd.get(self.cve) or {}
        self.query_one("#cve-exploit").display = bool(detail.get("exploits"))
        self.query_one("#cve-card-scroll").border_subtitle = self.hints()

    def render_card(self) -> Text:
        app = self.app
        p = app.palette
        cve = self.cve
        detail = app.nvd.get(cve) or {}
        kev = KEV_DETAILS.get(cve) or {}
        looking_up = cve in app.nvd.pending or "description" not in detail
        text = Text()

        def heading(label):
            text.append(f"\n{label}\n", style=f"bold {p.accent}")

        def wrapped(value, style=p.text):
            text.append(textwrap.fill(value, CARD_WIDTH, break_long_words=False, break_on_hyphens=False) + "\n", style=style)

        text.append(cve, style=f"bold {p.text}")
        if kev:
            text.append("  ")
            text.append(" KEV ", style=f"bold {p.bg} on {p.bad}")
        if len(self.cves) > 1:
            text.append(f"   {self.index + 1} of {len(self.cves)}", style=p.muted)
        text.append("\n")

        # Severity
        heading("SEVERITY")
        score = detail.get("score")
        if score is not None:
            color = p.bad if score >= 9 else p.warn if score >= 7 else p.text
            text.append(f"CVSS {score:.1f}", style=f"bold {color}")
            if detail.get("severity"):
                text.append(f"  {detail['severity']}", style=f"bold {color}")
            text.append("\n")
            if detail.get("vector"):
                text.append(f"{detail['vector']}\n", style=p.muted)
        elif cve in app.nvd.failed:
            text.append("CVSS unavailable - the NVD lookup failed. Close and reopen to retry.\n", style=p.warn)
        elif looking_up:
            text.append("CVSS looking up on NVD... (free tier allows one request every few seconds)\n", style=p.muted)
        else:
            text.append("CVSS not yet scored by NVD\n", style=p.muted)

        # Likelihood
        if cve in cve_intel.EPSS:
            prob, percentile = cve_intel.EPSS[cve]
            pct = prob * 100
            text.append(f"EPSS {pct:.1f}%", style=f"bold {p.bad if pct >= 10 else p.warn if pct >= 1 else p.muted}")
            text.append(f"  chance of exploitation in 30 days; higher than {percentile * 100:.0f}% of CVEs\n", style=p.muted)
        else:
            text.append("EPSS no score available\n", style=p.muted)

        # Exploitation evidence
        heading("EXPLOITATION")
        level, wording = exploit_status(kev, detail)
        wrapped(wording, f"bold {getattr(p, level)}" if level != "muted" else p.muted)
        if kev:
            ransomware = kev.get("knownRansomwareCampaignUse")
            if ransomware == "Known":
                text.append("Used in ransomware campaigns\n", style=f"bold {p.bad}")
            if kev.get("dueDate"):
                text.append(f"Federal patch deadline {kev['dueDate']}\n", style=p.text)

        # What it is
        description = detail.get("description") or kev.get("shortDescription")
        heading("DESCRIPTION")
        if description:
            wrapped(description)
        elif looking_up and cve not in app.nvd.failed:
            text.append("Looking up...\n", style=p.muted)
        else:
            text.append("NVD has no description for this CVE yet.\n", style=p.muted)
        if detail.get("cwes"):
            text.append(", ".join(detail["cwes"]) + "\n", style=p.muted)
        if detail.get("published"):
            status = f" · {detail['status']}" if detail.get("status") else ""
            text.append(f"Published {detail['published'][:10]}{status}\n", style=p.muted)

        # What it affects
        affected = detail.get("affected") or []
        if kev and not affected:
            name = f"{kev.get('vendorProject', '')} {kev.get('product', '')}".strip()
            affected = [name] if name else []
        if affected:
            heading("AFFECTS")
            more = detail.get("affected_total", len(affected)) - len(affected)
            wrapped(", ".join(affected) + (f" and {more} more" if more > 0 else ""))

        # Long and often boilerplate, so it comes after the facts
        if kev.get("requiredAction"):
            heading("CISA REQUIRED ACTION")
            wrapped(kev["requiredAction"])

        # Who's reporting it
        mentions = app.alerts_mentioning(cve)
        heading(f"IN YOUR FEEDS ({len(mentions)})")
        if not mentions:
            text.append("Not in the currently loaded feed items\n", style=p.muted)
        for a in mentions[:MAX_MENTIONS]:
            text.append(f"{age(a['ts']):>4}  ", style=p.muted)
            text.append(f"{a['source']}: ", style=p.muted)
            text.append(f"{a['title'][:60]}\n", style=p.text)

        references = detail.get("references") or []
        if references:
            more = detail.get("references_total", len(references)) - len(references)
            heading(f"REFERENCES{f' (first {len(references)} of {len(references) + more})' if more > 0 else ''}")
            for r in references:
                if "Exploit" in r["tags"]:
                    text.append("EXPLOIT ", style=f"bold {p.warn}")
                text.append(r["url"] + "\n", style=f"underline {p.muted}")

        heading("DATA FROM")
        wrapped("Scores and details: NVD. This product uses the NVD API but is not endorsed or certified by the NVD.", p.muted)
        wrapped("Exploit likelihood: FIRST EPSS (first.org/epss). Exploited lists: CISA KEV, ENISA, CIRCL, Metasploit.", p.muted)

        return text

    def hints(self) -> str:
        """Key hints for the card border, where scrolling can't hide them"""
        hints = ["Enter NVD"]
        if self.exploit_url():
            hints.append("x exploit")
        if len(self.cves) > 1:
            hints.append("←→ CVEs")
        return " · ".join(hints + ["↑↓ scroll", "Esc close"])

    def exploit_url(self):
        detail = self.app.nvd.get(self.cve) or {}
        return next((r["url"] for r in detail.get("references") or [] if "Exploit" in r["tags"]), None)

    def action_close(self) -> None:
        self.dismiss()

    def action_open_nvd(self) -> None:
        open_link(self.app, NVD_DETAIL_URL + self.cve)

    def action_open_exploit(self) -> None:
        url = self.exploit_url()
        if url:
            open_link(self.app, url)

    def action_step(self, delta: int) -> None:
        if len(self.cves) > 1:
            self.index = (self.index + delta) % len(self.cves)
            self.query_one("#cve-card-scroll").scroll_home(animate=False)
            self.load()
