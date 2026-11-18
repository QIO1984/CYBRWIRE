"""The alert preview and the incident view.

These are methods of the app, kept here so each panel lives in its own file."""

import asyncio
import textwrap
from datetime import datetime, timedelta, timezone

from rich.text import Text
from textual.coordinate import Coordinate

from . import evidence
from .enrichment import enrichment_engine
from .feeds import KEV_CATALOG
from .incidents import KIND_LABELS, age, build_incidents
from .state import alert_key
from .widgets import ViewTable


class AlertViewsMixin:
    def make_alert_preview(self, alert):
        """Detail pane for the highlighted alert"""
        p = self.palette
        text = Text()
        if not alert:
            text.append("Nothing to preview.", style=p.muted)
            return text
        
        if alert.get("kind") == "indicators":
            text.append((alert.get("ioc") or alert["title"]) + "\n", style=f"bold {p.text}")
            when = "no date in feed (list refreshed each fetch)" if alert.get("undated") else f"{p.stamp(alert['ts'], long=True)} ({age(alert['ts'])} ago)"
            text.append(f" {(alert.get('ioc_type') or 'IOC').upper()} ", style=f"bold {p.bg} on {p.accent}")
            text.append(f"  {alert.get('threat') or ''}  •  {alert['source']}  •  {when}\n", style=p.muted)
            text.append(alert.get("summary", "") + "\n", style=p.text)
            if alert.get("url"):
                text.append(alert["url"] + "\n", style=f"underline {p.muted}")
            hints = [("Enter", "look up in API Tools")] if enrichment_engine.providers else []
            text.append_text(self.hint_bar(hints) if hints else Text("Add enrichment API keys to look indicators up", style=p.muted))
            return text
        
        text.append(alert["title"] + "\n", style=f"bold {p.text}")
        when = "no publish date in feed" if alert.get("undated") else f"{p.stamp(alert['ts'], long=True)} ({age(alert['ts'])} ago)"
        sev = alert["severity"]
        label = p.severity_name(sev)
        if label != sev.upper():
            label += f" · {sev.upper()}"  # e.g. FLASH · ZERODAY
        text.append(f" {label} " if sev in ("critical", "zeroday") else label, style=p.badge(sev))
        ev = alert.get("evidence")
        if ev:
            text.append(f"  {ev.tier}", style=f"bold {p.severity(sev)}")
        text.append(f"  {alert['source']}  •  {when}", style=p.muted)
        if self.app_state.is_new(alert):
            text.append("  ")
            text.append(" NEW ", style=f"bold {p.bg} on {p.accent}")
        hits = self.watchlist.hits(alert)
        if hits:
            text.append(f"  ★ {', '.join(hits)}", style=f"bold {p.warn}")
        if alert.get("archived"):
            text.append("  from history", style=f"italic {p.muted}")
        text.append("\n")
        others = self.duplicate_groups().others.get(alert_key(alert), []) if self.group_dupes else []
        if others:
            text.append("Also reported by ", style=f"bold {p.accent}")
            text.append(", ".join(dict.fromkeys(a["source"] for a in others)) + "\n", style=p.muted)
        if ev:
            text.append("Why  ", style=f"bold {p.accent}")
            text.append(" · ".join(ev.reasons) + "\n", style=p.text)
            if ev.action:
                text.append("Do   ", style=f"bold {p.accent}")
                due = evidence.due_text(ev, datetime.now(timezone.utc))
                text.append(ev.action + (f" ({due})" if due else "") + "\n", style=p.text)
        
        all_cves = self.alert_cves(alert)
        cves = all_cves[:3]
        if cves:
            for i, cve in enumerate(cves):
                if i:
                    text.append("   ")
                text.append_text(self.cve_scores(cve))
            text.append("\n")
            missing = [c for c in cves if self.nvd.get(c) is None and c not in self.nvd.pending]
            if missing:
                asyncio.create_task(self._fetch_cvss(missing))
        
        key = alert_key(alert)
        if key in self.alert_explanations:
            text.append("AI  ", style=f"bold {p.accent}")
            text.append(self.alert_explanations[key].strip() + "\n", style=p.text)
        elif key in self.explaining:
            text.append("AI  analyzing...\n", style=f"italic {p.accent}")
        else:
            text.append((alert.get("summary") or "No summary provided by this feed.") + "\n", style=p.text)
        
        if alert.get("url"):
            text.append(alert["url"] + "\n", style=f"underline {p.muted}")
        hints = [("Enter", "open in browser")]
        if all_cves:
            hints.append(("i", "CVE card"))
        if not self.ai_problem and key not in self.alert_explanations:
            hints.append(("a", "explain with AI"))
        text.append_text(self.hint_bar(hints))
        text.truncate(max(self.size.width, 40) * self.PREVIEW_LINES)
        return text

    def current_incidents(self):
        """Incidents for the current window and feed source, rebuilt only when those change"""
        key = (id(self.all_alerts), self.recency_hours)
        if key != self.incidents_key:
            cutoff_time = datetime.now(timezone.utc) - timedelta(hours=self.recency_hours)
            alerts = [a for a in self.all_alerts if a["ts"] >= cutoff_time]
            self.incidents = build_incidents(alerts, KEV_CATALOG)
            self.incidents_key = key
        return self.incidents

    def incident_block(self, inc, incidents, width, now, selected):
        """Lines describing one incident"""
        p = self.palette
        
        def labeled(label, value, value_style=p.text):
            line = Text(f"    {label + ':':<9}", style=p.muted)
            line.append(value, style=value_style)
            line.truncate(width, overflow="ellipsis")
            return line
        
        lines = []
        header = Text()
        header.append("▶ " if selected else "  ", style=f"bold {p.accent}")
        # Incident headers get a filled badge; Cold War keeps reverse video for FLASH only
        badge_style = p.badge(inc.severity) if p.monochrome else f"bold {p.bg} on {p.severity(inc.severity)}"
        header.append(f" {p.severity_name(inc.severity)} ", style=badge_style)
        header.append(f"  {KIND_LABELS[inc.kind]} ", style=p.muted)
        header.append(inc.value, style=f"bold {p.accent if selected else p.text}" + (" underline" if selected else ""))
        if inc.kev:
            header.append("  KNOWN EXPLOITED", style=f"bold {p.bad}")
        if inc.kind == "cve":
            # Scores only (the CVE ID and KEV status are already in the header)
            header.append_text(self.cve_scores(inc.value, scores_only=True))
        n_src = len(inc.sources)
        header.append(f"   {n_src} source{'s' if n_src != 1 else ''} · {len(inc.alerts)} alerts · latest {age(inc.last_seen, now)} ago",
                      style=p.muted)
        lines.append(header)
        
        lines.append(Text(f"    {inc.headline}"[:width], style=f"bold {p.text}"))
        what_lines = textwrap.wrap(inc.what, width=width - 13, max_lines=3, placeholder=" ...")
        for i, line in enumerate(what_lines):
            lines.append(labeled("What", line) if i == 0 else Text(f"{'':13}{line}", style=p.text))
        lines.append(labeled("Why", inc.why))
        first = min(inc.alerts, key=lambda a: a["ts"])
        lines.append(labeled("When", f"first {age(inc.first_seen, now)} ago ({first['source']}) → "
                                     f"latest {age(inc.last_seen, now)} ago ({inc.timeline[0]['source']})"))
        related = inc.related(incidents)
        if related:
            lines.append(labeled("Related", ", ".join(related), p.accent))
        for a in inc.timeline[:2]:
            row = Text(f"{'':13}{age(a['ts'], now):>3}  ", style=p.muted)
            row.append(f"{a['source'][:22]:<23}", style=p.muted)
            row.append(a["title"], style=p.text)
            row.truncate(width, overflow="ellipsis")
            lines.append(row)
        lines.append(Text(""))
        return lines

    def incident_cell(self, inc, incidents, width, now, selected):
        return Text("\n", no_wrap=True, overflow="ellipsis").join(self.incident_block(inc, incidents, width, now, selected))

    def sync_incident_view(self):
        """Correlated incidents with the context needed to act on them"""
        now = datetime.now(timezone.utc)
        incidents = self.current_incidents()
        p = self.palette
        table = self.query_one("#incident-table", ViewTable)
        view = self.query_one("#incidents-view")
        width = table.size.width or max(40, self.size.width * 3 // 4 - 6)
        text_width = max(30, width - 3)  # Cell padding and the scrollbar
        self.incident_cell_args = (incidents, text_width, now)
        
        previous = self.selected_incident()
        old_row = table.cursor_row
        cells = [self.incident_cell(inc, incidents, text_width, now, False) for inc in incidents]
        if not cells:
            cells = [Text("\n").join([Text("No correlated incidents in this window.", style=f"bold {p.text}"),
                                      Text("An incident needs the same CVE, IP or hash reported by two or more sources,", style=p.muted),
                                      Text("or a named threat actor appearing in several alerts. Try a longer data age (d).", style=p.muted)])]
        signature = (p.key, text_width, tuple(c.plain for c in cells))
        self.incident_list = incidents
        keys = {inc.value: i for i, inc in enumerate(incidents)}
        row = keys.get(previous.value, old_row) if previous else old_row
        row = max(0, min(row, len(cells) - 1))
        if signature != self.incident_signature:
            self.incident_signature = signature
            self.incident_marked = None
            table.clear(columns=True)
            table.add_column("", width=text_width)
            for cell in cells:
                table.add_row(cell, height=None)  # As tall as the incident's text
        table.show_cursor = bool(incidents)
        table.move_cursor(row=row, animate=False)
        self.mark_selected_incident(row)
        
        status = Text(f" {len(incidents)} incidents from {len(self.filtered_alerts())} alerts   ", style=p.muted)
        status.append_text(self.hint_bar([("↑↓", "select"), ("Enter", "open latest report"), ("i", "CVE"), ("←→", "page")]))
        status.append(" ")
        title_text, border = self.frame("CORRELATED INCIDENTS", self.panel_focus == "main")
        view.border_title = title_text
        view.border_subtitle = status
        view.styles.border = ("round", border)

    def mark_selected_incident(self, row):
        """The selected incident gets the arrow and a brighter name"""
        if row == self.incident_marked or not self.incident_list or row >= len(self.incident_list):
            return
        table = self.query_one("#incident-table", ViewTable)
        incidents, width, now = self.incident_cell_args
        if self.incident_marked is not None and self.incident_marked < len(self.incident_list):
            table.update_cell_at(Coordinate(self.incident_marked, 0), self.incident_cell(self.incident_list[self.incident_marked], incidents, width, now, False))
        table.update_cell_at(Coordinate(row, 0), self.incident_cell(self.incident_list[row], incidents, width, now, True))
        self.incident_marked = row
