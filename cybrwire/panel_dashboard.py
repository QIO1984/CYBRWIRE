"""The dashboard panel and the feed status panel.

These are methods of the app, kept here so each panel lives in its own file."""

import io
import re
from collections import Counter
from datetime import datetime, timedelta, timezone

from rich import box
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from . import cve_intel, evidence
from .feeds import KEV_CATALOG
from .incidents import CVE_RE, age

RANSOM_VICTIM_RE = re.compile(r"^RANSOMWARE VICTIM: .* \(([^)]+)\)(?: \[([A-Z]{2})\])?")
COUNTRY_NAMES = {
    "US": "United States", "CA": "Canada", "GB": "United Kingdom", "DE": "Germany", "FR": "France",
    "IT": "Italy", "ES": "Spain", "NL": "Netherlands", "BE": "Belgium", "CH": "Switzerland", "AT": "Austria",
    "AU": "Australia", "BR": "Brazil", "MX": "Mexico", "IN": "India", "JP": "Japan", "KR": "South Korea",
    "TW": "Taiwan", "CN": "China", "SG": "Singapore", "ZA": "South Africa", "SE": "Sweden", "PL": "Poland",
}


class DashboardMixin:
    def make_dashboard(self):
        """Create dashboard panel with all metrics"""
        p = self.palette
        now = datetime.now(timezone.utc)
        cutoff_time = now - timedelta(hours=self.recency_hours)
        
        source_filtered_queue = self.all_alerts
        window_alerts = [a for a in source_filtered_queue if a["ts"] >= cutoff_time]
        # Undated items (IP/URL lists, some blogs) are re-stamped on every fetch, so they
        # don't count as "incoming"
        dated_alerts = [a for a in source_filtered_queue if not a.get("undated")]
        
        # Blocklist rows are lookups, not events: a thousand listed IPs say nothing about
        # exploitation, so threat counts and meters only read stories
        stories = [a for a in window_alerts if a.get("kind") != "indicators"]
        counts = Counter(a["severity"] for a in stories)
        critical_count, zeroday_count = counts["critical"], counts["zeroday"]
        ransomware_count, apt_count, exploit_count = counts["ransomware"], counts["apt"], counts["exploit"]
        filtered_count = len(window_alerts)
        new_count = sum(1 for a in dated_alerts if now - a["ts"] < timedelta(hours=1))
        ioc_count = sum(1 for a in window_alerts if a.get("kind") == "indicators")
        tiers = Counter(a["evidence"].tier for a in window_alerts if a.get("evidence"))
        
        # --- Metrics (left) and source mix (right) ---
        metrics_list = [
            ("Items Seen", filtered_count, p.text),
            ("Alerts", sum(1 for a in stories if self.is_alert(a)), p.text),
            ("Confirmed", tiers[evidence.CONFIRMED], p.critical),
            ("Likely", tiers[evidence.LIKELY], p.exploit),
            ("Reported", tiers[evidence.REPORTED], p.zeroday),
            ("Ransomware", ransomware_count, p.ransomware),
            ("Exploits", exploit_count, p.exploit),
            ("IOCs Listed", ioc_count, p.text),
            ("Incoming (1h)", new_count, p.text),
        ]
        # Which feed sets are loaded: curated (vetted) vs custom and community contributions
        source_counts = Counter(a.get("source_file", "curated") for a in window_alerts)
        total_sources = sum(source_counts.values()) or 1
        sources_right = [Text("SOURCES", style=f"bold {p.accent}")]
        panel_width = self.query_one("#dashboard").size.width - 4
        meter_width = max(3, min(12, panel_width - self.METRICS_WIDTH - 9))  # 9: table padding and " 100%"
        for key, label in (("curated", "Curated"), ("custom", "Custom"), ("community", "Community")):
            n = source_counts.get(key, 0)
            line = Text(f"{label} ", style=p.text if n else p.muted)
            line.append(str(n), style=p.muted)
            sources_right.append(line)
            meter = self.bar(n / total_sources * 100, p.accent if n else p.muted, width=meter_width)
            meter.append(f" {int(n / total_sources * 100)}%", style=p.muted)
            sources_right.append(meter)
        
        # The labels and counts get a fixed width, so a narrow panel shrinks the meters instead of hiding the numbers
        metrics_table = Table(show_header=False, box=None, expand=True, padding=(0, 1))
        metrics_table.add_column(no_wrap=True, width=self.METRICS_WIDTH)
        metrics_table.add_column(no_wrap=True, ratio=1)
        for i in range(max(len(metrics_list), len(sources_right))):
            left = Text()
            if i < len(metrics_list):
                label, value, color = metrics_list[i]
                left.append(f"{label:<13} ", style=p.muted)
                left.append(str(value), style=f"bold {color}" if value not in (0, "0/hr") else p.muted)
            metrics_table.add_row(left, sources_right[i] if i < len(sources_right) else Text(""))
        
        # --- Heat meters ---
        def pct_of(n):
            return n / len(stories) * 100 if stories else 0

        def pct_text(n):
            """One zero-day among hundreds of items must not read as none"""
            pct = pct_of(n)
            return "<1%" if 0 < pct < 1 else f"{int(pct)}%"
        total_threats = critical_count + zeroday_count + ransomware_count + apt_count + exploit_count
        heat_pct = pct_of(total_threats)
        # Weighted score: zero-days 5x, critical/KEV 4x, ransomware & APT 3x, exploits 2x
        weighted = critical_count * 4 + zeroday_count * 5 + (ransomware_count + apt_count) * 3 + exploit_count * 2
        master_pct = min(100, weighted / (len(stories) * 17) * 100) if stories else 0
        defcon = 5 if master_pct < 20 else 4 if master_pct < 40 else 3 if master_pct < 60 else 2 if master_pct < 80 else 1
        last_zeroday_time = max((a["ts"] for a in window_alerts if a["severity"] == "zeroday"), default=None)
        time_since_zeroday = f"{age(last_zeroday_time)} ago" if last_zeroday_time else "none in window"
        # 0% at the farthest setting ever (17 minutes, 1991), 100% at midnight
        doomsday_pct = max(0, min(100, (1 - self.doomsday_seconds / 1020) * 100))
        
        meters = [
            ("Heat Level", f"{int(heat_pct)}%", heat_pct, p.level(heat_pct)),
            ("Ransomware", pct_text(ransomware_count), pct_of(ransomware_count), p.ransomware),
            ("APT", pct_text(apt_count), pct_of(apt_count), p.apt),
            ("Zero-Day", pct_text(zeroday_count), pct_of(zeroday_count), p.zeroday),
            ("Exploit", pct_text(exploit_count), pct_of(exploit_count), p.exploit),
            ("Doomsday", f"{self.doomsday_seconds}s", doomsday_pct, p.bad),
            (f"DEFCON {defcon}", f"{int(master_pct)}%", master_pct, p.level(master_pct)),
        ]
        try:
            inner_width = self.query_one("#dashboard").size.width - 4
        except Exception:
            inner_width = 44
        # One line per meter: label, bar, value
        bar_width = max(8, inner_width - 11 - 6)
        lines = [Text("")]
        for label, value, pct, color in meters:
            row = Text(f"{label:<11}", style=f"bold {p.text}")
            row.append_text(self.bar(pct, color, width=bar_width))
            row.append(f" {value:>4}", style=p.muted)
            lines.append(row)
        
        # --- Recent breaches (HIBP) ---
        lines.append(Text(""))
        lines.append(Text("RECENT BREACHES", style=f"bold {p.accent}"))
        self.breach_urls = []
        for breach in self.recent_breaches:
            name = breach.get("Title", "Unknown")
            name = name if len(name) <= 20 else name[:19] + "…"
            count = breach.get("PwnCount", 0)
            count_str = f"{count / 1e6:.1f}M" if count >= 1e6 else f"{count / 1e3:.0f}K" if count >= 1e3 else str(count)
            self.breach_urls.append(f"https://haveibeenpwned.com/?q={name.replace(' ', '+')}")
            row = Text(f"{name:<21}", style=p.text)
            row.append(f"{breach.get('AddedDate', '')[5:10]:<6}", style=p.muted)
            row.append(f"{count_str:>7}", style=p.accent)
            lines.append(row)
        if not self.recent_breaches:
            lines.append(Text("Fetching breach data...", style=p.muted))
        
        # --- Insights ---
        insights = []
        if total_threats:
            name, _ = max({"Ransomware": ransomware_count, "APT": apt_count, "Zero-Day": zeroday_count,
                           "Exploitation": exploit_count, "Critical": critical_count}.items(), key=lambda x: x[1])
            color = {"Ransomware": p.ransomware, "APT": p.apt, "Zero-Day": p.zeroday,
                     "Exploitation": p.exploit, "Critical": p.critical}[name]
            insights.append(("Dominant threat", f"{name} wave", color))
        insights.append(("Last zero-day", time_since_zeroday, p.zeroday if last_zeroday_time else p.muted))
        
        # Item velocity - items published in the last 24h vs the 24h before. Each feed only
        # keeps its newest items, so only count feeds whose history reaches back 48h;
        # otherwise busy feeds make every day look like a spike.
        oldest = {}
        for a in dated_alerts:
            oldest[a["source"]] = min(oldest.get(a["source"], a["ts"]), a["ts"])
        covered = [a for a in dated_alerts if oldest[a["source"]] <= now - timedelta(hours=48)]
        last_day = sum(1 for a in covered if a["ts"] > now - timedelta(hours=24))
        prev_day = sum(1 for a in covered if now - timedelta(hours=48) < a["ts"] <= now - timedelta(hours=24))
        if prev_day:
            ratio = last_day / prev_day
            status, color = (("Spiking", p.bad) if ratio > 1.5 else ("Increasing", p.warn) if ratio > 1.2
                             else ("Cooling", p.good) if ratio < 0.7 else ("Steady", p.text))
            insights.append(("Item velocity", f"{status} ({last_day} vs {prev_day} prior day)", color))
        else:
            insights.append(("Item velocity", "not enough history", p.muted))
        
        vectors = Counter()
        for alert in stories:
            title_lower = alert["title"].lower()
            vectors.update(v for v in ("Malware", "Ransomware", "Web", "Exploit", "Phishing", "Email") if v.lower() in title_lower)
        if vectors:
            vector, n = vectors.most_common(1)[0]
            insights.append(("Primary vector", f"{vector} ({pct_text(n)})", p.text))
        
        victims = [m for m in (RANSOM_VICTIM_RE.match(a["title"]) for a in window_alerts
                               if a["title"].startswith("RANSOMWARE VICTIM")) if m]
        if victims:
            countries = Counter(m.group(2) for m in victims if m.group(2))
            if countries:
                code, n = countries.most_common(1)[0]
                insights.append(("Ransom hotspot", f"{COUNTRY_NAMES.get(code, code)} ({n} of {len(victims)} victims)", p.ransomware))
            group, n = Counter(m.group(1) for m in victims).most_common(1)[0]
            insights.append(("Top group", f"{group.upper()} ({n} victims)", p.ransomware))
        
        insight_grid = Table.grid(expand=True, padding=(0, 1))
        insight_grid.add_column(no_wrap=True, style=p.muted)
        insight_grid.add_column(ratio=1)
        for label, value, color in insights:
            insight_grid.add_row(label, Text(value, style=f"bold {color}"))
        
        # --- Activity: dated alerts per hour over the last 24h, oldest on the left ---
        hourly = [0] * 24
        for a in dated_alerts:
            hours_ago = int((now - a["ts"]).total_seconds() // 3600)
            if 0 <= hours_ago < 24:
                hourly[23 - hours_ago] += 1
        peak = max(hourly) or 1
        blocks = "▁▂▃▄▅▆▇█"
        spark = Text()
        for n in hourly:
            # Quiet hours stay visible as a muted baseline
            spark.append(blocks[max(1, min(7, round(n / peak * 7)))] if n else blocks[0], style=p.accent if n else p.border)
        activity = [Text("ACTIVITY", style=f"bold {p.accent}") + Text(f"  last 24h · peak {peak}/hr", style=p.muted),
                    Text("24h ", style=p.muted) + spark + Text(" now", style=p.muted)]
        
        # --- Top CVEs: most independent sources in the window, KEV first on ties ---
        cve_sources = {}
        for a in window_alerts:
            for cve in set(m.upper() for m in CVE_RE.findall(f"{a['title']} {a['summary']}")):
                cve_sources.setdefault(cve, set()).add(a["source"])
        top_cves = sorted(cve_sources.items(), key=lambda kv: (-len(kv[1]), kv[0] not in KEV_CATALOG, kv[0]))[:3]
        cve_lines = [Text("TOP CVEs", style=f"bold {p.accent}") + Text("  by number of sources", style=p.muted)]
        for cve, sources in top_cves:
            row = Text(f"{cve:<17}", style=p.text)
            row.append(" KEV " if cve in KEV_CATALOG else "     ", style=f"bold {p.bg} on {p.bad}" if cve in KEV_CATALOG else "")
            row.append(f" {len(sources)} src", style=p.muted)
            if cve in cve_intel.EPSS:
                prob = cve_intel.EPSS[cve][0] * 100
                row.append(f"  EPSS {prob:.0f}%" if prob >= 10 else f"  EPSS {prob:.1f}%",
                           style=p.bad if prob >= 10 else p.warn if prob >= 1 else p.muted)
            cve_lines.append(row)
        if not top_cves:
            cve_lines.append(Text("No CVEs mentioned in this window", style=p.muted))
        
        # Sections in display order; when space is short, drop the lowest priority first
        breaches_start = lines.index(next(l for l in lines if l.plain == "RECENT BREACHES")) - 1
        sections = [
            ("metrics", [metrics_table], 0),
            ("meters", lines[:breaches_start], 0),
            ("breaches", lines[breaches_start:], 3),
            ("insights", [Text(""), insight_grid], 2),
            ("activity", [Text(""), *activity], 1),
            ("cves", [Text(""), *cve_lines], 1),
        ]
        try:
            available = self.query_one("#dashboard").size.height - 2
            measure = Console(width=max(20, self.query_one("#dashboard").size.width - 4), file=io.StringIO())
            heights = {name: len(measure.render_lines(Group(*parts), pad=False)) for name, parts, _ in sections}
            for name, _, priority in sorted(sections, key=lambda s: -s[2]):
                if priority == 0 or sum(heights[n] for n, _, _ in sections) <= available:
                    break
                sections = [sec for sec in sections if sec[0] != name]
        except Exception:
            pass  # Not mounted yet; render everything
        
        title, border = self.frame("WAR ROOM DASHBOARD", self.panel_focus == "dashboard")
        return Panel(Group(*(part for _, parts, _ in sections for part in parts)),
                     title=title, border_style=border, box=box.ROUNDED, padding=(0, 1))

    def make_feed_status_panel(self):
        """Failed and auto-disabled feeds, paginated"""
        p = self.palette
        total = len(self.app_config.sources)
        broken = len(self.failed_feed_map) + len(self.disabled_feed_map)
        body = [Text(f"{total - broken} of {total} feeds healthy", style=f"bold {p.good if not broken else p.text}"), Text("")]
        
        entries = [("failed", name, f"{msg}", f"{count}/7 failures") for name, (msg, count) in sorted(self.failed_feed_map.items())]
        entries += [("disabled", name, msg, reason) for name, (msg, reason) in sorted(self.disabled_feed_map.items())]
        per_page = 8
        total_pages = max(1, (len(entries) + per_page - 1) // per_page)
        self.feed_status_pages = total_pages
        self.dashboard_page_offset = max(0, min(self.dashboard_page_offset, total_pages - 1))
        section = None
        for kind, name, msg, detail in entries[self.dashboard_page_offset * per_page:(self.dashboard_page_offset + 1) * per_page]:
            if kind != section:
                section = kind
                heading = "FAILED THIS CYCLE" if kind == "failed" else "AUTO-DISABLED (press e to re-enable)"
                body.append(Text(heading, style=f"bold {p.warn if kind == 'failed' else p.bad}"))
            line = Text(f"{name}  ", style=p.text)
            line.append(detail, style=p.muted)
            body.append(line)
            body.append(Text(f"  {msg[:60]}", style=p.muted))
        
        title_str = "FEED STATUS" + (f" · page {self.dashboard_page_offset + 1}/{total_pages}" if total_pages > 1 else "")
        title, border = self.frame(title_str, self.panel_focus == "dashboard")
        hints = [("←→", "pages"), ("e", "re-enable")] if total_pages > 1 else [("e", "re-enable"), ("r", "refresh")]
        return Panel(Group(*body), title=title, subtitle=self.hint_bar(hints),
                     border_style=border, box=box.ROUNDED, padding=(1, 2))
