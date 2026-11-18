"""The War Room: AI briefing, alert explanations and the local keyword analysis.

These are methods of the app, kept here so each panel lives in its own file."""

import logging
from datetime import datetime, timedelta, timezone

from rich import box
from rich.console import Group
from rich.panel import Panel
from rich.text import Text

from . import ai
from .incidents import KIND_LABELS, SEVERITY_RANK, age
from .state import alert_key


class WarRoomMixin:
    def analyze_top_cves(self, alerts):
        """Extract and rank top 10 CVEs by frequency"""
        import re
        cve_counts = {}
        for alert in alerts:
            title = alert.get('title', '').upper()
            matches = re.findall(r'CVE-\d{4}-\d{4,5}', title)
            for cve in matches:
                cve_counts[cve] = cve_counts.get(cve, 0) + 1
        
        return sorted(cve_counts.items(), key=lambda x: x[1], reverse=True)[:10]

    def analyze_threat_actors(self, alerts):
        """Extract threat actor names from alert titles with improved accuracy"""
        import re
        threat_actors = {}
        
        # Real threat actor patterns with word boundaries to prevent false matches
        actor_patterns = [
            r'\bAPT\d+\b', r'\bFIN\d+\b', r'\bHAFNIUM\b', r'\bWIZARD SPIDER\b', 
            r'\bLAZARUS\b', r'\bCARBANAK\b', r'\bEMOTET\b', r'\bCONTI\b', r'\bLOCKBIT\b',
            r'\bBLACKCAT\b', r'\bALPHV\b', r'\bPLAY\b', r'\bCLOP\b', r'\bSCATTERED SPIDER\b',
            r'\bGAMAREDON\b', r'\bSANDWORM\b', r'\bFANCY BEAR\b', r'\bCOZY BEAR\b',
            r'\bTURLA\b', r'\bEQUATION GROUP\b'
        ]
        
        # Framework/taxonomy keywords to exclude (false positives)
        exclude_keywords = ['MITRE', 'TACTICS', 'TECHNIQUES', 'FRAMEWORK', 'MATRIX', 'ATT&CK']
        
        for alert in alerts:
            title = alert.get('title', '').upper()
            
            # Skip alerts that mention framework/taxonomy references
            if any(keyword in title for keyword in exclude_keywords):
                continue
            
            for pattern in actor_patterns:
                matches = re.findall(pattern, title, re.IGNORECASE)
                for match in matches:
                    actor_key = match.upper()
                    threat_actors[actor_key] = threat_actors.get(actor_key, 0) + 1
        
        return sorted(threat_actors.items(), key=lambda x: x[1], reverse=True)[:10]

    def analyze_attack_surface(self, alerts):
        """Parse alert titles for affected software/products"""
        software_keywords = {
            'Apache': ['APACHE', 'HTTP SERVER'],
            'Windows': ['WINDOWS', 'WIN32', 'SMB'],
            'Linux': ['LINUX', 'KERNEL'],
            'Exchange': ['EXCHANGE', 'OUTLOOK'],
            'Oracle': ['ORACLE', 'DATABASE'],
            'SQL Server': ['SQL SERVER', 'MSSQL'],
            'Adobe': ['ADOBE', 'PDF', 'ACROBAT'],
            'Chrome': ['CHROME', 'CHROMIUM'],
            'Firefox': ['FIREFOX', 'MOZILLA'],
            'SSH': ['SSH', 'OPENSSH'],
            'Kubernetes': ['KUBERNETES', 'K8S'],
            'Docker': ['DOCKER', 'CONTAINER'],
            'AWS': ['AWS', 'AMAZON'],
            'Azure': ['AZURE', 'MICROSOFT CLOUD'],
            'Jenkins': ['JENKINS', 'CI/CD'],
            'Nginx': ['NGINX', 'WEB SERVER'],
            'OpenSSL': ['OPENSSL', 'SSL/TLS'],
            'Java': ['JAVA', 'JVM'],
            'Python': ['PYTHON', 'PIP'],
            'Node.js': ['NODE', 'NODEJS'],
            'PHP': ['PHP', 'LARAVEL'],
            'WordPress': ['WORDPRESS', 'WP'],
            'Drupal': ['DRUPAL', 'CMS'],
            'Salesforce': ['SALESFORCE', 'CRMSYSTEM'],
            'SAP': ['SAP', 'ERP'],
            'Cisco': ['CISCO', 'NETWORKING'],
            'Fortinet': ['FORTINET', 'FORTIGATE'],
            'Palo Alto': ['PALO ALTO', 'FIREWALL'],
        }
        
        affected = {}
        for alert in alerts:
            title = alert.get('title', '').upper()
            for software, keywords in software_keywords.items():
                for keyword in keywords:
                    if keyword in title:
                        affected[software] = affected.get(software, 0) + 1
                        break
        
        return sorted(affected.items(), key=lambda x: x[1], reverse=True)[:15]

    def analyze_vulnerability_chains(self, alerts):
        """Detect potential CVE chains (multiple CVEs in 24h window)"""
        import re
        from collections import defaultdict
        
        chains = defaultdict(list)
        for alert in alerts:
            title = alert.get('title', '').upper()
            cves = re.findall(r'CVE-\d{4}-\d{4,5}', title)
            if len(cves) > 1:
                key = f"{len(cves)}-chain"
                chains[key].append((title[:60], cves))
        
        return list(chains.items())[:5]  # Top 5 chain types

    def analyze_exploit_maturity(self, alerts):
        """Track exploit progression from disclosure to weaponization"""
        maturity_stages = {
            'in-the-wild': [],
            'poc-available': [],
            'exploited': [],
            'active': [],
        }
        
        for alert in alerts:
            title = alert.get('title', '').upper()
            summary = alert.get('summary', '').upper()
            combined = f"{title} {summary}"
            
            if any(x in combined for x in ['IN-THE-WILD', 'IN THE WILD', 'WILD EXPLOITATION']):
                maturity_stages['in-the-wild'].append(alert)
            elif any(x in combined for x in ['POC', 'PROOF OF CONCEPT', 'EXPLOIT AVAILABLE']):
                maturity_stages['poc-available'].append(alert)
            elif any(x in combined for x in ['EXPLOITED', 'ACTIVE EXPLOITATION', 'ACTIVELY EXPLOITED']):
                maturity_stages['exploited'].append(alert)
            elif any(x in combined for x in ['ACTIVE', 'CRITICAL', 'URGENT']):
                maturity_stages['active'].append(alert)
        
        return {k: len(v) for k, v in maturity_stages.items()}

    def analyze_industry_targeting(self, alerts):
        """Detect industry/sector targeting patterns"""
        sectors = {
            'Healthcare': ['HEALTHCARE', 'HOSPITAL', 'MEDICAL', 'PHARMA', 'HEALTHCARE SECTOR'],
            'Finance': ['FINANCE', 'BANK', 'BANKING', 'FINTECH', 'CRYPTOCURRENCY'],
            'Manufacturing': ['MANUFACTURING', 'INDUSTRIAL', 'OT', 'SCADA', 'ICS'],
            'Government': ['GOVERNMENT', 'FEDERAL', 'AGENCY', 'DEFENSE', 'MILITARY'],
            'Education': ['EDUCATION', 'UNIVERSITY', 'SCHOOL', 'ACADEMIC'],
            'Retail': ['RETAIL', 'E-COMMERCE', 'SHOPPING', 'ONLINE STORE'],
            'Telecom': ['TELECOM', 'TELECOMMUNICATIONS', 'ISP', 'CARRIER'],
            'Energy': ['ENERGY', 'UTILITY', 'POWER', 'OIL', 'GAS'],
            'Transportation': ['TRANSPORTATION', 'AIRLINE', 'LOGISTICS', 'SHIPPING'],
            'Insurance': ['INSURANCE', 'UNDERWRITING'],
        }
        
        targeted = {}
        for alert in alerts:
            title = alert.get('title', '').upper()
            for sector, keywords in sectors.items():
                for keyword in keywords:
                    if keyword in title:
                        targeted[sector] = targeted.get(sector, 0) + 1
                        break
        
        return sorted(targeted.items(), key=lambda x: x[1], reverse=True) if targeted else [("General Targeting", len(alerts))]

    async def _load_threat_summary_async(self):
        """Build the local keyword analysis for the current data window"""
        if self.threat_summary_loading:
            return
        
        self.threat_summary_loading = True
        try:
            cutoff_time = datetime.now(timezone.utc) - timedelta(hours=self.recency_hours)
            window = [a for a in self.all_alerts if a['ts'] >= cutoff_time]
            top_alerts = [a for a in window if a.get('severity') in ['critical', 'zeroday', 'ransomware', 'apt', 'exploit', 'high', 'medium']][:10]
            
            if top_alerts:
                # Run all analysis methods to get comprehensive intelligence
                top_cves = self.analyze_top_cves(window)
                threat_actors = self.analyze_threat_actors(window)
                attack_surface = self.analyze_attack_surface(window)
                vuln_chains = self.analyze_vulnerability_chains(window)
                exploit_maturity = self.analyze_exploit_maturity(window)
                industry_targeting = self.analyze_industry_targeting(window)
                
                # Build combined analysis text - ordered for optimal pagination
                analysis_text = []
                analysis_text.append("LOCAL KEYWORD ANALYSIS")
                analysis_text.append("─" * 70)
                analysis_text.append("")
                
                analysis_text.append("TOP 10 CVEs (by frequency in alerts):")
                for i, (cve, count) in enumerate(top_cves, 1):
                    analysis_text.append(f"  {i}. {cve} [{count} alerts]")
                
                analysis_text.append("")
                analysis_text.append("AFFECTED SOFTWARE (Attack Surface):")
                for i, (software, count) in enumerate(attack_surface, 1):
                    analysis_text.append(f"  {i}. {software} [{count} CVEs/alerts]")
                
                analysis_text.append("")
                analysis_text.append("EXPLOIT MATURITY STATUS:")
                analysis_text.append(f"  In-The-Wild: {exploit_maturity['in-the-wild']} threats")
                analysis_text.append(f"  POC Available: {exploit_maturity['poc-available']} threats")
                analysis_text.append(f"  Actively Exploited: {exploit_maturity['exploited']} threats")
                analysis_text.append(f"  Active/Critical: {exploit_maturity['active']} threats")
                
                analysis_text.append("")
                analysis_text.append("VULNERABILITY CHAINS DETECTED:")
                if vuln_chains:
                    for chain_type, examples in vuln_chains:
                        analysis_text.append(f"  {chain_type}:")
                        for title, cves in examples[:2]:
                            analysis_text.append(f"    • {title}")
                            analysis_text.append(f"      CVEs: {', '.join(cves)}")
                else:
                    analysis_text.append("  No multi-CVE chains detected")
                
                analysis_text.append("")
                analysis_text.append("INDUSTRY/SECTOR TARGETING:")
                for sector, count in industry_targeting[:8]:
                    analysis_text.append(f"  • {sector}: {count} relevant alerts")
                
                analysis_text.append("")
                analysis_text.append("THREAT ACTORS DETECTED:")
                if threat_actors:
                    for i, (actor, count) in enumerate(threat_actors, 1):
                        analysis_text.append(f"  {i}. {actor} [{count} mentions]")
                else:
                    analysis_text.append("  No known threat actors detected in current alerts")
                
                analysis_text.append("")
                analysis_text.append(f"Total Alerts Analyzed: {len(window)} | High Priority: {len(top_alerts)}")
                analysis_text.append("─" * 70)
                
                self.threat_summary_full = "\n".join(analysis_text)
                self.threat_summary = "LOCAL KEYWORD ANALYSIS"
                self.threat_summary_timestamp = datetime.now(timezone.utc)
            else:
                self.threat_summary_full = "Waiting for threat data to arrive..."
                self.threat_summary = self.threat_summary_full
                self.threat_summary_timestamp = datetime.now(timezone.utc)
        except Exception as e:
            import traceback
            error_msg = f"Error: {str(e)}\n{traceback.format_exc()}"
            logging.error(error_msg)
            self.threat_summary = self.threat_summary_full = f"Error loading summary: {str(e)[:100]}"
            self.threat_summary_timestamp = datetime.now(timezone.utc)
        finally:
            self.threat_summary_loading = False
            self.mark_dirty()

    def briefing_prompt(self):
        """Compact digest of the current window for the AI briefing"""
        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=self.recency_hours)
        window = [a for a in self.all_alerts if a["ts"] >= cutoff_time]
        ranked = sorted(window, key=lambda a: (SEVERITY_RANK.get(a["severity"], 9), -a["ts"].timestamp()))
        # Indicator lists (IPs, URLs) add little to a briefing; keep them out of the digest
        ranked = [a for a in ranked if a.get("kind") != "indicators"][:60]
        lines = [f"Data window: last {self.recency_hours} hours. {len(window)} alerts from {len({a['source'] for a in window})} sources.", ""]
        incidents = self.current_incidents()[:10]
        if incidents:
            lines.append("Correlated incidents (same indicator reported by several sources):")
            for inc in incidents:
                lines.append(f"- {KIND_LABELS[inc.kind]} {inc.value}: {len(inc.sources)} sources"
                             f"{', CISA KEV' if inc.kev else ''}. {inc.headline}")
            lines.append("")
        lines.append("Alerts (most severe first):")
        for a in ranked:
            summary = f" - {a['summary'][:220]}" if a.get("summary") else ""
            lines.append(f"- [{a['severity'].upper()}] {a['title']} ({a['source']}, {age(a['ts'])} ago){summary}")
        return "\n".join(lines)

    async def generate_ai_briefing(self):
        """Ask the configured AI provider for a briefing on the current alerts"""
        if self.ai_briefing_loading:
            return
        if self.ai_problem:
            self.ai_briefing_error = self.ai_problem
            self.mark_dirty()
            return
        self.ai_briefing_loading = True
        self.ai_briefing_error = None
        self.mark_dirty()
        try:
            text = await ai.generate(self.ai_settings, self.BRIEFING_SYSTEM, self.briefing_prompt())
            self.ai_briefing = text.replace("**", "").replace("## ", "").strip()
            self.ai_briefing_time = datetime.now(timezone.utc)
            self.threat_summary_page = 0
            self.app_state.briefing = {"text": self.ai_briefing, "time": self.ai_briefing_time.isoformat()}
            self.app_state.save()
        except ai.AIError as e:
            self.ai_briefing_error = str(e)
        except Exception as e:
            logging.error(f"AI briefing failed: {e}", exc_info=True)
            self.ai_briefing_error = f"Unexpected error: {type(e).__name__} - see cybrwire.log"
        finally:
            self.ai_briefing_loading = False
            self.mark_dirty()

    async def explain_alert(self, alert):
        """Ask the AI provider to explain one alert; shown in the preview pane"""
        key = alert_key(alert)
        if key in self.explaining:
            return
        self.explaining.add(key)
        self.mark_dirty()
        prompt = (f"Title: {alert['title']}\nSource: {alert['source']}\nPublished: {alert['ts']:%Y-%m-%d %H:%M} UTC\n"
                  f"Severity tag: {alert['severity']}\nSummary: {alert.get('summary') or '(none)'}\nURL: {alert.get('url') or '(none)'}")
        try:
            text = await ai.generate(self.ai_settings, self.EXPLAIN_SYSTEM, prompt)
            self.alert_explanations[key] = text.replace("**", "").strip()
        except ai.AIError as e:
            self.alert_explanations[key] = f"(AI unavailable: {e})"
        except Exception as e:
            logging.error(f"AI explanation failed: {e}", exc_info=True)
            self.alert_explanations[key] = f"(AI error: {type(e).__name__})"
        finally:
            self.explaining.discard(key)
            self.mark_dirty()

    def make_war_room_panel(self) -> Panel:
        """AI briefing followed by the local keyword analysis, paginated"""
        p = self.palette
        heading = f"bold {p.accent}"
        body = p.text
        dim = p.muted
        
        lines = []
        label = ai.describe(self.ai_settings) if self.ai_settings.get("provider") else "no provider"
        lines.append(Text(f"AI BRIEFING ({label})", style=heading))
        if self.ai_briefing_loading:
            lines.append(Text("⏳ Analyzing current alerts...", style=f"bold {p.warn}"))
        if self.ai_briefing_error:
            lines.append(Text(self.ai_briefing_error, style=f"bold {p.bad}"))
            if self.ai_problem:
                lines.append(Text("Press Shift+K to choose an AI provider and add its key.", style=dim))
        if self.ai_briefing:
            lines.append(Text(f"Generated {age(self.ai_briefing_time)} ago ({self.ai_briefing_time:%a %d %b %H:%M} UTC) • press g to refresh", style=dim))
            for line in self.ai_briefing.split("\n"):
                stripped = line.strip()
                if stripped.endswith(":") and stripped[:-1].replace(" ", "").isupper():
                    if lines and lines[-1].plain:
                        lines.append(Text(""))
                    lines.append(Text(stripped, style=heading))
                elif stripped or (lines and lines[-1].plain):
                    lines.append(Text(line, style=body))
        elif not self.ai_briefing_loading and not self.ai_briefing_error:
            lines.append(Text("Press g to generate a briefing (one AI call).", style=dim))
        
        lines.append(Text(""))
        if self.threat_summary:
            for line in self.threat_summary_full.split("\n"):
                if line.startswith("─"):
                    lines.append(Text("─" * 30, style=dim))
                elif line.endswith(":") or line == "LOCAL KEYWORD ANALYSIS":
                    lines.append(Text(line, style=heading))
                else:
                    lines.append(Text(line, style=body if not ("CVE-" in line and "[" in line) else f"bold {p.text}"))
        
        try:
            page_height = max(10, self.query_one("#dashboard").size.height - 6)
        except Exception:
            page_height = 40
        # Wrapped lines take more than one row; estimate with the panel width
        try:
            width = max(20, self.query_one("#dashboard").size.width - 6)
        except Exception:
            width = 60
        pages, current, used = [], [], 0
        for line in lines:
            rows = max(1, -(-len(line.plain) // width))
            if used + rows > page_height and current:
                pages.append(current)
                current, used = [], 0
            current.append(line)
            used += rows
        pages.append(current)
        self.threat_summary_pages = pages
        self.threat_summary_page = max(0, min(self.threat_summary_page, len(pages) - 1))
        
        title_str = "WAR ROOM" + (f" - Page {self.threat_summary_page + 1}/{len(pages)}" if len(pages) > 1 else "")
        title_text, border = self.frame(title_str, self.panel_focus == "dashboard")
        hints = [("←→", "pages"), ("g", "refresh")] if len(pages) > 1 else [("g", "refresh")]
        subtitle = self.hint_bar(hints)
        return Panel(Group(*pages[self.threat_summary_page]), title=title_text, subtitle=subtitle,
                     border_style=border, box=box.ROUNDED, padding=(1, 2), expand=True)
