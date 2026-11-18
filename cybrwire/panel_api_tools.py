"""The API Tools view: indicator lookups across the enrichment providers.

These are methods of the app, kept here so each panel lives in its own file."""

import asyncio
import logging

from rich.text import Text
from textual.widgets import Static

from .enrichment import enrichment_engine
from .widgets import IndicatorBox


class ApiToolsMixin:
    def sync_api_view(self):
        """The indicator box, the lookup results and the frame around them"""
        p = self.palette
        view = self.query_one("#api-view")
        self.query_one("#indicator-row").display = bool(enrichment_engine.providers)
        self.query_one("#api-content", Static).update(self.make_api_tools_content())
        if self.prompt == "indicator":
            hints = [("Enter", "look up"), ("Esc", "clear"), ("v", "next view when empty")]
        elif enrichment_engine.providers:
            hints = [("/", "type an indicator"), ("↑↓", "scroll"), ("v", "next view")]
        else:
            hints = [("Shift+K", "add keys"), ("v", "next view")]
        status = self.hint_bar(hints)
        title_text, border = self.frame("API TOOLS · IOC ENRICHMENT", self.panel_focus == "main")
        view.border_title = title_text
        view.border_subtitle = status
        view.styles.border = ("round", border)

    def focus_indicator_box(self):
        if enrichment_engine.providers:
            box = self.query_one("#indicator-box", IndicatorBox)
            box.focus()
            self.prompt = box.prompt_name

    def run_api_lookup(self, indicator):
        if self.api_tools_loading or not indicator or not enrichment_engine.providers:
            return
        self.api_tools_last_query = indicator
        self.api_tools_last_results = {}
        self.api_tools_loading = True
        asyncio.create_task(self._run_api_tools_query(indicator))
        self.update_display()

    def make_api_tools_content(self) -> Text:
        """Provider status and lookup results for the API Tools view"""
        p = self.palette
        content = Text()
        
        # Provider info with tier information
        providers_info = {
            "abuseipdb": {
                "name": "AbuseIPDB",
                "accepts": "IPs",
                "tier_note": "(Free tier: IP lookups only)"
            },
            "virustotal": {
                "name": "VirusTotal",
                "accepts": "IPs, hashes, domains, URLs",
                "tier_note": "(Free tier: 4 lookups/min, 500/day)"
            },
            "pulsedive": {
                "name": "Pulsedive",
                "accepts": "IPs, domains, hashes, URLs",
                "tier_note": "(Free tier: limited indicator database)"
            },
            "abusech": {
                "name": "Abuse.ch",
                "accepts": "Hashes, URLs, IPs, domains",
                "tier_note": "(Free Auth-Key: MalwareBazaar + URLhaus)"
            }
        }
        
        # Show which providers are configured
        configured = [k for k in providers_info.keys() if k in enrichment_engine.providers]
        unconfigured = [k for k in providers_info.keys() if k not in enrichment_engine.providers]
        
        if not configured:
            # No providers configured
            content.append("NO PROVIDERS CONFIGURED\n\n", style=f"bold {p.warn}")
            content.append("Available providers:\n\n", style=p.text)
            for key in providers_info.keys():
                info = providers_info[key]
                tier_note = info.get("tier_note", "")
                content.append(f"  {info['name']}: {info['accepts']}\n", style=p.muted)
                if tier_note:
                    content.append(f"    {tier_note}\n", style=p.muted)
            content.append("\nTo enable: press Shift+K to add API keys.\n", style=p.muted)
            content.append("\nNote: Free/limited tier accounts have restrictions on indicator types.\n", style=p.warn)
            content.append("      Upgrade to paid plans for full IOC database access.\n", style=p.warn)
            
        else:
            if self.api_tools_loading:
                content.append(f"Looking up {self.api_tools_last_query}...\n", style=f"bold {p.warn}")
            
            # Provider status line
            provider_line = "Providers: "
            for provider in configured:
                name = providers_info[provider]['name']
                tier_note = providers_info[provider].get("tier_note", "")
                provider_line += f"{name}  "
            
            if unconfigured:
                provider_line += f"[disabled: {', '.join([providers_info[p]['name'] for p in unconfigured])}]"
            
            content.append(f"{provider_line}\n\n", style=p.muted)
            
            # Results section
            if self.api_tools_last_query and self.api_tools_last_results:
                content.append("RESULTS\n\n", style=f"bold {p.accent}")
                
                for provider_name, enrichment_data in self.api_tools_last_results.items():
                    if enrichment_data is None:
                        continue
                    
                    # Provider header
                    provider_info = providers_info.get(provider_name, {})
                    provider_display = provider_info.get("name", provider_name)
                    provider_text = provider_display
                    content.append(f"\n{provider_text}\n", style=f"bold {p.text}")
                    content.append("─" * 40 + "\n", style=p.muted)
                    
                    # Threat level with color
                    threat_level = enrichment_data.threat_level.value.upper()
                    threat_color = {"CLEAN": p.good, "LOW": p.good, "MEDIUM": p.warn,
                                    "HIGH": p.bad, "CRITICAL": p.critical}.get(threat_level, p.text)
                    
                    content.append(f"Threat: {threat_level}  |  Score: {int(enrichment_data.reputation_score)}/100\n", style=threat_color)
                    
                    # Details summary - show all relevant fields
                    if enrichment_data.details:
                        # Format details nicely, filtering out internal/redundant fields
                        details = enrichment_data.details
                        
                        # Define display order for common fields
                        priority_fields = [
                            "abuse_score", "report_count", "threat_type", "is_whitelisted", 
                            "malicious_vendors", "suspicious_vendors", "undetected_vendors",
                            "threat", "threat_feed_count", "enhanced_threat_score",
                            "malware_family", "signature_count", "submission_count",
                            "country", "isp", "domain", "asn", "network",
                            "last_reported", "first_reported", "threat_feed_count"
                        ]
                        
                        displayed_fields = set()
                        
                        # Show priority fields first
                        for field in priority_fields:
                            if field in details and details[field] not in [None, "", [], {}]:
                                value = details[field]
                                # Format arrays/lists nicely
                                if isinstance(value, (list, tuple)):
                                    if value:
                                        value_str = ", ".join(str(v)[:30] for v in value[:3])
                                        if len(value) > 3:
                                            value_str += f"... (+{len(value)-3})"
                                    else:
                                        value_str = "(empty)"
                                elif isinstance(value, dict):
                                    value_str = f"{len(value)} items"
                                elif isinstance(value, bool):
                                    value_str = "✓ Yes" if value else "✗ No"
                                else:
                                    value_str = str(value)[:50]
                                
                                content.append(f"  {field}: {value_str}\n", style=p.muted)
                                displayed_fields.add(field)
                        
                        # Show other interesting fields (skip internal ones)
                        skip_fields = {"status", "status", "details", "timestamp", "analysis_stats", "sandbox_verdicts", "triage_verdicts"}
                        for key, value in details.items():
                            if key not in displayed_fields and key not in skip_fields and value not in [None, "", [], {}]:
                                if not key.startswith("_"):  # Skip internal fields
                                    if isinstance(value, (list, tuple)):
                                        if len(value) > 0:
                                            value_str = ", ".join(str(v)[:20] for v in value[:2])
                                            if len(value) > 2:
                                                value_str += f"... (+{len(value)-2})"
                                        else:
                                            continue
                                    elif isinstance(value, dict):
                                        value_str = f"{len(value)} items"
                                    elif isinstance(value, bool):
                                        value_str = "✓" if value else "✗"
                                    else:
                                        value_str = str(value)[:40]
                                    
                                    content.append(f"  {key}: {value_str}\n", style=p.muted)
                    
                    content.append("\n", style="")
            elif self.api_tools_last_query and not self.api_tools_last_results:
                content.append("NO RESULTS\n", style=f"bold {p.accent}")
                content.append(f"No threat data found for: {self.api_tools_last_query}\n", style=p.muted)
            else:
                content.append("USAGE\n\n", style=f"bold {p.accent}")
                content.append("Type an indicator (IP, hash, domain, URL) and press ENTER to query all configured providers.\n", style=p.text)
                content.append("Results will display below with threat scores from each provider.\n", style=p.text)
                content.append("\nPress Esc to clear the box and use other commands. Press / or click the box to type again.\n", style=p.muted)
                
                # Add API tier limitation note
                content.append("\nAPI TIER INFORMATION\n", style=f"bold {p.accent}")
                content.append("\nFree/limited API keys have restrictions on the indicator types they can query:\n\n", style=p.muted)
                content.append("  VirusTotal Free:  All indicator types, 4 lookups/min, 500/day\n", style=p.muted)
                content.append("  AbuseIPDB Free:   IP lookups only\n", style=p.muted)
                content.append("  Pulsedive Free:   Limited indicator database\n", style=p.muted)
                content.append("  Abuse.ch:         Free Auth-Key (hashes via MalwareBazaar; URLs/IPs/domains via URLhaus)\n", style=p.muted)
                content.append("\nCLEAN means the provider has no record of the indicator, not that it is safe.\n", style=p.muted)
            
        return content

    def lookup_indicator(self, alert):
        """Send an indicator from the Indicators view to API Tools and run the lookup"""
        if not enrichment_engine.providers:
            self.notify("No enrichment providers yet. Press Shift+K to add keys", timeout=4)
            return
        value = alert.get("ioc") or ""
        if alert.get("ioc_type") == "cidr":
            value = value.split("/")[0]
            self.notify("Looking up the network address of this range", timeout=3)
        self.app_state.mark_read(alert)
        self.main_view_mode = "api_tools"
        self.query_one("#indicator-box", IndicatorBox).value = value
        self.run_api_lookup(value)
        self.update_display()

    async def _run_api_tools_query(self, indicator: str):
        """Run an enrichment lookup for the indicator across all configured providers"""
        try:
            self.api_tools_last_results = await enrichment_engine.enrich(indicator)
        except Exception as e:
            logging.error(f"Error querying providers for {indicator}: {e}")
            self.api_tools_last_results = {}
        finally:
            self.api_tools_loading = False
            self.mark_dirty()
