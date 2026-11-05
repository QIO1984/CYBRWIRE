"""
Test an API key with the cheapest call each provider offers

Claude, Gemini, OpenAI and compatible servers only list models, which is free.
Reputation providers count one lookup against the daily quota. Notification
targets get a real test message, since that is the only thing that proves them.
Provider responses and exception text are never shown: they can echo the key.
"""

from dataclasses import dataclass
from typing import Dict, Iterable, Optional

import httpx

import ai
import notify
from keystore import SLOTS_BY_ID, feed_key_spec

OK = "ok"
REJECTED = "rejected"
UNKNOWN = "unknown"  # Couldn't tell: network trouble, rate limit, provider error
TIMEOUT = 15
ANTHROPIC_VERSION = "2023-06-01"
INVALID_STATUSES = {401, 403}
NOTIFICATION_SLOTS = {"ntfy_url": "ntfy", "ntfy_token": "ntfy", "pushover_token": "pushover", "pushover_user": "pushover",
                      "discord_webhook": "discord", "slack_webhook": "slack"}


@dataclass
class CheckResult:
    status: str
    message: str


def _request_for(slot_id: str, value: str, ai_settings: Dict, sources=()) -> Optional[dict]:
    """Keyword arguments for the test request"""
    slot = SLOTS_BY_ID[slot_id]
    if slot.feed:
        src = next((s for s in sources if s.get("key_slot") == slot_id), None)
        if not src or src.get("type") == "threatfox":
            return None
        spec = feed_key_spec(src)
        kind = "headers" if spec[0] == "header" else "params"
        return {"url": src["url"], kind: {spec[1]: value}}
    if slot_id == "abuseipdb_api_key":
        return {"url": "https://api.abuseipdb.com/api/v2/check", "params": {"ipAddress": "127.0.0.1"},
                "headers": {"Key": value, "Accept": "application/json"}}
    if slot_id == "virustotal_api_key":
        return {"url": "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8", "headers": {"x-apikey": value}}
    if slot_id == "pulsedive_api_key":
        return {"url": "https://pulsedive.com/api/info.php", "params": {"indicator": "pulsedive.com", "key": value}}
    if slot_id == "abuse_ch_api_key":
        return {"url": "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/1/", "headers": {"Auth-Key": value}}
    if slot_id == "nvd_api_key":
        return {"url": "https://services.nvd.nist.gov/rest/json/cves/2.0", "params": {"cveId": "CVE-2021-44228"},
                "headers": {"apiKey": value}}
    if slot.section == "ai":
        provider = slot.provider
        if provider == "anthropic":
            return {"url": "https://api.anthropic.com/v1/models", "params": {"limit": 1},
                    "headers": {"x-api-key": value, "anthropic-version": ANTHROPIC_VERSION}}
        custom_url = ai_settings.get("base_url") if ai_settings.get("provider") == provider else None
        base = (custom_url or ai.PROVIDERS[provider][1] or "").rstrip("/")
        if not base:
            return None
        if provider == "gemini":
            return {"url": f"{base}/models", "params": {"pageSize": 1}, "headers": {"x-goog-api-key": value}}
        # OpenRouter lists models for anyone, so its key endpoint is the one that proves the key
        path = "key" if provider == "openrouter" else "models"
        return {"url": f"{base}/{path}", "headers": {"Authorization": f"Bearer {value}"}}
    return None


async def _check_notification(slot_id: str, value: str, settings: Dict) -> CheckResult:
    name = NOTIFICATION_SLOTS[slot_id]
    target = {slot_id: value}
    if name == "ntfy":
        target = {"ntfy_url": settings.get("ntfy_url"), "ntfy_token": settings.get("ntfy_token"), **target}
        if not target["ntfy_url"]:
            return CheckResult(UNKNOWN, "Set the ntfy topic URL first; the token is tested against it")
    if name == "pushover":
        target = {"pushover_token": settings.get("pushover_token"), "pushover_user": settings.get("pushover_user"), **target}
        if not (target["pushover_token"] and target["pushover_user"]):
            return CheckResult(UNKNOWN, "Pushover needs both the app token and the user key. Add the other one to test them")
    results = await notify.send(target, "CybrWire test", "Notifications are working.")
    error = results.get(name)
    if error is None:
        return CheckResult(OK, "Test message sent. Check that it arrived")
    # Pushover answers bad credentials with 400
    if error in ("HTTP 401", "HTTP 403", "HTTP 404") or (name == "pushover" and error == "HTTP 400"):
        return CheckResult(REJECTED, f"Rejected ({error})")
    return CheckResult(UNKNOWN, f"Couldn't deliver ({error})")


async def check_key(slot_id: str, value: str, ai_settings: Dict, notifications: Dict, sources: Iterable = ()) -> CheckResult:
    if slot_id in NOTIFICATION_SLOTS:
        return await _check_notification(slot_id, value, notifications)
    request = _request_for(slot_id, value, ai_settings, sources)
    if not request:
        return CheckResult(UNKNOWN, "Can't test this one: set the server URL first" if SLOTS_BY_ID[slot_id].section == "ai"
                           else "This feed has no simple test. It will show in Feed Status")
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=False,
                                     headers={"User-Agent": "CybrWire"}) as client:
            response = await client.get(**request)
    except Exception as e:  # Names only: exception text can carry the URL
        return CheckResult(UNKNOWN, f"Couldn't reach the provider ({type(e).__name__})")
    code = response.status_code
    if code == 200:
        return CheckResult(OK, "Key accepted")
    # NVD answers a bad key with 404; the CVE asked about certainly exists
    if code in INVALID_STATUSES or (slot_id == "nvd_api_key" and code == 404):
        return CheckResult(REJECTED, f"Rejected by the provider (HTTP {code})")
    if code == 429:
        return CheckResult(UNKNOWN, "Provider is rate limiting (HTTP 429). Try again later")
    return CheckResult(UNKNOWN, f"Unexpected answer (HTTP {code}). Couldn't confirm the key")
