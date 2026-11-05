"""
Push notifications for CybrWire: ntfy, Pushover, Discord and Slack

Off until a target is configured. Each refresh sends at most one message per
target, summarizing what's new, so a busy day can't flood a phone or channel.
Feed titles are untrusted text, so they are stopped from pinging anyone.
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple

import httpx

from state import alert_key

MAX_LISTED = 8                  # Alerts named in one message; the rest are counted
MAX_AGE = timedelta(hours=48)   # A feed that resurfaces old items shouldn't alert
TIMEOUT = 15
TARGET_KEYS = ("ntfy_url", "discord_webhook", "slack_webhook")
TRIGGERS = ("watchlist", "kev", "zeroday")
PUSHOVER_URL = "https://api.pushover.net/1/messages.json"
PUSHOVER_MAX_TITLE = 250
PUSHOVER_MAX_MESSAGE = 1024


def is_configured(settings: Dict) -> bool:
    return any(settings.get(k) for k in TARGET_KEYS) or bool(settings.get("pushover_token") and settings.get("pushover_user"))


def triggered_by(alert: Dict, watch_hits: List[str], triggers: List[str]) -> Optional[str]:
    """Why this alert deserves a notification, or None"""
    if "watchlist" in triggers and watch_hits:
        return "★ " + ", ".join(watch_hits)
    if "kev" in triggers and alert["title"].startswith("KEV ACTIVE"):
        return "KEV"
    if "zeroday" in triggers and alert["severity"] == "zeroday":
        return "ZERO-DAY"
    return None


def select_new(alerts: List[Dict], notified: Dict[str, str], watchlist, triggers: List[str],
               leader_of: Dict[str, str], now: datetime = None) -> List[Tuple[Dict, str]]:
    """(alert, reason) for everything not yet notified. Only the lead report of a duplicate group counts."""
    now = now or datetime.now(timezone.utc)
    selected = []
    for a in alerts:
        key = alert_key(a)
        if key in notified or key in leader_of or a.get("kind") == "indicators" or now - a["ts"] > MAX_AGE:
            continue
        reason = triggered_by(a, watchlist.hits(a), triggers)
        if reason:
            selected.append((a, reason))
    return selected


def build_message(selected: List[Tuple[Dict, str]]) -> Tuple[str, str]:
    """(title, body) in plain text"""
    count = len(selected)
    title = f"CybrWire: {count} new alert{'s' if count != 1 else ''}"
    lines = [f"{reason} | {a['title'][:140]} ({a['source']})" for a, reason in selected[:MAX_LISTED]]
    if count > MAX_LISTED:
        lines.append(f"...and {count - MAX_LISTED} more")
    return title, "\n".join(lines)


def _escape_slack(text: str) -> str:
    # Slack reads <!channel> and <@user> as pings; these three escapes defuse them
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


async def send(settings: Dict, title: str, body: str) -> Dict[str, Optional[str]]:
    """Send to every configured target. Returns target name -> error (None = delivered)."""
    results: Dict[str, Optional[str]] = {}
    async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=False) as client:
        async def post(name, url, **kwargs):
            try:
                r = await client.post(url, **kwargs)
                r.raise_for_status()
                results[name] = None
            except httpx.HTTPStatusError as e:
                results[name] = f"HTTP {e.response.status_code}"  # str(e) would include the secret URL
            except Exception as e:  # A bad URL raises more than HTTPError; never stop the app's refresh loop
                results[name] = type(e).__name__
            if results[name]:
                logging.warning(f"Notification to {name} failed: {results[name]}")

        if settings.get("ntfy_url"):
            # JSON publishing: ntfy's Title header can't carry non-Latin-1 feed text
            base, _, topic = settings["ntfy_url"].rstrip("/").rpartition("/")
            token = settings.get("ntfy_token")
            await post("ntfy", base + "/", json={"topic": topic, "title": title, "message": body},
                       headers={"Authorization": f"Bearer {token}"} if token else {})
        if settings.get("pushover_token") and settings.get("pushover_user"):
            # Form fields, so the token stays out of the URL
            await post("pushover", PUSHOVER_URL,
                       data={"token": settings["pushover_token"], "user": settings["pushover_user"],
                             "title": title[:PUSHOVER_MAX_TITLE], "message": body[:PUSHOVER_MAX_MESSAGE]})
        if settings.get("discord_webhook"):
            await post("discord", settings["discord_webhook"],
                       json={"content": f"**{title}**\n{body}"[:2000], "allowed_mentions": {"parse": []}})
        if settings.get("slack_webhook"):
            await post("slack", settings["slack_webhook"],
                       json={"text": f"*{_escape_slack(title)}*\n{_escape_slack(body)}"})
    return results
