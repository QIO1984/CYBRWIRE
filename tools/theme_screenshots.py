#!/usr/bin/env python3
"""
Retake the theme gallery in screenshots/themes from fixed sample data (no feeds, no keys, no AI).

    venv/bin/python tools/theme_screenshots.py [output_dir]

Needs Firefox for turning the app's SVG screenshots into PNGs, and Pillow (pip install pillow) to
shrink them. Your real state, history and watchlist are left alone.
"""

import asyncio
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.environ["CYBRWIRE_KEYCHAIN"] = "off"
WORK = tempfile.mkdtemp(prefix="cybrwire-themes-")
os.environ["CYBRWIRE_HOME"] = WORK

from cybrwire import config, history, state  # noqa: E402

config.APP_DIR = WORK
state.STATE_PATH = os.path.join(WORK, "state.json")
history.HISTORY_PATH = os.path.join(WORK, "history.db")

from cybrwire import ai, feeds  # noqa: E402
from cybrwire import app as cybrwire  # noqa: E402
from cybrwire.config import Config  # noqa: E402
from cybrwire.evidence import CONFIRMED, LIKELY, REPORTED, Evidence  # noqa: E402
from cybrwire.theme import PALETTES  # noqa: E402

SIZE = (140, 42)
WIDTH = 1200
NOW = datetime.now(timezone.utc)


def alert(title, source="Feed", kind="news", severity="info", hours=1, **extra):
    return {"title": title, "summary": "Details here.", "source": source, "kind": kind, "severity": severity,
            "url": "https://example.test/" + str(abs(hash(title))), "ts": NOW - timedelta(hours=hours), **extra}


def evidence(tier, score, *reasons, zero_day=False):
    return Evidence(tier, score, list(reasons), recent=True, zero_day=zero_day)


def sample():
    items = [
        alert("Node2Shell (CVE-2026-111497) exploited in active attacks", "Sophos Threat Research", "advisory", "critical", 2,
              evidence=evidence(CONFIRMED, 160, "CISA KEV today", "EPSS 83%")),
        alert("CISA adds Cisco BroadWorks flaw CVE-2026-20320 to KEV", "CISA KEV", "advisory", "critical", 3,
              evidence=evidence(CONFIRMED, 150, "CISA KEV today")),
        alert("Chromium zero-day exploited in the wild", "The Hacker News", "news", "zeroday", 4,
              evidence=evidence(REPORTED, 130, "reported by The Hacker News", zero_day=True)),
        alert("lockbit claimed 49 victims in 48h", "Ransomware.live", "ransomware", "ransomware", 5),
        alert("China-linked APT41 targets Taiwan telecom providers", "BleepingComputer", "news", "apt", 6),
        alert("North Korean Lazarus group targets South Korean exchange", "The Record", "news", "apt", 7),
        alert("Fortinet FortiMail RCE module lands in Metasploit", "Rapid7", "news", "exploit", 8,
              evidence=evidence(LIKELY, 70, "Metasploit module", "EPSS 61%")),
        alert("Ivanti Connect Secure auth bypass gets public exploit", "watchTowr", "news", "exploit", 9,
              evidence=evidence(LIKELY, 64, "exploit public")),
        alert("OUTAGE · Cloudflare: elevated error rates", "Cloudflare Status", "outage", "info", 1, resolved=False),
        alert("OpenSSL 3.4.1 point release ships", "OpenSSL", "news", "info", 11),
        alert("Patch Tuesday preview from Krebs", "Krebs on Security", "news", "info", 13),
        alert("Siemens Industrial Products advisory", "CISA Advisories", "advisory", "info", 14),
    ]
    victims = [("US", 14), ("DE", 6), ("GB", 5), ("BR", 4), ("IN", 4), ("CA", 3), ("IT", 3), ("FR", 2), ("AU", 2), ("JP", 2)]
    items += [alert(f"RANSOMWARE VICTIM: Co{i} (lockbit) [{code}]", "Ransomware.live", "ransomware", "ransomware", i % 100)
              for code, n in victims for i in range(n)]
    items += [alert(f"Advisory {i}", src, "advisory", "info", i)
              for src, n in (("CISA Advisories", 6), ("JPCERT/CC", 3), ("NCSC UK Alerts", 4)) for i in range(n)]
    return items


async def take(svg_dir):
    keys = list(PALETTES) + ["cold_war"]
    with mock.patch.object(ai, "generate", side_effect=AssertionError("no AI here")), \
            mock.patch("httpx.AsyncClient.get", mock.AsyncMock(side_effect=OSError("offline"))):
        cybrwire.CONFIG = Config(sources=[], watchlist=["Fortinet", "Cisco"], timezone="UTC")
        cybrwire.STATE.settings = {"filter_type_index": 1, "alerts_default": True}
        cybrwire.HISTORY.record([])
        cybrwire.alert_queue[:] = sample()
        feeds.KEV_DETAILS.clear()
        app = cybrwire.CybrWireApp()

        async def load():
            app.pop_screen()
            app.is_loading = False
            app.update_display()

        app.initial_load = load
        async with app.run_test(size=SIZE) as pilot:
            await pilot.pause(1)
            app.effects_on = False  # Steady pictures: no pulse, tint or moving heartbeat
            app.main_view_mode = "alerts"
            for key in keys:
                if key == "cold_war":
                    app.cold_war_mode = True
                else:
                    app.set_theme_by_key(key)
                app.apply_theme()
                app.update_display()
                app.wire_tick()
                app.query_one("#feed-table").move_cursor(row=0)
                app.update_display()
                await pilot.pause(0.5)
                app.save_screenshot(os.path.join(svg_dir, f"{key}.svg"))
    return keys


def render(keys, svg_dir, output):
    """Headless Firefox turns each SVG into a PNG (snap Firefox can only read under its own folder)"""
    snap = os.path.expanduser("~/snap/firefox/common/cw_theme_shots")
    base = snap if os.path.isdir(os.path.expanduser("~/snap/firefox")) else tempfile.mkdtemp()
    os.makedirs(base, exist_ok=True)
    profile = os.path.join(base, "profile")
    os.makedirs(profile, exist_ok=True)
    os.makedirs(output, exist_ok=True)
    try:
        from PIL import Image
    except ImportError:
        Image = None
        print("Pillow is not installed, so the PNGs are left full size")
    for key in keys:
        with open(os.path.join(svg_dir, f"{key}.svg")) as f:
            page = os.path.join(base, f"{key}.html")
            with open(page, "w") as out:
                out.write(f"<!doctype html><html><body style='margin:0;background:#000'>{f.read()}</body></html>")
        png = os.path.join(base, f"{key}.png")
        for _ in range(3):  # Headless Firefox sometimes crashes on start
            done = subprocess.run(["firefox", "--headless", "--no-remote", "--profile", profile, "--window-size=1700,1075",
                                   f"--screenshot={png}", f"file://{page}"], timeout=120,
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if done.returncode == 0:
                break
        else:
            raise RuntimeError(f"Firefox could not render {key}")
        target = os.path.join(output, f"{key}.png")
        if Image:
            image = Image.open(png).convert("RGB")
            image = image.resize((WIDTH, int(image.height * WIDTH / image.width)), Image.LANCZOS)
            image.quantize(colors=96, dither=Image.Dither.NONE).save(target, optimize=True)
        else:
            with open(png, "rb") as src, open(target, "wb") as dst:
                dst.write(src.read())
        print(target)


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "screenshots", "themes")
    svgs = os.path.join(WORK, "svg")
    os.makedirs(svgs)
    render(asyncio.run(take(svgs)), svgs, out)
