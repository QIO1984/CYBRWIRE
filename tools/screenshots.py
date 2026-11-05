#!/usr/bin/env python3
"""
Regenerate the README screenshots from live feed data, with a sample watchlist and keys.

    venv/bin/python tools/screenshots.py [output_dir]

Needs Firefox. Feeds are fetched, but nothing is sent to an AI provider, no key is
loaded, and your real state, history and watchlist are left alone.
"""

import asyncio
import os
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.environ["CYBRWIRE_KEYCHAIN"] = "off"

import config  # noqa: E402
import history  # noqa: E402
import state  # noqa: E402

WORK = tempfile.mkdtemp(prefix="cybrwire-shots-")
# Only the shipped feeds: the user's own YAML, keys and watchlist are never read
config.APP_DIR = WORK
for name in ("cybrwire.yaml", "comwire.yaml"):
    shutil.copy(os.path.join(ROOT, name), WORK)
state.STATE_PATH = os.path.join(WORK, "state.json")
history.HISTORY_PATH = os.path.join(WORK, "history.db")

import ai  # noqa: E402
import cybrwire  # noqa: E402
from cve_card import CveCard  # noqa: E402
from key_card import KeyCard  # noqa: E402
from keystore import KEYCHAIN, SLOTS, KeyStore  # noqa: E402
from textual.screen import ModalScreen  # noqa: E402
from livewire import Shown, wire_items  # noqa: E402

SIZE = (150, 46)
FIREFOX_ATTEMPTS = 3
WATCH_TERMS = ["Fortinet", "Ivanti", "Citrix*", "Cisco"]
SAMPLE_KEYS = {"anthropic_api_key": "sample000000000000000e5f6", "virustotal_api_key": "sample000000000000000a1b2", "abuse_ch_api_key": "sample000000000000000c3d4"}


class SampleKeychain:
    """Stands in for the real keychain, which is never read here"""
    __module__ = "keyring.backends.SecretService"

    def get_password(self, _service, _name):
        return None


def neutralize_config():
    """Screenshots must never show or use a real key"""
    cfg = cybrwire.CONFIG
    cfg.keys = KeyStore(WORK, backend=SampleKeychain(), env={})
    for slot in SLOTS:
        cfg.set_key_value(slot.id, None)
    cfg.ai.clear()
    cfg.watchlist[:] = []

    async def no_ai(*_args, **_kwargs):
        raise ai.AIError("AI is off while taking screenshots")
    ai.generate = no_ai


def show_sample_keys():
    cfg = cybrwire.CONFIG
    for slot_id, value in SAMPLE_KEYS.items():
        cfg.set_key_value(slot_id, value, KEYCHAIN)


def hide_sample_keys():
    for slot_id in SAMPLE_KEYS:
        cybrwire.CONFIG.set_key_value(slot_id, None)


def first_with_cve(app):
    return next((i for i, a in enumerate(app.feed_rows)
                 if cybrwire.CVE_RE.search(a["title"] + " " + a.get("summary", ""))), 0)


async def main(output):
    neutralize_config()
    app = cybrwire.CybrWireApp(recency=48)
    for term in WATCH_TERMS:
        app.watchlist.toggle(term)
    app.set_ai_profile(0, "anthropic", "claude-sonnet-5-5", "")
    app.set_ai_profile(1, "openrouter", "provider/model-id", "")
    os.makedirs(WORK + "/svg", exist_ok=True)

    async def load():
        await app.fetch_feeds()
        app.pop_screen()
        app.is_loading = False
        app.update_display()
    app.initial_load = load
    shots = []

    async with app.run_test(size=SIZE) as pilot:
        for _ in range(600):
            await asyncio.sleep(0.2)
            if not app.is_loading:
                break
        await pilot.pause(1)

        async def snap(name, theme, cold_war=False):
            app.cold_war_mode = cold_war
            if theme:
                app.theme_mode = theme
            app.apply_theme()
            app.update_display()
            if not isinstance(app.screen, ModalScreen):
                app.wire_tick()  # Its timer doesn't run under the test harness
            if isinstance(app.screen, KeyCard):
                app.screen.redraw()
            await pilot.pause(0.5)
            path = f"{WORK}/svg/{name}.svg"
            app.save_screenshot(path)
            shots.append(name)

        synthwave, amber, retro = "synthwave", "amber_crt", "retro_warm"

        app.wire.baseline_done = True
        app.wire_tick()
        await snap("dashboard", synthwave)

        # The bar mid-check with an arrival on show. The alert is real; only its timing is staged.
        lead = wire_items(cybrwire.alert_queue, app.watchlist, app.duplicate_groups().leader_of)[0]
        app.wire.begin_sweep(len(cybrwire.CONFIG.sources))
        for _ in range(len(cybrwire.CONFIG.sources) * 2 // 3):
            app.wire.feed_done()
        app.wire.feed_started("CISA KEV")
        app.wire.session_count = 1
        app.wire.shown = Shown(lead, True, time.monotonic())
        app.query_one("#ticker").redraw(time.monotonic())
        await snap("live_wire", retro)
        app.wire.sweeping = False
        app.wire.shown = None
        app.wire.session_count = 0
        app.wire_tick()

        await pilot.press("slash", *"ransomware")
        await pilot.pause(0.5)
        await snap("search", amber)
        await pilot.press("escape")

        while app.active_kind != "indicators":
            await pilot.press("4")
        await pilot.pause(0.5)
        await snap("indicators", retro)
        while app.active_kind != "all":
            await pilot.press("4")
        await pilot.pause(0.3)

        await pilot.press("w")
        await pilot.pause(0.3)
        await snap("watchlist", retro)
        await pilot.press("w")

        await pilot.press("W")
        await pilot.pause(0.3)
        await snap("watchlist_card", synthwave)
        await pilot.press("escape")

        table = app.query_one("#feed-table")
        grouped = app.duplicate_groups().others
        row = next((i for i, a in enumerate(app.feed_rows) if cybrwire.alert_key(a) in grouped), None)
        if row is not None:
            table.move_cursor(row=row, animate=False)
            await pilot.pause(0.3)
            await snap("duplicates", amber)
        else:
            print("No duplicate groups in today's data; skipped that shot")

        table.move_cursor(row=first_with_cve(app), animate=False)
        await pilot.pause(0.3)
        await pilot.press("i")
        await app.workers.wait_for_complete()
        await pilot.pause(1)
        if isinstance(app.screen, CveCard):
            await snap("cve_card", amber)
            await pilot.press("escape")

        show_sample_keys()
        app.key_changed("anthropic_api_key")
        await pilot.press("K")
        await pilot.pause(0.3)
        await snap("key_card", synthwave)
        await pilot.press("escape")
        hide_sample_keys()

        await pilot.press("v")
        await pilot.pause(0.5)
        await snap("incidents", retro)
        app.query_one("#incident-table").action_cursor_down()
        await pilot.pause(0.3)
        await snap("incidents", retro)
        shots.pop()
        await pilot.press("v", "escape", "v")
        await pilot.pause(0.5)

        await snap("cold_war", None, cold_war=True)
        await pilot.press("slash", *"exploit")
        await pilot.pause(0.5)
        await snap("cold_war_search", None, cold_war=True)
        await pilot.press("escape")

    render(shots, output)


def render(shots, output):
    """Headless Firefox turns each SVG into a PNG. Snap Firefox can only read under its own folder."""
    firefox_dir = os.path.expanduser("~/snap/firefox/common/cw_shots")
    base = firefox_dir if os.path.isdir(os.path.expanduser("~/snap/firefox")) else tempfile.mkdtemp()
    os.makedirs(base, exist_ok=True)
    profile = os.path.join(base, "profile")
    os.makedirs(profile, exist_ok=True)
    os.makedirs(output, exist_ok=True)
    try:
        for name in shots:
            with open(f"{WORK}/svg/{name}.svg") as f:
                svg = f.read()
            page = os.path.join(base, f"{name}.html")
            with open(page, "w") as f:
                f.write(f"<!doctype html><html><body style='margin:0;background:#000'>{svg}</body></html>")
            png = os.path.join(base, f"{name}.png")
            for attempt in range(FIREFOX_ATTEMPTS):  # Headless Firefox sometimes crashes on start
                result = subprocess.run(["firefox", "--headless", "--no-remote", "--profile", profile, "--window-size=1700,1075",
                                         f"--screenshot={png}", f"file://{page}"], timeout=120,
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                if result.returncode == 0:
                    break
            else:
                raise RuntimeError(f"Firefox couldn't render {name}")
            shutil.copy(png, os.path.join(output, f"{name}.png"))
            print(os.path.join(output, f"{name}.png"))
    finally:
        if base == firefox_dir:
            shutil.rmtree(firefox_dir, ignore_errors=True)
        shutil.rmtree(WORK, ignore_errors=True)


if __name__ == "__main__":
    asyncio.run(main(sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "screenshots")))
