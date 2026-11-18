"""New sounds (sonar ping, ambient hum) and playing them in a browser tab"""

import asyncio
import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import isolated  # noqa: E402,F401
from cybrwire import sound, web_sound  # noqa: E402


def peak(samples):
    return max((abs(x) for x in samples), default=0.0)


class Tones(unittest.TestCase):
    def test_sonar_is_in_the_cycle_between_modem_and_the_bell(self):
        names = list(sound.TONES)
        self.assertEqual(names, ["off", "pc", "teletype", "modem", "sonar", "bell"])
        self.assertEqual(sound.label("sonar"), "Sonar ping")
        self.assertEqual(sound.next_tone("modem"), "sonar")

    def test_sonar_rings_down_and_has_a_quieter_echo(self):
        samples = sound.sonar_ping()
        n = sound.RATE
        first, second = peak(samples[: int(n * 0.1)]), peak(samples[int(n * 0.32): int(n * 0.45)])
        tail = peak(samples[int(n * 0.85):])
        self.assertGreater(first, second)       # The echo is softer than the ping
        self.assertGreater(second, tail * 2)    # ...but is clearly there, then it fades away
        self.assertLessEqual(peak(samples), 1.01)

    def test_the_hum_loops_without_a_seam_and_is_quiet(self):
        samples = sound.ambient_hum()
        self.assertEqual(len(samples), sound.RATE * sound.HUM_SECONDS)
        self.assertAlmostEqual(samples[0], 0.0, places=6)           # Starts at zero crossing...
        step = abs(samples[1] - samples[0])
        self.assertLess(abs(samples[-1] - samples[0]), step * 4)    # ...and the end flows into the start
        self.assertLess(peak(samples), 0.6)

    def test_the_wav_for_the_hum_has_no_fade_but_the_alerts_do(self):
        import tempfile, wave
        with tempfile.TemporaryDirectory() as folder:
            hum, ping = os.path.join(folder, "hum.wav"), os.path.join(folder, "ping.wav")
            sound.write_wav(hum, [1.0] * 2000, fade_ends=False)
            sound.write_wav(ping, [1.0] * 2000)
            def first_frame(path):
                with wave.open(path) as f:
                    return int.from_bytes(f.readframes(1), "little", signed=True)
            self.assertGreater(first_frame(hum), 1000)   # Full level from the first sample
            self.assertEqual(first_frame(ping), 0)       # Faded in


class Hum(unittest.TestCase):
    def test_no_player_means_it_says_so_and_does_not_start(self):
        hum = sound.Hum()
        with mock.patch.object(sound, "find_player", return_value=None):
            self.assertFalse(hum.start())
        self.assertFalse(hum.running)

    def test_it_loops_the_file_until_stopped(self):
        hum = sound.Hum()
        launched = []

        class FakeProc:
            def __init__(self, cmd, **kw):
                launched.append(cmd)
                hum_running = hum.running

            def wait(self):
                if len(launched) >= 3:
                    hum.running = False  # Stop after a few laps

            def poll(self):
                return 0

        with mock.patch.object(sound, "find_player", return_value="fake-player"), mock.patch.object(sound.subprocess, "Popen", FakeProc):
            self.assertTrue(hum.start())
            hum.thread.join(timeout=5)
        self.assertGreaterEqual(len(launched), 3)
        self.assertTrue(all(cmd[0] == "fake-player" and cmd[1].endswith("hum.wav") for cmd in launched))
        self.assertTrue(os.path.exists(hum.path))

    def test_stop_ends_the_player(self):
        hum = sound.Hum()
        proc = mock.Mock()
        proc.poll.return_value = None
        hum.proc, hum.running = proc, True
        hum.stop()
        self.assertFalse(hum.running)
        proc.terminate.assert_called_once()


class Browser(unittest.TestCase):
    def test_browser_mode_is_read_from_the_driver(self):
        with mock.patch.dict(os.environ, {"TEXTUAL_DRIVER": "textual.drivers.web_driver:WebDriver"}):
            self.assertTrue(sound.in_browser())
        with mock.patch.dict(os.environ, {"TEXTUAL_DRIVER": "textual.drivers.linux_driver:LinuxDriver"}):
            self.assertFalse(sound.in_browser())

    def test_the_page_gets_the_script_ahead_of_textuals_own(self):
        html = '<html><head><script src="/static/js/textual.js"></script></head><body><script>init()</script></body></html>'
        out = web_sound.inject(html)
        self.assertLess(out.index(web_sound.SCRIPT_PATH), out.index("textual.js"))
        self.assertEqual(web_sound.inject(out), out)                     # Only once
        self.assertEqual(web_sound.inject("<p>no scripts</p>"), "<p>no scripts</p>")

    def test_the_script_listens_for_our_message_and_knows_every_tone(self):
        script = web_sound.SCRIPT
        self.assertIn(f'["{web_sound.MESSAGE}"', script)
        for name in list(sound.TONES)[1:-1] + ["bell"]:
            self.assertIn(f"{name}:", script, name)
        self.assertIn("window.WebSocket = Wrapped", script)
        self.assertNotIn("__MESSAGE__", script)

    def test_the_service_passes_sound_messages_on_and_leaves_others_alone(self):
        class Base:
            def __init__(self):
                self.sent, self.seen = [], []

            async def remote_write_str(self, text):
                self.sent.append(text)

            async def on_meta(self, data):
                self.seen.append(data)

        service = web_sound.make_service_class(Base)()
        asyncio.run(service.on_meta(json.dumps({"type": web_sound.MESSAGE, "name": "sonar"}).encode()))
        asyncio.run(service.on_meta(json.dumps({"type": web_sound.MESSAGE, "hum": True}).encode()))
        asyncio.run(service.on_meta(json.dumps({"type": "open_url", "url": "https://x"}).encode()))
        asyncio.run(service.on_meta(b"not json"))
        self.assertEqual([json.loads(s) for s in service.sent], [[web_sound.MESSAGE, {"name": "sonar"}], [web_sound.MESSAGE, {"hum": True}]])
        self.assertEqual(len(service.seen), 2)  # open_url and the unreadable one went to textual-serve as before

    def test_install_patches_textual_serve_once(self):
        from textual_serve import server
        original = server.AppService
        try:
            web_sound.install()
            patched = server.AppService
            web_sound.install()
            self.assertIs(server.AppService, patched)
            self.assertTrue(issubclass(patched, original) or patched is original)
        finally:
            server.AppService = original


class OverHttp(unittest.IsolatedAsyncioTestCase):
    async def test_the_script_is_served_and_the_index_page_carries_it(self):
        from aiohttp import web
        from aiohttp.test_utils import TestClient, TestServer

        async def index(request):
            return web.Response(text='<html><head><script src="/textual.js"></script></head></html>', content_type="text/html")

        async def other(request):
            return web.Response(text="<script>x</script>", content_type="text/html")

        app = web.Application(middlewares=[web_sound.make_middleware()])
        app.router.add_get("/", index)
        app.router.add_get("/other", other)
        app.router.add_get(web_sound.SCRIPT_PATH, web_sound.script_response)
        async with TestClient(TestServer(app)) as client:
            page = await (await client.get("/")).text()
            self.assertLess(page.index(web_sound.SCRIPT_PATH), page.index("textual.js"))
            self.assertNotIn(web_sound.SCRIPT_PATH, await (await client.get("/other")).text())
            script = await client.get(web_sound.SCRIPT_PATH)
            self.assertEqual(script.status, 200)
            self.assertIn("javascript", script.headers["Content-Type"])
            self.assertIn(web_sound.MESSAGE, await script.text())


if __name__ == "__main__":
    unittest.main()
