"""Served in a browser, the app must not wait for plain-text questions nobody can answer"""

import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import isolated  # noqa: E402,F401

from cybrwire import app, links, web  # noqa: E402


class WebStartup(unittest.TestCase):
    def run_main(self, driver, settings):
        env = {"TEXTUAL_DRIVER": driver} if driver else {}
        with mock.patch.dict(os.environ, env, clear=False), mock.patch.object(sys, "argv", ["cybrwire"]), \
                mock.patch.object(app.STATE, "settings", settings), \
                mock.patch.object(app, "startup_prompts", return_value=(48, True)) as prompts, \
                mock.patch.object(app, "CybrWireApp") as App:
            if not driver:
                os.environ.pop("TEXTUAL_DRIVER", None)
            app.main()
        return prompts, App

    def test_browser_start_skips_the_questions_and_uses_defaults(self):
        prompts, App = self.run_main("textual.drivers.web_driver:WebDriver", {})
        prompts.assert_not_called()
        App.assert_called_once_with(cold_war=False, recency=24)

    def test_browser_start_keeps_saved_choices(self):
        prompts, App = self.run_main("textual.drivers.web_driver:WebDriver", {"recency_hours": 168, "cold_war": True})
        prompts.assert_not_called()
        App.assert_called_once_with(cold_war=True, recency=168)

    def test_a_terminal_first_run_still_asks(self):
        prompts, App = self.run_main(None, {})
        prompts.assert_called_once()
        App.assert_called_once_with(cold_war=True, recency=48)


class Links(unittest.TestCase):
    def test_terminal_uses_the_local_browser(self):
        host = mock.Mock()
        with mock.patch.dict(os.environ, {"TEXTUAL_DRIVER": "textual.drivers.linux_driver:LinuxDriver"}), \
                mock.patch("cybrwire.links.webbrowser.open") as opened:
            links.open_link(host, "https://example.test/a")
        opened.assert_called_once_with("https://example.test/a")
        host.open_url.assert_not_called()

    def test_browser_mode_asks_the_page_for_a_new_tab(self):
        host = mock.Mock()
        with mock.patch.dict(os.environ, {"TEXTUAL_DRIVER": "textual.drivers.web_driver:WebDriver"}), \
                mock.patch("cybrwire.links.webbrowser.open") as opened:
            links.open_link(host, "https://example.test/a")
        host.open_url.assert_called_once_with("https://example.test/a", new_tab=True)
        opened.assert_not_called()


class Origin(unittest.TestCase):
    def req(self, **headers):
        return mock.Mock(headers=headers, scheme="http")

    def test_direct_by_ip(self):
        self.assertEqual(web.request_origin(self.req(Host="192.168.1.195:1947"), "http://x"), "http://192.168.1.195:1947")

    def test_behind_a_proxy_uses_the_address_the_browser_used(self):
        r = self.req(Host="192.168.1.195:1947", **{"X-Forwarded-Proto": "https", "X-Forwarded-Host": "cybrwire.lan"})
        self.assertEqual(web.request_origin(r, "http://x"), "https://cybrwire.lan")
        self.assertEqual(web.request_origin(self.req(Host="cybrwire.lan", **{"X-Forwarded-Proto": "https, http"}), "http://x"),
                         "https://cybrwire.lan")

    def test_junk_falls_back(self):
        for bad in ('evil.test"><script>', "a b", "", "x/y"):
            self.assertEqual(web.request_origin(self.req(Host=bad), "http://fallback:8000"), "http://fallback:8000")
        self.assertEqual(web.request_origin(self.req(Host="ok.lan", **{"X-Forwarded-Proto": "javascript"}), "http://f"), "http://f")


class Startup(unittest.TestCase):
    def test_local_says_what_to_open(self):
        msg = web.startup_message("127.0.0.1", 8000, "cybrwire", False, False)
        self.assertIn("http://127.0.0.1:8000", msg)
        self.assertIn("No password", msg)

    def test_a_container_explains_the_published_port_and_never_prints_the_password(self):
        msg = web.startup_message("0.0.0.0", 8000, "cybrwire", True, True)
        self.assertNotIn("http://0.0.0.0", msg)
        self.assertIn("published", msg)
        self.assertIn("CYBRWIRE_PORT", msg)
        self.assertIn("CYBRWIRE_WEB_PASSWORD", msg)

    def test_a_specific_address_is_shown_as_is(self):
        self.assertIn("http://192.168.1.195:1947", web.startup_message("192.168.1.195", 1947, "u", True, False))


def basic(user, password):
    import base64
    return "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()


class WebLogin(unittest.TestCase):
    def test_right_and_wrong_credentials(self):
        self.assertTrue(web.credentials_ok(basic("cybrwire", "s3cret:x"), "cybrwire", "s3cret:x"))
        for bad in (basic("cybrwire", "nope"), basic("other", "s3cret"), None, "", "Bearer abc", "Basic !!!notbase64",
                    "Basic " + __import__("base64").b64encode(b"nocolon").decode()):
            self.assertFalse(web.credentials_ok(bad, "cybrwire", "s3cret"))

    def test_open_network_without_password_is_refused(self):
        self.assertIsNotNone(web.check_config("0.0.0.0", ""))
        self.assertIsNotNone(web.check_config("192.168.1.195", ""))
        self.assertIsNone(web.check_config("0.0.0.0", "pw"))
        self.assertIsNone(web.check_config("127.0.0.1", ""))

    def test_session_token(self):
        tok = web.session_token("u", "pw", 2000)
        self.assertTrue(web.token_ok(tok, "u", "pw", now=1000))
        self.assertFalse(web.token_ok(tok, "u", "pw", now=3000))  # expired
        self.assertFalse(web.token_ok(tok, "u", "other", now=1000))  # wrong password
        self.assertFalse(web.token_ok("2000." + "0" * 64, "u", "pw", now=1000))  # forged
        for junk in (None, "", "abc", "x.y"):
            self.assertFalse(web.token_ok(junk, "u", "pw", now=1000))

    def test_login_page_flow(self):
        import asyncio
        from aiohttp import web as aw
        from aiohttp.test_utils import TestClient, TestServer

        async def go():
            a = aw.Application(middlewares=[web.make_auth_middleware("cybrwire", "pw")])
            a.add_routes([aw.get("/", lambda r: aw.Response(text="secret page")),
                          aw.get("/ws", lambda r: aw.Response(text="secret ws"))])
            with mock.patch("asyncio.sleep", new=mock.AsyncMock()):
                async with TestClient(TestServer(a)) as c:
                    r = await c.get("/", allow_redirects=False)
                    body = await r.text()
                    self.assertEqual(r.status, 200)
                    self.assertIn('type="password"', body)
                    self.assertNotIn("secret", body)
                    self.assertEqual((await c.get("/ws")).status, 401)  # no page, no websocket
                    r = await c.post("/login", data={"user": "cybrwire", "password": "wrong"})
                    self.assertEqual(r.status, 401)
                    self.assertIn("Wrong password", await r.text())
                    self.assertEqual((await c.get("/ws")).status, 401)
                    r = await c.post("/login", data={"user": "cybrwire", "password": "pw"}, allow_redirects=False)
                    self.assertEqual(r.status, 303)
                    self.assertIn("httponly", r.headers["Set-Cookie"].lower())
                    # the client keeps the cookie, so the page and websocket now open
                    self.assertEqual(await (await c.get("/")).text(), "secret page")
                    self.assertEqual((await c.get("/ws")).status, 200)
                async with TestClient(TestServer(a)) as c2:  # curl-style header still works
                    r = await c2.get("/", headers={"Authorization": basic("cybrwire", "pw")})
                    self.assertEqual(await r.text(), "secret page")
        asyncio.run(go())


if __name__ == "__main__":
    unittest.main()
