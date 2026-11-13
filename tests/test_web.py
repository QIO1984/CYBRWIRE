"""Served in a browser, the app must not wait for plain-text questions nobody can answer"""

import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import isolated  # noqa: E402,F401

from cybrwire import app, web  # noqa: E402


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

    def test_middleware_blocks_then_lets_in(self):
        import asyncio
        from aiohttp import web as aw
        from aiohttp.test_utils import TestClient, TestServer

        async def go():
            a = aw.Application(middlewares=[web.make_auth_middleware("cybrwire", "pw")])
            a.add_routes([aw.get("/", lambda r: aw.Response(text="secret page"))])
            with mock.patch("asyncio.sleep", new=mock.AsyncMock()):
                async with TestClient(TestServer(a)) as c:
                    r = await c.get("/")
                    self.assertEqual(r.status, 401)
                    self.assertIn("Basic", r.headers["WWW-Authenticate"])
                    self.assertNotIn("secret", await r.text())
                    r = await c.get("/", headers={"Authorization": basic("cybrwire", "wrong")})
                    self.assertEqual(r.status, 401)
                    r = await c.get("/", headers={"Authorization": basic("cybrwire", "pw")})
                    self.assertEqual((r.status, await r.text()), (200, "secret page"))
        asyncio.run(go())


if __name__ == "__main__":
    unittest.main()
