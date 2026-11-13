"""Served in a browser, the app must not wait for plain-text questions nobody can answer"""

import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import isolated  # noqa: E402,F401

from cybrwire import app  # noqa: E402


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


if __name__ == "__main__":
    unittest.main()
