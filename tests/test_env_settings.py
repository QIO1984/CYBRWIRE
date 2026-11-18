"""The settings that can come from the environment (cybrwire.env in Docker) as well as usrwire.yaml"""

import os
import re
import unittest
from unittest import mock

from cybrwire import config as cfg


def applied(env, **start):
    config = cfg.Config(**start)
    with mock.patch.dict(os.environ, env, clear=False):
        cfg.apply_env_settings(config)
    return config


class EnvSettingsTests(unittest.TestCase):
    def test_nothing_set_changes_nothing(self):
        with mock.patch.dict(os.environ):
            for name in ("CYBRWIRE_NOTIFY_TRIGGERS", "CYBRWIRE_AI_AUTO_BRIEFING", "CYBRWIRE_WATCHLIST"):
                os.environ.pop(name, None)
            config = cfg.Config(watchlist=["a"], notifications={"triggers": ["kev"]}, ai={"auto_briefing": True})
            cfg.apply_env_settings(config)
        self.assertEqual((config.watchlist, config.notifications, config.ai),
                         (["a"], {"triggers": ["kev"]}, {"auto_briefing": True}))

    def test_triggers_replace_the_yaml_ones_and_tolerate_spaces_and_case(self):
        config = applied({"CYBRWIRE_NOTIFY_TRIGGERS": "Watchlist, zeroday ,KEV"}, notifications={"triggers": ["confirmed"]})
        self.assertEqual(config.notifications["triggers"], ["watchlist", "zeroday", "kev"])

    def test_unknown_triggers_are_dropped_and_all_unknown_keeps_the_yaml_value(self):
        config = applied({"CYBRWIRE_NOTIFY_TRIGGERS": "kev,bogus"})
        self.assertEqual(config.notifications["triggers"], ["kev"])
        config = applied({"CYBRWIRE_NOTIFY_TRIGGERS": "bogus"}, notifications={"triggers": ["confirmed"]})
        self.assertEqual(config.notifications["triggers"], ["confirmed"])

    def test_auto_briefing_true_false_and_junk(self):
        self.assertIs(applied({"CYBRWIRE_AI_AUTO_BRIEFING": "true"}).ai["auto_briefing"], True)
        self.assertIs(applied({"CYBRWIRE_AI_AUTO_BRIEFING": "No"}, ai={"auto_briefing": True}).ai["auto_briefing"], False)
        self.assertEqual(applied({"CYBRWIRE_AI_AUTO_BRIEFING": "maybe"}, ai={"auto_briefing": True}).ai, {"auto_briefing": True})
        self.assertEqual(applied({"CYBRWIRE_AI_AUTO_BRIEFING": ""}).ai, {})

    def test_watchlist_terms_are_added_without_duplicates(self):
        config = applied({"CYBRWIRE_WATCHLIST": "Fortinet, citrix* ,CVE-2024-3400,Fortinet"}, watchlist=["Fortinet", "Cisco"])
        self.assertEqual(config.watchlist, ["Fortinet", "Cisco", "citrix*", "CVE-2024-3400"])

    def test_the_shipped_env_example_names_each_setting_and_valid_triggers(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(root, "cybrwire.env.example")) as f:
            text = f.read()
        for name in ("CYBRWIRE_WATCHLIST", "CYBRWIRE_NOTIFY_TRIGGERS", "CYBRWIRE_AI_AUTO_BRIEFING"):
            self.assertRegex(text, rf"(?m)^# {name}=")
        line = re.search(r"(?m)^# CYBRWIRE_NOTIFY_TRIGGERS=(.*)$", text).group(1)
        self.assertTrue(set(line.split(",")) <= set(cfg.NOTIFY_TRIGGERS))


if __name__ == "__main__":
    unittest.main()
