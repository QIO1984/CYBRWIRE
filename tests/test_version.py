"""The version is written once (cybrwire/__init__.py); everything else must agree with it"""

import os
import re
import subprocess
import sys
import unittest

import cybrwire

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class VersionTests(unittest.TestCase):
    def test_version_looks_like_a_release_number(self):
        self.assertRegex(cybrwire.__version__, r"^\d+\.\d+\.\d+$")

    def test_the_changelog_top_entry_is_this_version(self):
        with open(os.path.join(ROOT, "CHANGELOG.md")) as f:
            first = re.search(r"(?m)^## (\d+\.\d+\.\d+)", f.read()).group(1)
        self.assertEqual(first, cybrwire.__version__)

    def test_the_user_agent_carries_the_version(self):
        self.assertTrue(cybrwire.USER_AGENT.startswith(f"CybrWire/{cybrwire.__version__} "))

    def test_no_version_number_is_written_into_the_source_by_hand(self):
        for name in os.listdir(os.path.join(ROOT, "cybrwire")):
            if name.endswith(".py") and name != "__init__.py":
                with open(os.path.join(ROOT, "cybrwire", name)) as f:
                    self.assertNotRegex(f.read(), r"CybrWire/\d", name)

    def test_the_screens_show_the_real_version(self):
        from cybrwire import app
        self.assertIn(f"v{cybrwire.__version__} LEGENDARY", app.CybrWireApp.TITLE)
        self.assertEqual(app.EDITION, f"v{cybrwire.__version__} LEGENDARY // EDITION")
        box_width = len("╔" + "═" * 104 + "╗")
        for text in (app.EDITION, f"{app.EDITION} // *COLD*WAR*MODE*"):
            line = app.boxed(text)
            self.assertEqual(len(line), box_width)
            self.assertIn(text, line)

    def test_no_screen_text_hardcodes_a_release_number(self):
        for name in os.listdir(os.path.join(ROOT, "cybrwire")):
            if name.endswith(".py"):
                with open(os.path.join(ROOT, "cybrwire", name)) as f:
                    self.assertNotRegex(f.read(), r"v\d+\.\d+ LEGENDARY|W I R E {1,2}\d+\.\d+ {1,2}H E L P", name)

    def test_pyproject_reads_the_version_from_the_package(self):
        with open(os.path.join(ROOT, "pyproject.toml")) as f:
            text = f.read()
        self.assertIn('dynamic = ["version"]', text)
        self.assertIn('version = { attr = "cybrwire.__version__" }', text)

    def test_the_command_line_reports_it(self):
        out = subprocess.run([sys.executable, "-m", "cybrwire", "--version"], capture_output=True, text=True,
                             cwd=ROOT, timeout=60)
        self.assertEqual(out.stdout.strip(), f"CybrWire {cybrwire.__version__}")


if __name__ == "__main__":
    unittest.main()
