"""The readme keeps its sections: a bad edit once cut most of it out without any test noticing"""

import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SECTIONS = ["Features", "Screenshots", "Installation & Usage", "World Clock", "Threat Map", "Atmosphere", "AI Briefings",
            "Live Wire", "Outages", "Evidence", "Keyboard or Mouse", "API Keys", "API Tier Limitations", "Where Settings Live",
            "Configuration Files", "Features in Detail", "Requirements", "Data Sources and Credits", "License",
            "Contributing / Feed Crowd-sourcing", "Author"]


class Readme(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(os.path.join(ROOT, "readme.md")) as f:
            cls.text = f.read()
        cls.headings = [line[3:].strip() for line in cls.text.split("\n") if line.startswith("## ")]

    def test_every_section_is_still_there_in_order(self):
        found = [h for h in self.headings if any(h.startswith(s) for s in SECTIONS)]
        self.assertEqual([max((s for s in SECTIONS if h.startswith(s)), key=len) for h in found], SECTIONS)

    def test_it_is_still_a_whole_document(self):
        self.assertGreater(self.text.count("\n"), 450)

    def test_the_screenshots_section_keeps_its_images_and_features_in_detail_describes_the_ioc_page(self):
        self.assertGreaterEqual(self.text.count("![") , 12)
        detail = self.text[self.text.index("## Features in Detail"):self.text.index("## Requirements")]
        self.assertIn("### IOC Lookup", detail)
        self.assertIn("### War Room", detail)


if __name__ == "__main__":
    unittest.main()
