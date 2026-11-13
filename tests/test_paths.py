"""Where files live, and the one-time move from next to the code"""

import os
import stat
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import isolated  # noqa: E402,F401

from cybrwire import paths  # noqa: E402


class MigrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.src = os.path.join(self.tmp.name, "checkout")
        self.dst = os.path.join(self.tmp.name, "home", "cybrwire")
        os.makedirs(self.src)

    def put(self, folder, name, text="x", mode=0o600):
        path = os.path.join(folder, name)
        with open(path, "w") as f:
            f.write(text)
        os.chmod(path, mode)
        return path

    def test_files_move_once_and_keep_their_permissions(self):
        self.put(self.src, "pyproject.toml")
        self.put(self.src, "usrwire.yaml", "mine")
        self.put(self.src, "cybrwire_secrets.yaml", "secret", 0o600)
        self.put(self.src, "readme.md")
        moved = paths.migrate_legacy(self.dst, self.src)
        self.assertEqual(sorted(moved), ["cybrwire_secrets.yaml", "usrwire.yaml"])
        self.assertFalse(os.path.exists(os.path.join(self.src, "usrwire.yaml")))
        self.assertEqual(open(os.path.join(self.dst, "usrwire.yaml")).read(), "mine")
        self.assertEqual(stat.S_IMODE(os.stat(os.path.join(self.dst, "cybrwire_secrets.yaml")).st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(self.dst).st_mode), 0o700)
        self.assertTrue(os.path.exists(os.path.join(self.src, "readme.md")))
        self.assertEqual(paths.migrate_legacy(self.dst, self.src), [])

    def test_never_overwrites_an_existing_file(self):
        self.put(self.src, "pyproject.toml")
        self.put(self.src, "usrwire.yaml", "old")
        os.makedirs(self.dst)
        self.put(self.dst, "usrwire.yaml", "new")
        self.assertEqual(paths.migrate_legacy(self.dst, self.src), [])
        self.assertEqual(open(os.path.join(self.dst, "usrwire.yaml")).read(), "new")
        self.assertTrue(os.path.exists(os.path.join(self.src, "usrwire.yaml")))

    def test_an_installed_copy_is_left_alone(self):
        self.put(self.src, "usrwire.yaml")  # No pyproject.toml: not a source checkout
        self.assertEqual(paths.migrate_legacy(self.dst, self.src), [])

    def test_an_explicit_home_pulls_nothing_in(self):
        self.assertEqual(os.environ.get("CYBRWIRE_HOME"), paths.USER_DIR)
        self.assertEqual(paths.bootstrap(), [])

    def test_shipped_files_are_inside_the_package(self):
        for name in ("cybrwire.yaml", "community.yaml", "usrwire.example.yaml"):
            self.assertTrue(os.path.isfile(os.path.join(paths.DATA_DIR, name)), name)


if __name__ == "__main__":
    unittest.main()
