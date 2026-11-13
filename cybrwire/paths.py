"""
Where CybrWire keeps things.

    DATA_DIR  The feed lists and the settings template that ship inside the package (read-only).
    USER_DIR  Your settings, keys file, state, history and log. ~/.config/cybrwire by default;
              set CYBRWIRE_HOME to use another folder.
"""

import logging
import os
import shutil

PACKAGE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(PACKAGE_DIR, "data")
USER_DIR = os.path.abspath(os.path.expanduser(
    os.environ.get("CYBRWIRE_HOME") or os.path.join(os.environ.get("XDG_CONFIG_HOME") or "~/.config", "cybrwire")))

# What older versions kept next to the code, and still does for a source checkout
LEGACY_FILES = ("usrwire.yaml", "cybrwire_local.yaml", "cybrwire_local.yaml.old", "cybrwire_secrets.yaml",
                "cybrwire_state.json", "cybrwire_history.db", "cybrwire.log")


def ensure_user_dir(path: str = USER_DIR) -> str:
    """Create the folder, owner-only, because it holds keys"""
    os.makedirs(path, mode=0o700, exist_ok=True)
    return path


def bootstrap() -> list:
    """Run once at startup, before anything reads or writes the user folder"""
    ensure_user_dir()
    if os.environ.get("CYBRWIRE_HOME"):
        return []  # An explicit folder was chosen (tests, containers): never pull files in from elsewhere
    return migrate_legacy()


def migrate_legacy(user_dir: str = USER_DIR, source_dir: str = os.path.dirname(PACKAGE_DIR)) -> list:
    """
    Move files an older version kept next to the code into the user folder, once.
    Only for a source checkout (pyproject.toml beside the package), and never over a file that
    already exists. Contents are not read; moving keeps the permissions. Returns the names moved.
    """
    if not os.path.exists(os.path.join(source_dir, "pyproject.toml")) or os.path.abspath(source_dir) == os.path.abspath(user_dir):
        return []
    moved = []
    for name in LEGACY_FILES:
        old, new = os.path.join(source_dir, name), os.path.join(user_dir, name)
        if os.path.isfile(old) and not os.path.lexists(new):
            try:
                ensure_user_dir(user_dir)
                shutil.move(old, new)
                moved.append(name)
            except OSError as e:
                logging.error(f"Could not move {name}: {type(e).__name__}")
    return moved
