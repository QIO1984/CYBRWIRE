"""Import first in any test that loads cybrwire: keeps tests away from the real keychain, state and history."""

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ["CYBRWIRE_KEYCHAIN"] = "off"

import history  # noqa: E402
import state  # noqa: E402

TMP = tempfile.TemporaryDirectory()
state.STATE_PATH = os.path.join(TMP.name, "state.json")
history.HISTORY_PATH = os.path.join(TMP.name, "history.db")
