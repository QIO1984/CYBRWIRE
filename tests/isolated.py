"""Import first in any test that loads cybrwire: keeps tests away from the real keychain, YAML, state and history."""

import logging
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ["CYBRWIRE_KEYCHAIN"] = "off"
_TMP = tempfile.TemporaryDirectory()
os.environ["CYBRWIRE_HOME"] = _TMP.name  # Before any cybrwire import: the real folder is never touched

from cybrwire import config  # noqa: E402
from cybrwire import history  # noqa: E402
from cybrwire import state  # noqa: E402

TMP = _TMP
# Claims the root logger first, so the app's own setup can't send test noise to the real cybrwire.log
logging.basicConfig(filename=os.path.join(TMP.name, "test.log"), level=logging.WARNING)
config.APP_DIR = TMP.name  # load_config can create and convert the user's YAML, so never let it see the real one
state.STATE_PATH = os.path.join(TMP.name, "state.json")
history.HISTORY_PATH = os.path.join(TMP.name, "history.db")
