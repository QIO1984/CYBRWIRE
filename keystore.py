"""
Where CybrWire keeps API keys and notification URLs

Lookup order: environment variable, restricted file, system keychain, YAML.
New keys go to the keychain, or to the restricted file when no keychain works.
The file only holds keys saved while the keychain was out, so it outranks it,
and "move" transfers them back once the keychain returns.

A keychain protects keys from other users, backups and accidental commits, but
not from malware running as you, because the app itself must be able to read them.
"""

import logging
import os
import stat
import tempfile
import threading
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple

import yaml

APP_DIR = os.path.dirname(os.path.abspath(__file__))
SERVICE = "cybrwire"
SECRETS_FILE = "cybrwire_secrets.yaml"
YAML_FILES = ("usrwire.yaml", "cybrwire_local.yaml")  # Lowest precedence first
KEYCHAIN_TIMEOUT = 30  # Seconds; leaves time to answer a keychain unlock prompt

ENV = "environment"
FILE = "file"
KEYCHAIN = "keychain"
YAML = "yaml"
SOURCE_LABELS = {ENV: "environment variable", FILE: "restricted file", KEYCHAIN: "keychain", YAML: "plaintext YAML"}


@dataclass(frozen=True)
class Slot:
    id: str
    label: str
    group: str
    section: str   # Where the same value lives in YAML
    yaml_key: str
    hint: str
    is_url: bool = False

    @property
    def env(self) -> str:
        return f"CYBRWIRE_{self.id.upper()}"


SLOTS = [
    Slot("ai_api_key", "AI provider", "AI", "ai", "api_key", "The key for the provider set as ai.provider in your YAML"),
    Slot("abuseipdb_api_key", "AbuseIPDB", "ENRICHMENT", "enrichment", "abuseipdb_api_key", "Free key: abuseipdb.com/api"),
    Slot("virustotal_api_key", "VirusTotal", "ENRICHMENT", "enrichment", "virustotal_api_key", "Free key: virustotal.com"),
    Slot("pulsedive_api_key", "Pulsedive", "ENRICHMENT", "enrichment", "pulsedive_api_key", "Free key: pulsedive.com"),
    Slot("abuse_ch_api_key", "abuse.ch", "ENRICHMENT", "enrichment", "abuse_ch_api_key",
         "Free Auth-Key: auth.abuse.ch. Also turns on the URLhaus and ThreatFox feeds"),
    Slot("nvd_api_key", "NVD", "ENRICHMENT", "enrichment", "nvd_api_key",
         "Optional, speeds up CVSS lookups: nvd.nist.gov/developers/request-an-api-key"),
    Slot("ntfy_url", "ntfy topic URL", "NOTIFICATIONS", "notifications", "ntfy_url",
         "https://ntfy.sh/a-long-random-topic-name", is_url=True),
    Slot("ntfy_token", "ntfy token", "NOTIFICATIONS", "notifications", "ntfy_token", "Only for protected ntfy topics"),
    Slot("discord_webhook", "Discord webhook", "NOTIFICATIONS", "notifications", "discord_webhook",
         "Channel settings > Integrations > Webhooks", is_url=True),
    Slot("slack_webhook", "Slack webhook", "NOTIFICATIONS", "notifications", "slack_webhook",
         "Slack app > Incoming Webhooks", is_url=True),
]
SLOTS_BY_ID = {s.id: s for s in SLOTS}


class KeyStoreError(Exception):
    """Raised with a short, user-facing message"""


def clean_value(slot: Slot, value: str) -> str:
    """Tidy a pasted key, or raise if it can't be one"""
    value = value.strip()
    if not value:
        raise KeyStoreError("Nothing entered")
    if not value.isprintable() or " " in value:
        raise KeyStoreError("Keys can't contain spaces or control characters")
    if slot.is_url and not value.startswith(("https://", "http://")):
        raise KeyStoreError("This one should be a URL starting with https://")
    return value


def mask(value: str) -> str:
    """Enough to recognize a key by, and nothing for short ones"""
    if len(value) < 16 or "://" in value:
        return "•" * 8
    return "•" * 8 + value[-4:]


def _timed(func: Callable, timeout: float):
    """Run a keychain call without letting a stuck desktop service hang the app"""
    result: list = []
    error: list = []

    def run():
        try:
            result.append(func())
        except Exception as e:
            error.append(e)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    thread.join(timeout)
    if thread.is_alive():
        raise TimeoutError("the keychain didn't respond")
    if error:
        raise error[0]
    return result[0]


def _default_backend():
    """A real keychain, or (None, why not). Plaintext or 'null' backends don't count."""
    if os.environ.get("CYBRWIRE_KEYCHAIN", "").lower() == "off":
        return None, "turned off with CYBRWIRE_KEYCHAIN=off"
    try:
        import keyring
    except ImportError:
        return None, "the keyring package isn't installed"
    backend = keyring.get_keyring()
    module = type(backend).__module__
    if module.startswith(("keyring.backends.fail", "keyring.backends.null", "keyrings.alt")):
        return None, "this system has no keychain service"
    return backend, ""


def _write_private(path: str, text: str, mode: int = 0o600) -> None:
    """Atomic write; the temp file is private from the moment it exists"""
    path = os.path.realpath(path)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".cybrwire-")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
            os.fchmod(f.fileno(), mode)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def scrub_yaml(path: str, section: str, key: str) -> bool:
    """
    Blank one value in a YAML file, keeping its comments and layout.
    Returns whether anything changed. Raises KeyStoreError and leaves the file alone
    if the edit wouldn't produce exactly the expected data.
    """
    if not os.path.exists(path):
        return False
    with open(path, "r") as f:
        original = f.read()
    try:
        before = yaml.safe_load(original) or {}
    except yaml.YAMLError:
        raise KeyStoreError(f"Couldn't parse {os.path.basename(path)}; remove {section}.{key} by hand")
    block = before.get(section)
    if not isinstance(block, dict) or not block.get(key):
        return False

    lines = original.splitlines(keepends=True)
    current = None
    for i, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if not line[0].isspace():
            current = stripped.split(":", 1)[0].strip("\"'")
        elif current == section and stripped.split(":", 1)[0].strip("\"'") == key:
            indent = line[:len(line) - len(line.lstrip())]
            ending = "\r\n" if line.endswith("\r\n") else "\n"
            lines[i] = f'{indent}{key}: ""{ending}'
            break
    edited = "".join(lines)

    expected = {**before, section: {**block, key: ""}}
    try:
        if yaml.safe_load(edited) != expected:
            raise ValueError
    except (yaml.YAMLError, ValueError):
        raise KeyStoreError(f"Couldn't edit {os.path.basename(path)} safely; remove {section}.{key} by hand")
    _write_private(path, edited, stat.S_IMODE(os.stat(path).st_mode))
    return True


class KeyStore:
    def __init__(self, app_dir: str = APP_DIR, backend=None, env: Optional[Dict[str, str]] = None):
        self.app_dir = app_dir
        self.env = os.environ if env is None else env
        self.file_path = os.path.join(app_dir, SECRETS_FILE)
        self.problem = ""  # Why the keychain isn't being used
        self.backend = backend
        self.keychain_values: Dict[str, str] = {}
        if backend is None:
            self.backend, self.problem = _default_backend()
        self._read_keychain()

    @property
    def keychain_available(self) -> bool:
        return self.backend is not None

    @property
    def keychain_name(self) -> str:
        return type(self.backend).__module__.rsplit(".", 1)[-1] if self.backend else ""

    def _give_up_on_keychain(self, error: Exception) -> None:
        self.backend = None
        self.problem = "the keychain is locked or not responding"
        logging.warning(f"Keychain unavailable: {type(error).__name__}")

    def _read_keychain(self) -> None:
        if not self.backend:
            return
        backend = self.backend

        def read_all():
            return {s.id: backend.get_password(SERVICE, s.id) for s in SLOTS}

        try:
            found = _timed(read_all, KEYCHAIN_TIMEOUT)
            self.keychain_values = {k: v for k, v in found.items() if v}
        except Exception as e:
            self._give_up_on_keychain(e)

    def _read_file(self) -> Dict[str, str]:
        if not os.path.exists(self.file_path):
            return {}
        try:
            if stat.S_IMODE(os.stat(self.file_path).st_mode) & 0o077:
                os.chmod(self.file_path, 0o600)
            with open(self.file_path, "r") as f:
                data = yaml.safe_load(f) or {}
            return {k: str(v) for k, v in data.items() if k in SLOTS_BY_ID and v}
        except Exception as e:
            logging.error(f"Could not read {SECRETS_FILE}: {type(e).__name__}")
            return {}

    def _write_file(self, values: Dict[str, str]) -> None:
        if values:
            _write_private(self.file_path, yaml.safe_dump(values))
        elif os.path.exists(self.file_path):
            os.unlink(self.file_path)

    def _env_value(self, slot: Slot) -> Optional[str]:
        """The variable itself, or NAME_FILE pointing at a mounted secret"""
        value = self.env.get(slot.env)
        if value:
            return value.strip()
        path = self.env.get(slot.env + "_FILE")
        if path:
            try:
                with open(path, "r") as f:
                    return f.read().strip() or None
            except OSError as e:
                logging.error(f"Could not read {slot.env}_FILE: {type(e).__name__}")
        return None

    def resolve_all(self, yaml_values: Dict[str, str]) -> Dict[str, Tuple[str, str]]:
        """Slot id -> (value, source) for everything that has a value"""
        file_values = self._read_file()
        resolved = {}
        for slot in SLOTS:
            for value, source in ((self._env_value(slot), ENV), (file_values.get(slot.id), FILE),
                                  (self.keychain_values.get(slot.id), KEYCHAIN), (yaml_values.get(slot.id), YAML)):
                if value:
                    resolved[slot.id] = (str(value), source)
                    break
        return resolved

    def read_yaml_values(self) -> Dict[str, str]:
        """Secrets still sitting in YAML files, later files winning"""
        values: Dict[str, str] = {}
        for name in YAML_FILES:
            path = os.path.join(self.app_dir, name)
            if not os.path.exists(path):
                continue
            try:
                with open(path, "r") as f:
                    data = yaml.safe_load(f) or {}
            except (OSError, yaml.YAMLError):
                continue
            for slot in SLOTS:
                block = data.get(slot.section)
                if isinstance(block, dict) and block.get(slot.yaml_key):
                    values[slot.id] = str(block[slot.yaml_key])
        return values

    def _scrub_everywhere(self, slot: Slot) -> None:
        for name in YAML_FILES:
            scrub_yaml(os.path.join(self.app_dir, name), slot.section, slot.yaml_key)

    def _to_keychain(self, slot: Slot, value: str) -> bool:
        """True only once the keychain has given the value back"""
        backend = self.backend
        if not backend:
            return False

        def store():
            backend.set_password(SERVICE, slot.id, value)
            return backend.get_password(SERVICE, slot.id) == value

        try:
            if _timed(store, KEYCHAIN_TIMEOUT):
                self.keychain_values[slot.id] = value
                return True
            logging.warning(f"Keychain did not return {slot.id} after saving it")
            return False
        except Exception as e:
            self._give_up_on_keychain(e)
            return False

    def _store(self, slot: Slot, value: str) -> str:
        """Keychain if possible, otherwise the file. Returns where it went."""
        file_values = self._read_file()
        if self._to_keychain(slot, value):
            if file_values.pop(slot.id, None):
                self._write_file(file_values)
            return KEYCHAIN
        file_values[slot.id] = value
        self._write_file(file_values)
        return FILE

    def save(self, slot_id: str, value: str) -> str:
        """Store a key and remove any plaintext YAML copy. Returns where it went."""
        slot = SLOTS_BY_ID[slot_id]
        where = self._store(slot, value)
        self._scrub_everywhere(slot)
        return where

    def delete(self, slot_id: str) -> None:
        slot = SLOTS_BY_ID[slot_id]
        file_values = self._read_file()
        if file_values.pop(slot_id, None):
            self._write_file(file_values)
        if self.backend and slot_id in self.keychain_values:
            backend = self.backend
            try:
                _timed(lambda: backend.delete_password(SERVICE, slot_id), KEYCHAIN_TIMEOUT)
                del self.keychain_values[slot_id]
            except Exception as e:
                self._give_up_on_keychain(e)
                raise KeyStoreError("The keychain didn't respond, so the key is still stored there")
        self._scrub_everywhere(slot)

    def movable(self) -> List[str]:
        """Slots with a copy somewhere weaker than the best place available"""
        ids = list(self.read_yaml_values())
        if self.keychain_available:
            ids += list(self._read_file())
        return [s.id for s in SLOTS if s.id in ids]

    def move_all(self) -> Tuple[List[str], List[str]]:
        """
        Move stored keys to the best place available, deleting the old copies only
        after the new one is confirmed. Returns (moved ids, problem messages).
        """
        moved, problems = [], []
        yaml_values = self.read_yaml_values()
        file_values = self._read_file()
        for slot_id in self.movable():
            slot = SLOTS_BY_ID[slot_id]
            # What the app is using now, skipping the environment, which isn't ours to move
            value = file_values.get(slot_id) or self.keychain_values.get(slot_id) or yaml_values.get(slot_id)
            try:
                if file_values.get(slot_id) or slot_id not in self.keychain_values:
                    self._store(slot, value)
                self._scrub_everywhere(slot)
                moved.append(slot_id)
            except (KeyStoreError, OSError) as e:
                problems.append(str(e) if isinstance(e, KeyStoreError) else f"{slot.label}: {type(e).__name__}")
        return moved, problems
