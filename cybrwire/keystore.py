"""
Where CybrWire keeps API keys and notification URLs

Lookup order: environment variable, restricted file, system keychain, YAML.
New keys go to the keychain, or to the restricted file when no keychain works.
The file only holds keys saved while the keychain was out, so it outranks it,
and "move" transfers them back once the keychain returns.

A keychain protects keys from other users, backups and accidental commits, but
not from malware running as you, because the app itself must be able to read them.
"""

import copy
import logging
import os
import re
import stat
import tempfile
import threading
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple

import yaml

from .paths import DATA_DIR, USER_DIR

APP_DIR = USER_DIR
SERVICE = "cybrwire"
SECRETS_FILE = "cybrwire_secrets.yaml"
USER_FILE = "usrwire.yaml"
EXAMPLE_FILE = "usrwire.example.yaml"
OLD_USER_FILE = "cybrwire_local.yaml"
OLD_COPY = OLD_USER_FILE + ".old"
YAML_FILES = (USER_FILE, OLD_USER_FILE)  # The old name is only read until it has been converted
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
    yaml_key: str  # For a feed, the header or URL parameter that carries the key
    hint: str
    is_url: bool = False
    provider: str = ""  # AI slots: only used while this provider is chosen
    feed: str = ""      # Feed slots: the feed's name

    @property
    def env(self) -> str:
        return f"CYBRWIRE_{self.id.upper()}"


def _ai_slot(provider: str, label: str, hint: str) -> Slot:
    return Slot(f"{provider}_api_key", label, "AI", "ai", "api_key", hint, provider=provider)


SLOTS = [
    # Each AI provider has its own key, so choosing another never sends one provider's key to the next
    _ai_slot("anthropic", "Anthropic", "Key: console.anthropic.com"),
    _ai_slot("gemini", "Gemini", "Key: aistudio.google.com/apikey"),
    _ai_slot("openai", "OpenAI", "Key: platform.openai.com/api-keys"),
    _ai_slot("openrouter", "OpenRouter", "Key: openrouter.ai/keys"),
    _ai_slot("openai_compatible", "Compatible server", "The key for your OpenAI-compatible server"),
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
    Slot("pushover_token", "Pushover app token", "NOTIFICATIONS", "notifications", "pushover_token",
         "Create an application at pushover.net/apps/build. Needs the user key too"),
    Slot("pushover_user", "Pushover user key", "NOTIFICATIONS", "notifications", "pushover_user",
         "Shown on your pushover.net dashboard. Needs the app token too"),
    Slot("telegram_token", "Telegram bot token", "NOTIFICATIONS", "notifications", "telegram_token",
         "Message @BotFather on Telegram and send /newbot. Needs the chat ID too"),
    Slot("telegram_chat_id", "Telegram chat ID", "NOTIFICATIONS", "notifications", "telegram_chat_id",
         "Message your bot, then open api.telegram.org/bot<token>/getUpdates to find the chat ID"),
    Slot("discord_webhook", "Discord webhook", "NOTIFICATIONS", "notifications", "discord_webhook",
         "Channel settings > Integrations > Webhooks", is_url=True),
    Slot("slack_webhook", "Slack webhook", "NOTIFICATIONS", "notifications", "slack_webhook",
         "Slack app > Incoming Webhooks", is_url=True),
]
SLOTS_BY_ID = {s.id: s for s in SLOTS}
LEGACY_AI_SLOT = "ai_api_key"  # Used before each provider had its own key
SECRET_HEADER_RE = re.compile(r"key|token|auth|secret|password", re.IGNORECASE)
FEED_SECTIONS = ("custom", "curated", "community")


def feed_key_spec(src: dict) -> Optional[Tuple[str, str, str]]:
    """(header or param, its name, any value written inline in YAML) if this feed needs a key"""
    if src.get("key_header"):
        return "header", str(src["key_header"]), ""
    if src.get("key_param"):
        return "param", str(src["key_param"]), ""
    for name, value in (src.get("headers") or {}).items():
        if SECRET_HEADER_RE.search(str(name)):
            return "header", str(name), str(value or "")
    return None


def feed_slot_id(feed_name: str) -> str:
    return "feed_" + re.sub(r"[^a-z0-9]+", "_", feed_name.lower()).strip("_")


def add_feed_slot(src: dict) -> Optional[Slot]:
    """Give a feed that needs a key its own row in the key card"""
    spec = feed_key_spec(src)
    if not spec:
        return None
    slot_id = feed_slot_id(src["name"])
    if slot_id not in SLOTS_BY_ID:
        slot = Slot(slot_id, src["name"], "FEEDS", "feeds", spec[1], f"Sent to this feed as {spec[1]}", feed=src["name"])
        SLOTS.append(slot)
        SLOTS_BY_ID[slot_id] = slot
    return SLOTS_BY_ID[slot_id]


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


def rewrite_feed_header(path: str, feed: str, header: str) -> bool:
    """
    Turn an inline header key into `key_header: NAME`, keeping everything else.
    Same safety rule as scrub_yaml: the result must parse to exactly the expected data.
    """
    if not os.path.exists(path):
        return False
    with open(path, "r") as f:
        original = f.read()
    try:
        before = yaml.safe_load(original) or {}
    except yaml.YAMLError:
        raise KeyStoreError(f"Couldn't parse {os.path.basename(path)}; move the key for {feed} by hand")
    expected = copy.deepcopy(before)
    entry = next((src for section in FEED_SECTIONS for src in (expected.get(section) or [])
                  if isinstance(src, dict) and src.get("name") == feed and header in (src.get("headers") or {})), None)
    if entry is None:
        return False
    del entry["headers"][header]
    if not entry["headers"]:
        del entry["headers"]
    entry["key_header"] = header

    lines = original.splitlines(keepends=True)
    problem = KeyStoreError(f"Couldn't edit {os.path.basename(path)} safely; move the key for {feed} by hand")
    try:
        start = next(i for i, line in enumerate(lines) if re.match(r"\s*-\s*name:\s*[\"']?" + re.escape(feed) + r"[\"']?\s*(#.*)?$", line))
        block = next(i for i in range(start + 1, len(lines)) if lines[i].strip().startswith("headers:"))
        child = next(i for i in range(block + 1, len(lines)) if lines[i].strip().split(":", 1)[0].strip("\"'") == header)
    except StopIteration:
        raise problem
    indent = lines[block][:len(lines[block]) - len(lines[block].lstrip())]
    siblings = len(entry.get("headers") or {})
    new_line = f"{indent}key_header: {header}\n"
    if siblings:
        lines[child] = ""
        lines.insert(block, new_line)
    else:
        lines[block] = new_line
        lines[child] = ""
    edited = "".join(lines)
    try:
        if yaml.safe_load(edited) != expected:
            raise problem
    except yaml.YAMLError:
        raise problem
    _write_private(path, edited, stat.S_IMODE(os.stat(path).st_mode))
    return True


def _render_user_file(data: Dict, example: str) -> str:
    """The documented template, followed by this user's settings"""
    keep = {}
    for key, value in data.items():
        if key == "enrichment":  # Keys that are still here are carried over until they are moved
            value = {k: v for k, v in (value or {}).items() if v}
        elif key == "ai":
            value = {k: v for k, v in (value or {}).items() if v not in ("", None)}
        if value not in (None, "", [], {}):
            keep[key] = value
    return example.rstrip() + "\n\n" + (yaml.safe_dump(keep, sort_keys=False, allow_unicode=True) if keep else "")


def convert_user_file(app_dir: str = APP_DIR) -> bool:
    """
    One-time move to the single usrwire.yaml layout. The old file is kept as
    cybrwire_local.yaml.old, because comments can't be carried over and may hold
    something the user still wants. The app warns until they delete it.
    """
    old = os.path.join(app_dir, OLD_USER_FILE)
    new = os.path.join(app_dir, USER_FILE)
    example_path = os.path.join(DATA_DIR, EXAMPLE_FILE)
    if not os.path.exists(old) or os.path.exists(new) or not os.path.exists(example_path):
        return False
    try:
        with open(old, "r") as f:
            data = yaml.safe_load(f) or {}
        with open(example_path, "r") as f:
            example = f.read()
        text = _render_user_file(data, example)
        if (yaml.safe_load(text) or {}) != (yaml.safe_load(_render_user_file(data, "")) or {}):
            raise ValueError("template isn't all comments")
        _write_private(new, text)
        os.chmod(old, 0o600)
        os.replace(old, os.path.join(app_dir, OLD_COPY))
        return True
    except (OSError, ValueError, yaml.YAMLError) as e:
        logging.error(f"Could not convert {OLD_USER_FILE}: {type(e).__name__}")
        return False


def create_user_file(app_dir: str = APP_DIR) -> None:
    """First run: start from the documented template"""
    new = os.path.join(app_dir, USER_FILE)
    example_path = os.path.join(DATA_DIR, EXAMPLE_FILE)
    if os.path.exists(new) or os.path.exists(os.path.join(app_dir, OLD_USER_FILE)) or not os.path.exists(example_path):
        return
    try:
        with open(example_path, "r") as f:
            _write_private(new, f.read())
    except OSError as e:
        logging.error(f"Could not create {USER_FILE}: {type(e).__name__}")


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
            return {slot_id: backend.get_password(SERVICE, slot_id) for slot_id in [*SLOTS_BY_ID, LEGACY_AI_SLOT]}

        try:
            found = _timed(read_all, KEYCHAIN_TIMEOUT)
            self.keychain_values = {k: v for k, v in found.items() if v}
        except Exception as e:
            self._give_up_on_keychain(e)

    def adopt_legacy_ai_key(self, provider: Optional[str]) -> None:
        """A key saved before keys were per provider belongs to the provider then in use"""
        target = SLOTS_BY_ID.get(f"{provider}_api_key")
        if not target or target.section != "ai":
            return
        if self.backend and LEGACY_AI_SLOT in self.keychain_values:
            value = self.keychain_values[LEGACY_AI_SLOT]
            if target.id in self.keychain_values or self._to_keychain(target, value):
                backend = self.backend
                try:
                    _timed(lambda: backend.delete_password(SERVICE, LEGACY_AI_SLOT), KEYCHAIN_TIMEOUT)
                    del self.keychain_values[LEGACY_AI_SLOT]
                except Exception as e:
                    self._give_up_on_keychain(e)
        file_values = self._read_file(include_legacy=True)
        if LEGACY_AI_SLOT in file_values:
            value = file_values.pop(LEGACY_AI_SLOT)
            file_values.setdefault(target.id, value)
            self._write_file(file_values)

    def _read_file(self, include_legacy: bool = False) -> Dict[str, str]:
        if not os.path.exists(self.file_path):
            return {}
        try:
            if stat.S_IMODE(os.stat(self.file_path).st_mode) & 0o077:
                os.chmod(self.file_path, 0o600)
            with open(self.file_path, "r") as f:
                data = yaml.safe_load(f) or {}
            known = {*SLOTS_BY_ID, LEGACY_AI_SLOT} if include_legacy else SLOTS_BY_ID
            return {k: str(v) for k, v in data.items() if k in known and v}
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
                if not isinstance(block, dict) or not block.get(slot.yaml_key):
                    continue
                # ai.api_key belongs to the provider named next to it
                if slot.section == "ai" and block.get("provider") != slot.provider:
                    continue
                values[slot.id] = str(block[slot.yaml_key])
            for section in FEED_SECTIONS:
                for src in data.get(section) or []:
                    spec = feed_key_spec(src) if isinstance(src, dict) and src.get("name") else None
                    if spec and spec[2]:
                        values[feed_slot_id(src["name"])] = spec[2]
        return values

    def _scrub_everywhere(self, slot: Slot) -> None:
        for name in YAML_FILES:
            path = os.path.join(self.app_dir, name)
            if slot.feed:
                rewrite_feed_header(path, slot.feed, slot.yaml_key)
            elif slot.section != "ai" or self._yaml_provider(path) == slot.provider:
                scrub_yaml(path, slot.section, slot.yaml_key)

    @staticmethod
    def _yaml_provider(path: str) -> Optional[str]:
        try:
            with open(path, "r") as f:
                block = (yaml.safe_load(f) or {}).get("ai")
            return block.get("provider") if isinstance(block, dict) else None
        except (OSError, yaml.YAMLError):
            return None

    @property
    def old_copy_exists(self) -> bool:
        return os.path.exists(os.path.join(self.app_dir, OLD_COPY))

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
