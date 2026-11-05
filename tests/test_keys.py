"""
API key storage, testing and the key card. Fake keychain, temp folders and blocked
network: the real keychain, YAML files and every provider are left alone.
"""

import asyncio
import os
import stat
import sys
import tempfile
import unittest
from unittest import mock

import httpx
import yaml

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import isolated  # noqa: E402,F401

import ai  # noqa: E402
import config  # noqa: E402
import cybrwire  # noqa: E402
import key_card  # noqa: E402
import key_check  # noqa: E402
import keystore  # noqa: E402
from key_card import KeyCard  # noqa: E402
from keystore import FILE, KEYCHAIN, YAML, KeyStore, KeyStoreError, clean_value, mask, scrub_yaml  # noqa: E402

KEY = "abcdef-secret-value-1234"


class FakeKeychain:
    def __init__(self, broken=False, lossy=False):
        self.data = {}
        self.broken = broken
        self.lossy = lossy

    def get_password(self, service, name):
        if self.broken:
            raise RuntimeError("locked")
        return self.data.get((service, name))

    def set_password(self, service, name, value):
        if self.broken:
            raise RuntimeError("locked")
        if not self.lossy:
            self.data[(service, name)] = value

    def delete_password(self, service, name):
        del self.data[(service, name)]


class Base(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = tmp.name

    def write(self, name, text):
        path = os.path.join(self.dir, name)
        with open(path, "w") as f:
            f.write(text)
        return path

    def store(self, backend=None, env=None):
        return KeyStore(self.dir, backend=backend, env=env or {})


class StorageTests(Base):
    def test_save_goes_to_keychain_and_reads_back(self):
        chain = FakeKeychain()
        self.assertEqual(self.store(chain).save("nvd_api_key", KEY), KEYCHAIN)
        self.assertEqual(chain.data[("cybrwire", "nvd_api_key")], KEY)
        self.assertFalse(os.path.exists(os.path.join(self.dir, keystore.SECRETS_FILE)))
        self.assertEqual(self.store(chain).resolve_all({})["nvd_api_key"], (KEY, KEYCHAIN))

    def test_no_keychain_falls_back_to_owner_only_file(self):
        store = self.store()
        store.backend, store.problem = None, "none here"
        self.assertEqual(store.save("nvd_api_key", KEY), FILE)
        self.assertEqual(stat.S_IMODE(os.stat(store.file_path).st_mode), 0o600)
        self.assertEqual(store.resolve_all({})["nvd_api_key"], (KEY, FILE))

    def test_broken_or_lossy_keychain_falls_back_instead_of_losing_the_key(self):
        for chain in (FakeKeychain(lossy=True),):
            store = self.store(chain)
            self.assertEqual(store.save("nvd_api_key", KEY), FILE)
            self.assertEqual(store.resolve_all({})["nvd_api_key"], (KEY, FILE))
        locked = self.store(FakeKeychain(broken=True))
        self.assertFalse(locked.keychain_available)
        self.assertIn("locked", locked.problem)

    def test_loose_fallback_file_is_tightened_on_read(self):
        path = self.write(keystore.SECRETS_FILE, f"nvd_api_key: {KEY}\n")
        os.chmod(path, 0o644)
        store = self.store(FakeKeychain())
        store.resolve_all({})
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)

    def test_precedence_env_then_file_then_keychain_then_yaml(self):
        chain = FakeKeychain()
        chain.data[("cybrwire", "nvd_api_key")] = "from-keychain"
        self.write(keystore.SECRETS_FILE, "nvd_api_key: from-file\n")
        yaml_values = {"nvd_api_key": "from-yaml", "ntfy_url": "https://only-yaml.test/x"}
        env = {"CYBRWIRE_NVD_API_KEY": "from-env"}
        self.assertEqual(self.store(chain, env).resolve_all(yaml_values)["nvd_api_key"], ("from-env", keystore.ENV))
        self.assertEqual(self.store(chain).resolve_all(yaml_values)["nvd_api_key"], ("from-file", FILE))
        os.unlink(os.path.join(self.dir, keystore.SECRETS_FILE))
        self.assertEqual(self.store(chain).resolve_all(yaml_values)["nvd_api_key"], ("from-keychain", KEYCHAIN))
        self.assertEqual(self.store(chain).resolve_all(yaml_values)["ntfy_url"], ("https://only-yaml.test/x", YAML))

    def test_env_file_variable_reads_a_mounted_secret(self):
        path = self.write("mounted", KEY + "\n")
        store = self.store(env={"CYBRWIRE_NVD_API_KEY_FILE": path})
        self.assertEqual(store.resolve_all({})["nvd_api_key"], (KEY, keystore.ENV))

    def test_delete_clears_every_copy(self):
        chain = FakeKeychain()
        self.write("cybrwire_local.yaml", f'enrichment:\n  nvd_api_key: "{KEY}"\n')
        store = self.store(chain)
        store.save("nvd_api_key", KEY)
        store.delete("nvd_api_key")
        self.assertEqual(chain.data, {})
        self.assertNotIn(KEY, open(os.path.join(self.dir, "cybrwire_local.yaml")).read())
        self.assertEqual(store.resolve_all(store.read_yaml_values()), {})


class ScrubTests(Base):
    LOCAL = ('# my notes\nai:\n  provider: anthropic  # keep\n  api_key: "sk-secret"   # old\n  model: m\n\n'
             'enrichment:\n  # vt\n  virustotal_api_key: vt-secret\n  nvd_api_key: ""\n'
             'custom:\n  - name: Feed\n    url: https://x.test/a\n    api_key: not-ours\n')

    def test_blanks_only_the_value_and_keeps_the_rest(self):
        path = self.write("f.yaml", self.LOCAL)
        self.assertTrue(scrub_yaml(path, "ai", "api_key"))
        text = open(path).read()
        self.assertNotIn("sk-secret", text)
        self.assertIn("# my notes", text)
        self.assertIn("provider: anthropic  # keep", text)
        self.assertIn("vt-secret", text)
        self.assertIn("api_key: not-ours", text)
        self.assertEqual(yaml.safe_load(text)["ai"], {"provider": "anthropic", "api_key": "", "model": "m"})

    def test_mode_is_kept(self):
        path = self.write("f.yaml", self.LOCAL)
        os.chmod(path, 0o640)
        scrub_yaml(path, "ai", "api_key")
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o640)

    def test_absent_value_changes_nothing(self):
        path = self.write("f.yaml", self.LOCAL)
        self.assertFalse(scrub_yaml(path, "enrichment", "nvd_api_key"))
        self.assertFalse(scrub_yaml(path, "notifications", "ntfy_url"))
        self.assertEqual(open(path).read(), self.LOCAL)

    def test_layouts_it_cannot_edit_safely_are_left_alone(self):
        for text in ('ai: {provider: x, api_key: "sk-secret"}\n',
                     'ai:\n  api_key: >\n    sk-secret\n    more\n'):
            path = self.write("f.yaml", text)
            with self.assertRaises(KeyStoreError):
                scrub_yaml(path, "ai", "api_key")
            self.assertEqual(open(path).read(), text)
        path = self.write("f.yaml", "ai: [unclosed\n")
        with self.assertRaises(KeyStoreError):
            scrub_yaml(path, "ai", "api_key")


class MoveTests(Base):
    def setUp(self):
        super().setUp()
        self.local = self.write("cybrwire_local.yaml",
                                f'ai:\n  provider: anthropic\n  api_key: "{KEY}"\nenrichment:\n  nvd_api_key: nvd-secret-value\n'
                                "watchlist:\n  - Fortinet\n")

    def test_move_to_keychain_clears_yaml_and_keeps_settings(self):
        chain = FakeKeychain()
        store = self.store(chain)
        self.assertEqual(store.movable(), ["anthropic_api_key", "nvd_api_key"])
        moved, problems = store.move_all()
        self.assertEqual((moved, problems), (["anthropic_api_key", "nvd_api_key"], []))
        self.assertEqual(chain.data[("cybrwire", "anthropic_api_key")], KEY)
        text = open(self.local).read()
        self.assertNotIn(KEY, text)
        self.assertNotIn("nvd-secret-value", text)
        data = yaml.safe_load(text)
        self.assertEqual(data["ai"]["provider"], "anthropic")
        self.assertEqual(data["watchlist"], ["Fortinet"])
        self.assertEqual(store.movable(), [])

    def test_yaml_is_kept_when_the_keychain_fails_mid_move_and_nothing_is_lost(self):
        store = self.store(FakeKeychain(lossy=True))
        moved, problems = store.move_all()
        self.assertEqual(problems, [])
        self.assertEqual(store.resolve_all(store.read_yaml_values())["anthropic_api_key"], (KEY, FILE))
        self.assertNotIn(KEY, open(self.local).read())

    def test_uneditable_yaml_is_reported_and_key_still_works(self):
        self.write("cybrwire_local.yaml", f'ai: {{provider: anthropic, api_key: "{KEY}"}}\n')
        chain = FakeKeychain()
        store = self.store(chain)
        moved, problems = store.move_all()
        self.assertEqual(moved, [])
        self.assertIn("by hand", problems[0])
        self.assertEqual(store.resolve_all(store.read_yaml_values())["anthropic_api_key"][0], KEY)

    def test_stale_yaml_copy_does_not_overwrite_a_newer_keychain_key(self):
        chain = FakeKeychain()
        chain.data[("cybrwire", "anthropic_api_key")] = "newer-key-in-keychain"
        store = self.store(chain)
        store.move_all()
        self.assertEqual(chain.data[("cybrwire", "anthropic_api_key")], "newer-key-in-keychain")
        self.assertNotIn(KEY, open(self.local).read())

    def test_file_keys_move_back_once_a_keychain_returns(self):
        os.unlink(self.local)
        self.write(keystore.SECRETS_FILE, f"nvd_api_key: {KEY}\n")
        chain = FakeKeychain()
        store = self.store(chain)
        self.assertEqual(store.movable(), ["nvd_api_key"])
        store.move_all()
        self.assertEqual(chain.data[("cybrwire", "nvd_api_key")], KEY)
        self.assertFalse(os.path.exists(store.file_path))


class ValueTests(unittest.TestCase):
    def test_clean_value(self):
        slot = keystore.SLOTS_BY_ID["nvd_api_key"]
        self.assertEqual(clean_value(slot, f"  {KEY}\n"), KEY)
        for bad in ("", "   ", "two words", "a\tb"):
            with self.assertRaises(KeyStoreError):
                clean_value(slot, bad)
        with self.assertRaises(KeyStoreError):
            clean_value(keystore.SLOTS_BY_ID["discord_webhook"], "not-a-url")

    def test_mask_never_reveals_short_values_or_urls(self):
        self.assertEqual(mask("short"), "•" * 8)
        self.assertEqual(mask("https://discord.test/api/webhooks/1/secrettoken"), "•" * 8)
        self.assertEqual(mask(KEY), "•" * 8 + "1234")


def transport_for(status, seen=None):
    def handler(request):
        if seen is not None:
            seen.append(request)
        return httpx.Response(status, text=f"echo {request.url} {KEY}")
    return httpx.MockTransport(handler)


class CheckTests(unittest.IsolatedAsyncioTestCase):
    def patched_client(self, transport):
        real = httpx.AsyncClient

        def build(**kwargs):
            return real(transport=transport, **kwargs)
        return mock.patch.object(key_check.httpx, "AsyncClient", build)

    async def check(self, slot_id, status, ai_settings=None, seen=None):
        with self.patched_client(transport_for(status, seen)):
            return await key_check.check_key(slot_id, KEY, ai_settings or {}, {})

    async def test_statuses_map_to_results(self):
        self.assertEqual((await self.check("virustotal_api_key", 200)).status, key_check.OK)
        self.assertEqual((await self.check("virustotal_api_key", 401)).status, key_check.REJECTED)
        self.assertEqual((await self.check("virustotal_api_key", 429)).status, key_check.UNKNOWN)
        self.assertEqual((await self.check("virustotal_api_key", 500)).status, key_check.UNKNOWN)

    async def test_nvd_answers_a_bad_key_with_404(self):
        self.assertEqual((await self.check("nvd_api_key", 404)).status, key_check.REJECTED)
        self.assertEqual((await self.check("virustotal_api_key", 404)).status, key_check.UNKNOWN)

    async def test_results_never_contain_the_key_or_response_text(self):
        for status in (200, 401, 429, 500):
            self.assertNotIn(KEY, (await self.check("pulsedive_api_key", status)).message)

    async def test_network_error_does_not_leak_the_url(self):
        def boom(request):
            raise httpx.ConnectError(f"cannot reach {request.url}")
        with self.patched_client(httpx.MockTransport(boom)):
            result = await key_check.check_key("pulsedive_api_key", KEY, {}, {})
        self.assertEqual(result.status, key_check.UNKNOWN)
        self.assertNotIn(KEY, result.message)

    async def test_claude_key_test_only_lists_models(self):
        seen = []
        await self.check("anthropic_api_key", 200, {"provider": "anthropic"}, seen)
        self.assertEqual(seen[0].method, "GET")
        self.assertEqual(seen[0].url.path, "/v1/models")
        self.assertEqual(seen[0].headers["x-api-key"], KEY)

    async def test_ai_providers_use_free_endpoints(self):
        for settings, path in (({"provider": "gemini"}, "/v1beta/models"), ({"provider": "openai"}, "/v1/models"),
                               ({"provider": "openrouter"}, "/api/v1/key"),
                               ({"provider": "openai_compatible", "base_url": "http://x.test/v1/"}, "/v1/models")):
            seen = []
            await self.check(f"{settings['provider']}_api_key", 200, settings, seen)
            self.assertEqual((seen[0].method, seen[0].url.path), ("GET", path))

    async def test_compatible_server_needs_a_url_before_testing(self):
        result = await key_check.check_key("openai_compatible_api_key", KEY, {}, {})
        self.assertEqual(result.status, key_check.UNKNOWN)
        self.assertIn("server URL", result.message)

    async def test_notification_only_contacts_the_slot_under_test(self):
        calls = {}

        async def send(settings, title, body):
            calls.update(settings)
            return {"discord": None}
        with mock.patch.object(key_check.notify, "send", send):
            result = await key_check.check_key("discord_webhook", "https://d.test/h", {}, {"slack_webhook": "https://s.test"})
        self.assertEqual(result.status, key_check.OK)
        self.assertEqual(calls, {"discord_webhook": "https://d.test/h"})

    async def test_pushover_needs_both_parts_and_a_400_means_rejected(self):
        result = await key_check.check_key("pushover_token", KEY, {}, {})
        self.assertIn("both", result.message)
        for error, status in ((None, key_check.OK), ("HTTP 400", key_check.REJECTED), ("ConnectError", key_check.UNKNOWN)):
            with mock.patch.object(key_check.notify, "send", mock.AsyncMock(return_value={"pushover": error})) as send:
                result = await key_check.check_key("pushover_token", KEY, {}, {"pushover_user": "user-key"})
            self.assertEqual(result.status, status)
            self.assertEqual(send.await_args.args[0], {"pushover_token": KEY, "pushover_user": "user-key"})

    async def test_feed_key_is_tested_against_the_feed_itself(self):
        slot = keystore.add_feed_slot({"name": "Check Me", "url": "https://x.test/feed", "key_header": "X-Key"})
        self.addCleanup(lambda: (keystore.SLOTS.remove(slot), keystore.SLOTS_BY_ID.pop(slot.id)))
        sources = [{"name": "Check Me", "url": "https://x.test/feed", "key_header": "X-Key", "key_slot": slot.id, "type": "json"}]
        seen = []
        with self.patched_client(transport_for(200, seen)):
            result = await key_check.check_key(slot.id, KEY, {}, {}, sources)
        self.assertEqual(result.status, key_check.OK)
        self.assertEqual(seen[0].headers["X-Key"], KEY)
        self.assertEqual(str(seen[0].url), "https://x.test/feed")

    async def test_ntfy_token_needs_a_url(self):
        result = await key_check.check_key("ntfy_token", KEY, {}, {})
        self.assertIn("topic URL", result.message)


class CardTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = tmp.name
        self.chain = FakeKeychain()
        cfg = config.Config()
        cfg.keys = KeyStore(self.dir, backend=self.chain, env={})
        patches = [mock.patch.object(cybrwire, "CONFIG", cfg),
                   mock.patch.object(cybrwire, "enrichment_engine", mock.Mock(providers={})),
                   mock.patch.object(cybrwire, "initialize_enrichment"),
                   mock.patch.object(cybrwire.CybrWireApp, "initial_load", mock.AsyncMock())]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        self.cfg = cfg

    def result(self, status, message="Result"):
        return mock.patch.object(key_card.key_check, "check_key", mock.AsyncMock(
            return_value=key_check.CheckResult(status, message)))

    async def open_card(self, pilot):
        app = pilot.app
        app.is_loading = False
        while app.screen_stack[-1] is not app.screen_stack[0]:
            app.pop_screen()
        app.action_manage_keys()
        await pilot.pause()
        return app.screen

    async def select(self, pilot, card, slot_id):
        while card.slot.id != slot_id:
            await pilot.press("down")

    async def wait(self, pilot, card):
        await pilot.pause()
        if card.pending_task:
            await card.pending_task
        await pilot.pause()

    async def enter_key(self, pilot, card, value=KEY):
        await pilot.press("enter")
        card.query_one("#key-input").value = value
        await pilot.press("enter")
        await self.wait(pilot, card)

    def card_text(self, card):
        table = card.query_one("#key-table")
        rows = " ".join(" ".join(c.plain for c in table.get_row_at(i)) for i in range(table.row_count))
        return " ".join([rows, str(card.query_one("#key-notice").render()), str(card.query_one("#key-status").render())])

    async def test_valid_key_is_saved_applied_and_masked(self):
        app = cybrwire.CybrWireApp()
        async with app.run_test(size=(120, 45)) as pilot:
            card = await self.open_card(pilot)
            await self.select(pilot, card, "nvd_api_key")
            with self.result(key_check.OK, "Key accepted"):
                await self.enter_key(pilot, card)
            self.assertEqual(self.chain.data[("cybrwire", "nvd_api_key")], KEY)
            self.assertEqual(app.nvd.api_key, KEY)
            self.assertFalse(card.editing)
            self.assertEqual(card.query_one("#key-input").value, "")
            text = self.card_text(card)
            self.assertNotIn(KEY, text)
            self.assertIn("1234", text)
            self.assertIn("✓ works", text)
            self.assertIn(KEY, config.SECRETS)

    async def test_typing_in_the_input_does_not_trigger_app_commands(self):
        app = cybrwire.CybrWireApp()
        async with app.run_test(size=(120, 45)) as pilot:
            card = await self.open_card(pilot)
            await pilot.press("enter", "q", "t", "m")
            self.assertTrue(app.is_running)
            self.assertEqual(card.query_one("#key-input").value, "qtm")
            self.assertTrue(card.query_one("#key-input").password)

    async def test_rejected_key_is_not_saved_until_confirmed(self):
        app = cybrwire.CybrWireApp()
        async with app.run_test(size=(120, 45)) as pilot:
            card = await self.open_card(pilot)
            await self.select(pilot, card, "virustotal_api_key")
            with self.result(key_check.REJECTED, "Rejected") as check:
                await self.enter_key(pilot, card)
                self.assertEqual(self.chain.data, {})
                self.assertTrue(card.editing)
                await pilot.press("enter")
                await self.wait(pilot, card)
                self.assertEqual(check.await_count, 1)
            self.assertEqual(self.chain.data[("cybrwire", "virustotal_api_key")], KEY)

    async def test_escape_while_editing_cancels_and_stays_on_the_card(self):
        app = cybrwire.CybrWireApp()
        async with app.run_test(size=(120, 45)) as pilot:
            card = await self.open_card(pilot)
            await pilot.press("enter", "a", "b", "escape")
            await pilot.pause()
            self.assertIs(app.screen, card)
            self.assertFalse(card.editing)
            self.assertEqual(card.query_one("#key-input").value, "")
            self.assertEqual(self.chain.data, {})

    async def test_delete_needs_a_second_press(self):
        app = cybrwire.CybrWireApp()
        async with app.run_test(size=(120, 45)) as pilot:
            card = await self.open_card(pilot)
            await self.select(pilot, card, "nvd_api_key")
            with self.result(key_check.OK):
                await self.enter_key(pilot, card)
            await pilot.press("delete")
            self.assertIn(("cybrwire", "nvd_api_key"), self.chain.data)
            await pilot.press("delete")
            await self.wait(pilot, card)
            self.assertEqual(self.chain.data, {})
            self.assertIsNone(app.nvd.api_key)

    async def test_environment_keys_cannot_be_edited_here(self):
        self.cfg.set_key_value("nvd_api_key", KEY, keystore.ENV)
        app = cybrwire.CybrWireApp()
        async with app.run_test(size=(120, 45)) as pilot:
            card = await self.open_card(pilot)
            await self.select(pilot, card, "nvd_api_key")
            await pilot.press("enter")
            self.assertFalse(card.editing)
            await pilot.press("delete", "delete")
            await self.wait(pilot, card)
            self.assertIn("CYBRWIRE_NVD_API_KEY", self.card_text(card))
            self.assertEqual(self.cfg.key_value("nvd_api_key"), KEY)

    async def test_no_keychain_warns_on_the_card_and_on_save(self):
        self.cfg.keys.backend, self.cfg.keys.problem = None, "this system has no keychain service"
        app = cybrwire.CybrWireApp()
        async with app.run_test(size=(120, 45)) as pilot:
            card = await self.open_card(pilot)
            self.assertIn("NOT encrypted", self.card_text(card))
            await self.select(pilot, card, "nvd_api_key")
            with self.result(key_check.OK), mock.patch.object(app, "notify") as notify:
                await self.enter_key(pilot, card)
            self.assertIn("not encrypted", notify.call_args.args[0])
            self.assertEqual(self.cfg.key_sources["nvd_api_key"], FILE)
            self.assertIn("restricted file", self.card_text(card))

    async def test_move_from_the_card_needs_confirmation(self):
        path = os.path.join(self.dir, "cybrwire_local.yaml")
        with open(path, "w") as f:
            f.write(f'enrichment:\n  nvd_api_key: "{KEY}"\n')
        self.cfg.set_key_value("nvd_api_key", KEY, YAML)
        app = cybrwire.CybrWireApp()
        async with app.run_test(size=(120, 45)) as pilot:
            card = await self.open_card(pilot)
            self.assertIn("Press m", self.card_text(card))
            self.assertIn("1234", self.card_text(card))
            await pilot.press("m")
            self.assertIn(KEY, open(path).read())
            await pilot.press("m")
            await self.wait(pilot, card)
            self.assertNotIn(KEY, open(path).read())
            self.assertEqual(self.cfg.key_sources["nvd_api_key"], KEYCHAIN)

    async def test_abuse_key_switches_enrichment_and_feeds(self):
        app = cybrwire.CybrWireApp()
        async with app.run_test(size=(120, 45)) as pilot:
            cybrwire.force_event.clear()
            card = await self.open_card(pilot)
            await self.select(pilot, card, "abuse_ch_api_key")
            with self.result(key_check.OK):
                await self.enter_key(pilot, card)
            cybrwire.initialize_enrichment.assert_called_with(self.cfg.enrichment)
            self.assertTrue(cybrwire.force_event.is_set())
            cybrwire.force_event.clear()


class ConfigTests(Base):
    def test_load_config_prefers_store_and_tracks_source(self):
        self.write("cybrwire_local.yaml", 'enrichment:\n  nvd_api_key: from-yaml-value\n  virustotal_api_key: vt-from-yaml\n')
        chain = FakeKeychain()
        chain.data[("cybrwire", "nvd_api_key")] = "from-keychain-value"
        with mock.patch.object(config, "APP_DIR", self.dir), mock.patch.object(
                config, "KeyStore", lambda d: KeyStore(d, backend=chain, env={})):
            cfg = config.load_config()
        self.assertEqual(cfg.key_value("nvd_api_key"), "from-keychain-value")
        self.assertEqual(cfg.key_sources["nvd_api_key"], KEYCHAIN)
        self.assertEqual(cfg.key_value("virustotal_api_key"), "vt-from-yaml")
        self.assertEqual(cfg.key_sources["virustotal_api_key"], YAML)
        self.assertIn("from-keychain-value", config.SECRETS)


class ProviderKeyTests(Base):
    def test_each_provider_has_its_own_key(self):
        cfg = config.Config(ai={"provider": "anthropic"})
        cfg.set_key_value("anthropic_api_key", "anthropic-secret-key", KEYCHAIN)
        self.assertEqual(cfg.ai["api_key"], "anthropic-secret-key")
        cfg.choose_ai("openai", "gpt-x")
        self.assertNotIn("api_key", cfg.ai)  # The Anthropic key must never reach OpenAI
        cfg.set_key_value("openai_api_key", "openai-secret-key", KEYCHAIN)
        self.assertEqual(cfg.ai["api_key"], "openai-secret-key")
        cfg.choose_ai("anthropic")
        self.assertEqual(cfg.ai["api_key"], "anthropic-secret-key")
        cfg.choose_ai(None)
        self.assertEqual(cfg.ai, {})

    def test_old_single_ai_key_goes_to_the_provider_in_use(self):
        chain = FakeKeychain()
        chain.data[("cybrwire", keystore.LEGACY_AI_SLOT)] = KEY
        store = self.store(chain)
        store.adopt_legacy_ai_key("anthropic")
        self.assertEqual(chain.data, {("cybrwire", "anthropic_api_key"): KEY})
        self.assertEqual(store.resolve_all({})["anthropic_api_key"], (KEY, KEYCHAIN))

    def test_old_ai_key_waits_if_no_provider_is_known(self):
        chain = FakeKeychain()
        chain.data[("cybrwire", keystore.LEGACY_AI_SLOT)] = KEY
        self.store(chain).adopt_legacy_ai_key(None)
        self.store(chain).adopt_legacy_ai_key("ollama")
        self.assertEqual(chain.data, {("cybrwire", keystore.LEGACY_AI_SLOT): KEY})

    def test_yaml_key_only_counts_for_the_provider_next_to_it(self):
        path = self.write("usrwire.yaml", f'ai:\n  provider: gemini\n  api_key: "{KEY}"\n')
        store = self.store(FakeKeychain())
        self.assertEqual(store.read_yaml_values(), {"gemini_api_key": KEY})
        store.save("anthropic_api_key", "other-key-value-0000")
        self.assertIn(KEY, open(path).read())  # Saving another provider's key leaves this one alone
        store.save("gemini_api_key", "new-gemini-value-000")
        self.assertNotIn(KEY, open(path).read())


class FeedKeyTests(Base):
    INLINE = ('custom:\n  # my feed\n  - name: "OTX Feed"\n    url: https://x.test/a?limit=1\n    type: json\n'
              f'    headers:\n      X-OTX-API-KEY: "{KEY}"\n  - name: Other\n    url: https://x.test/b\n    type: rss\n')

    def setUp(self):
        super().setUp()
        self.slots_before = list(keystore.SLOTS)
        self.ids_before = dict(keystore.SLOTS_BY_ID)
        self.addCleanup(lambda: (keystore.SLOTS.__setitem__(slice(None), self.slots_before),
                                 keystore.SLOTS_BY_ID.clear(), keystore.SLOTS_BY_ID.update(self.ids_before)))

    def load(self, chain):
        with mock.patch.object(config, "APP_DIR", self.dir), mock.patch.object(
                config, "KeyStore", lambda d: KeyStore(d, backend=chain, env={})):
            return config.load_config()

    def test_inline_header_key_is_found_used_and_moved(self):
        path = self.write("usrwire.yaml", self.INLINE)
        chain = FakeKeychain()
        cfg = self.load(chain)
        feed = next(s for s in cfg.sources if s["name"] == "OTX Feed")
        slot = "feed_otx_feed"
        self.assertEqual(cfg.key_value(slot), KEY)
        self.assertEqual(cfg.key_sources[slot], YAML)
        self.assertEqual(cfg.feed_request_parts(feed), {"headers": {"X-OTX-API-KEY": KEY}, "params": {}})
        self.assertIn(slot, cfg.keys.movable())
        moved, problems = cfg.keys.move_all()
        self.assertEqual((moved, problems), ([slot], []))
        text = open(path).read()
        self.assertNotIn(KEY, text)
        self.assertIn("# my feed", text)
        data = yaml.safe_load(text)
        self.assertEqual(data["custom"][0], {"name": "OTX Feed", "url": "https://x.test/a?limit=1", "type": "json",
                                             "key_header": "X-OTX-API-KEY"})
        self.assertEqual(data["custom"][1]["name"], "Other")
        again = self.load(chain)
        self.assertEqual(again.key_value(slot), KEY)
        self.assertEqual(again.key_sources[slot], KEYCHAIN)

    def test_other_headers_survive_the_move(self):
        path = self.write("usrwire.yaml", 'custom:\n  - name: F\n    url: https://x.test\n    type: json\n'
                                          f'    headers:\n      Accept: text/json\n      Api-Token: "{KEY}"\n')
        self.assertTrue(keystore.rewrite_feed_header(path, "F", "Api-Token"))
        entry = yaml.safe_load(open(path))["custom"][0]
        self.assertEqual(entry["headers"], {"Accept": "text/json"})
        self.assertEqual(entry["key_header"], "Api-Token")

    def test_key_param_and_waiting_for_a_key(self):
        self.write("usrwire.yaml", "custom:\n  - name: P\n    url: https://x.test\n    type: json\n    key_param: token\n")
        cfg = self.load(FakeKeychain())
        feed = next(s for s in cfg.sources if s["name"] == "P")
        self.assertFalse(cfg.feed_is_ready(feed))
        cfg.set_key_value("feed_p", KEY, KEYCHAIN)
        self.assertTrue(cfg.feed_is_ready(feed))
        self.assertEqual(cfg.feed_request_parts(feed)["params"], {"token": KEY})

    def test_feeds_without_a_key_are_always_ready(self):
        cfg = config.Config()
        self.assertTrue(cfg.feed_is_ready({"name": "x", "url": "u"}))


class FileLayoutTests(Base):
    OLD = ('# my notes\n# api_key: "commented-out-secret"\nai:\n  provider: anthropic\n  api_key: ""\n  model: claude-haiku-5-5\n'
           'enrichment:\n  nvd_api_key: ""\nwatchlist:\n  - Fortinet\ncustom:\n  - name: F\n    url: https://x.test\n    type: rss\n')

    def setUp(self):
        super().setUp()
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(root, keystore.EXAMPLE_FILE)) as f:
            self.write(keystore.EXAMPLE_FILE, f.read())

    def test_old_file_converts_and_is_kept_aside(self):
        self.write(keystore.OLD_USER_FILE, self.OLD)
        self.assertTrue(keystore.convert_user_file(self.dir))
        new = os.path.join(self.dir, keystore.USER_FILE)
        old = os.path.join(self.dir, keystore.OLD_COPY)
        self.assertEqual(stat.S_IMODE(os.stat(new).st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(old).st_mode), 0o600)
        self.assertFalse(os.path.exists(os.path.join(self.dir, keystore.OLD_USER_FILE)))
        data = yaml.safe_load(open(new))
        self.assertEqual(data, {"ai": {"provider": "anthropic", "model": "claude-haiku-5-5"}, "watchlist": ["Fortinet"],
                                "custom": [{"name": "F", "url": "https://x.test", "type": "rss"}]})
        self.assertNotIn("commented-out-secret", open(new).read())
        self.assertIn("commented-out-secret", open(old).read())  # Not ours to destroy
        self.assertTrue(self.store(FakeKeychain()).old_copy_exists)

    def test_conversion_is_one_time_and_never_overwrites(self):
        self.write(keystore.USER_FILE, "watchlist: [Mine]\n")
        self.write(keystore.OLD_USER_FILE, self.OLD)
        self.assertFalse(keystore.convert_user_file(self.dir))
        self.assertEqual(yaml.safe_load(open(os.path.join(self.dir, keystore.USER_FILE))), {"watchlist": ["Mine"]})
        self.assertTrue(os.path.exists(os.path.join(self.dir, keystore.OLD_USER_FILE)))

    def test_broken_old_file_is_left_alone(self):
        self.write(keystore.OLD_USER_FILE, "ai: [unclosed\n")
        self.assertFalse(keystore.convert_user_file(self.dir))
        self.assertTrue(os.path.exists(os.path.join(self.dir, keystore.OLD_USER_FILE)))
        self.assertFalse(os.path.exists(os.path.join(self.dir, keystore.USER_FILE)))

    def test_first_run_starts_from_the_template(self):
        keystore.create_user_file(self.dir)
        path = os.path.join(self.dir, keystore.USER_FILE)
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        self.assertIn("Keys never go in here", open(path).read())


class ProviderCardTests(CardTests):
    def setUp(self):
        super().setUp()
        self.cfg.load_ai_profiles(None)
        patcher = mock.patch.object(cybrwire.STATE, "save")
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(cybrwire.STATE.settings.pop, "ai", None)

    async def pick(self, pilot, card, index, provider):
        card.query_one(f"#ai-provider-{index}").value = provider
        await pilot.pause()
        await pilot.pause()

    async def test_picking_a_provider_shows_its_key_row_and_asks_for_a_model(self):
        app = cybrwire.CybrWireApp()
        async with app.run_test(size=(120, 50)) as pilot:
            card = await self.open_card(pilot)
            self.assertFalse(any(s.section == "ai" for s in card.rows))
            await self.pick(pilot, card, 0, "openai")
            self.assertEqual(self.cfg.ai["provider"], "openai")
            self.assertEqual(cybrwire.STATE.settings["ai"]["profiles"][0]["provider"], "openai")
            self.assertEqual([s.id for s in card.rows if s.section == "ai"], ["openai_api_key"])
            self.assertTrue(card.query_one("#ai-model-0").display)
            self.assertFalse(card.query_one("#ai-url-row-0").display)
            self.assertIs(card.focused, card.query_one("#ai-model-0"))  # The next thing it needs
            self.assertIn("Choose a model", app.ai_problem)
            self.assertIn("AI is off", self.card_text(card))
            app.save_settings()
            self.assertEqual(cybrwire.STATE.settings["ai"]["profiles"][0]["provider"], "openai")

    async def test_changing_provider_clears_the_model(self):
        app = cybrwire.CybrWireApp()
        async with app.run_test(size=(120, 50)) as pilot:
            card = await self.open_card(pilot)
            await self.pick(pilot, card, 0, "anthropic")
            await pilot.press(*"my-model", "enter")
            await pilot.pause()
            self.assertEqual(self.cfg.ai["model"], "my-model")
            await self.pick(pilot, card, 0, "gemini")
            self.assertNotIn("model", self.cfg.ai)
            self.assertEqual(card.query_one("#ai-model-0").value, "")

    async def test_alternate_profile_switches_provider_model_and_key(self):
        self.cfg.set_key_value("anthropic_api_key", "anthropic-secret-key", KEYCHAIN)
        self.cfg.set_key_value("openrouter_api_key", "openrouter-secret-key", KEYCHAIN)
        app = cybrwire.CybrWireApp()
        async with app.run_test(size=(120, 50)) as pilot:
            card = await self.open_card(pilot)
            await self.pick(pilot, card, 0, "anthropic")
            await pilot.press(*"model-a", "enter")
            await pilot.press("a")  # The alternate has no provider yet
            self.assertEqual(self.cfg.active_ai_profile, 0)
            self.assertIn("Choose a provider for Alternate", self.card_text(card))
            await self.pick(pilot, card, 1, "openrouter")
            await pilot.press(*"vendor/model-b", "enter")
            await pilot.pause()
            self.assertEqual(self.cfg.ai["provider"], "anthropic")  # Editing the alternate doesn't activate it
            self.assertEqual({s.provider for s in card.rows if s.section == "ai"}, {"anthropic", "openrouter"})
            await pilot.press("a")
            await pilot.pause()
            self.assertEqual((self.cfg.ai["provider"], self.cfg.ai["model"], self.cfg.ai["api_key"]),
                             ("openrouter", "vendor/model-b", "openrouter-secret-key"))
            self.assertIsNone(app.ai_problem)
            await pilot.click("#ai-use-0")
            await pilot.pause()
            self.assertEqual((self.cfg.ai["provider"], self.cfg.ai["api_key"]), ("anthropic", "anthropic-secret-key"))
            self.assertEqual(cybrwire.STATE.settings["ai"]["active"], 0)

    async def test_url_row_only_for_servers(self):
        app = cybrwire.CybrWireApp()
        async with app.run_test(size=(120, 50)) as pilot:
            card = await self.open_card(pilot)
            await self.pick(pilot, card, 0, "openai_compatible")
            self.assertTrue(card.query_one("#ai-url-row-0").display)
            card.query_one("#ai-model-0").value = "my-model"
            card.query_one("#ai-url-0").value = "http://localhost:1234/v1"
            await pilot.press("enter")
            await pilot.pause()
            self.assertEqual(self.cfg.ai["model"], "my-model")
            self.assertEqual(self.cfg.ai["base_url"], "http://localhost:1234/v1")

    async def test_tab_reaches_settings_and_escape_backs_out(self):
        app = cybrwire.CybrWireApp()
        async with app.run_test(size=(120, 50)) as pilot:
            card = await self.open_card(pilot)
            await pilot.press("tab")
            await pilot.pause()
            self.assertIs(card.focused, card.query_one("#ai-provider-0"))
            await pilot.press("escape")
            await pilot.pause()
            self.assertIs(app.screen, card)
            self.assertIsNone(card.focused)

    async def test_buttons_do_what_the_keys_do(self):
        self.cfg.set_key_value("nvd_api_key", KEY, YAML)
        app = cybrwire.CybrWireApp()
        async with app.run_test(size=(120, 50)) as pilot:
            card = await self.open_card(pilot)
            await self.select(pilot, card, "nvd_api_key")
            await pilot.click("#key-set")
            await pilot.pause()
            self.assertTrue(card.editing)
            await pilot.press("escape")
            with self.result(key_check.OK, "Key accepted"):
                await pilot.click("#key-test")
                await self.wait(pilot, card)
            self.assertIn("Key accepted", self.card_text(card))
            await pilot.click("#key-close")
            await pilot.pause()
            self.assertIsNot(app.screen, card)


class ProfileTests(unittest.TestCase):
    def test_yaml_seeds_the_primary_and_saved_choice_wins(self):
        cfg = config.Config(ai={"provider": "anthropic", "model": "from-yaml", "auto_briefing": True})
        cfg.load_ai_profiles(None)
        self.assertEqual(cfg.ai_profiles[0], {"provider": "anthropic", "model": "from-yaml", "base_url": ""})
        self.assertEqual(cfg.ai_profiles[1], {"provider": "", "model": "", "base_url": ""})
        cfg.load_ai_profiles({"active": 1, "profiles": [{"provider": "gemini", "model": "g"}, {"provider": "openai", "model": "o"}]})
        self.assertEqual((cfg.ai["provider"], cfg.ai["model"], cfg.active_ai_profile), ("openai", "o", 1))
        self.assertTrue(cfg.ai["auto_briefing"])  # Other settings aren't touched

    def test_older_saved_choice_and_bad_index_still_load(self):
        cfg = config.Config()
        cfg.load_ai_profiles({"provider": "gemini", "model": "g", "base_url": ""})
        self.assertEqual(cfg.ai["provider"], "gemini")
        cfg.load_ai_profiles({"active": 9, "profiles": [{"provider": "openai", "model": "o"}]})
        self.assertEqual(cfg.active_ai_profile, 0)
        self.assertEqual(len(cfg.ai_profiles), config.AI_PROFILE_COUNT)

    def test_no_provider_runs_without_a_model(self):
        for provider in ai.PROVIDERS:
            problem = ai.configuration_problem({"provider": provider, "api_key": "k", "base_url": "http://x.test"})
            self.assertIn("Choose a model", problem)


class TemplateTests(unittest.TestCase):
    def test_tracked_template_holds_no_key_fields(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.assertEqual(yaml.safe_load(open(os.path.join(root, keystore.EXAMPLE_FILE))), None)  # All comments


if __name__ == "__main__":
    unittest.main()
