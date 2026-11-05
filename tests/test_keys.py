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
        self.assertEqual(store.movable(), ["ai_api_key", "nvd_api_key"])
        moved, problems = store.move_all()
        self.assertEqual((moved, problems), (["ai_api_key", "nvd_api_key"], []))
        self.assertEqual(chain.data[("cybrwire", "ai_api_key")], KEY)
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
        self.assertEqual(store.resolve_all(store.read_yaml_values())["ai_api_key"], (KEY, FILE))
        self.assertNotIn(KEY, open(self.local).read())

    def test_uneditable_yaml_is_reported_and_key_still_works(self):
        self.write("cybrwire_local.yaml", f'ai: {{provider: x, api_key: "{KEY}"}}\n')
        chain = FakeKeychain()
        store = self.store(chain)
        moved, problems = store.move_all()
        self.assertEqual(moved, [])
        self.assertIn("by hand", problems[0])
        self.assertEqual(store.resolve_all(store.read_yaml_values())["ai_api_key"][0], KEY)

    def test_stale_yaml_copy_does_not_overwrite_a_newer_keychain_key(self):
        chain = FakeKeychain()
        chain.data[("cybrwire", "ai_api_key")] = "newer-key-in-keychain"
        store = self.store(chain)
        store.move_all()
        self.assertEqual(chain.data[("cybrwire", "ai_api_key")], "newer-key-in-keychain")
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
        await self.check("ai_api_key", 200, {"provider": "anthropic"}, seen)
        self.assertEqual(seen[0].method, "GET")
        self.assertEqual(seen[0].url.path, "/v1/models")
        self.assertEqual(seen[0].headers["x-api-key"], KEY)

    async def test_ai_providers_use_free_endpoints(self):
        for settings, path in (({"provider": "gemini"}, "/v1beta/models"), ({"provider": "openai"}, "/v1/models"),
                               ({"provider": "openrouter"}, "/api/v1/key"),
                               ({"provider": "openai_compatible", "base_url": "http://x.test/v1/"}, "/v1/models")):
            seen = []
            await self.check("ai_api_key", 200, settings, seen)
            self.assertEqual((seen[0].method, seen[0].url.path), ("GET", path))

    async def test_ai_key_without_provider_cannot_be_tested(self):
        result = await key_check.check_key("ai_api_key", KEY, {}, {})
        self.assertEqual(result.status, key_check.UNKNOWN)
        self.assertIn("ai.provider", result.message)

    async def test_notification_only_contacts_the_slot_under_test(self):
        calls = {}

        async def send(settings, title, body):
            calls.update(settings)
            return {"discord": None}
        with mock.patch.object(key_check.notify, "send", send):
            result = await key_check.check_key("discord_webhook", "https://d.test/h", {}, {"slack_webhook": "https://s.test"})
        self.assertEqual(result.status, key_check.OK)
        self.assertEqual(calls, {"discord_webhook": "https://d.test/h"})

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
        return str(card.query_one("#key-card").render()) + str(card.query_one("#key-card-status").render())

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


class TemplateTests(unittest.TestCase):
    def test_tracked_template_holds_no_key_fields(self):
        path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "usrwire.yaml")
        data = yaml.safe_load(open(path)) or {}
        self.assertNotIn("enrichment", data)
        self.assertNotIn("ai", data)


if __name__ == "__main__":
    unittest.main()
