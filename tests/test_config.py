"""Validate Helm values settings and environment overrides."""

from __future__ import annotations

import copy
import os
import unittest
from collections.abc import Mapping
from types import SimpleNamespace
from typing import TYPE_CHECKING, cast
from unittest.mock import patch

from support import CONFIG, ROOT, SETTINGS, DexAuthProvider, DexSettings, config, register

if TYPE_CHECKING:
    from hermes_cli.plugins import PluginContext


def _registration_context(providers: list[DexAuthProvider]) -> PluginContext:
    return cast("PluginContext", SimpleNamespace(register_dashboard_auth_provider=providers.append))


class ConfigTests(unittest.TestCase):
    def _load(self, settings: object = None, env: Mapping[str, str] | None = None) -> DexSettings:
        loaded = config.load_settings(
            {"dashboard": {"oauth": {"dex": SETTINGS if settings is None else settings}}},
            environ={} if env is None else env,
        )
        assert loaded is not None
        return loaded

    def test_values_configuration_works_without_environment_variables(self) -> None:
        settings = self._load()
        self.assertEqual(settings["issuer"], SETTINGS["issuer"])
        self.assertEqual(settings["client_id"], "hermes-dashboard")
        self.assertEqual(settings["display_name"], "Dex")
        self.assertFalse(settings["insecure_skip_verify"])
        self.assertEqual(settings["client_secret"], "")

    def test_environment_overrides_config_and_blank_values_do_not(self) -> None:
        settings = self._load(
            env={
                "HERMES_DEX_ISSUER": "https://other.example.com/dex",
                "HERMES_DEX_CLIENT_ID": " ",
                "HERMES_DEX_CLIENT_SECRET": "secret",
                "HERMES_DEX_INSECURE_SKIP_VERIFY": "true",
            }
        )
        self.assertEqual(settings["issuer"], "https://other.example.com/dex")
        self.assertEqual(settings["client_id"], "hermes-dashboard")
        self.assertEqual(settings["client_secret"], "secret")
        self.assertTrue(settings["insecure_skip_verify"])

    def test_unconfigured_plugin_is_not_registered(self) -> None:
        with patch.object(config, "_read_hermes_config", return_value={}), patch.dict(os.environ, {}, clear=True):
            self.assertIsNone(config.load_settings())
            providers: list[DexAuthProvider] = []
            register(_registration_context(providers))
            self.assertEqual(providers, [])

    def test_registration_reads_hermes_configuration(self) -> None:
        providers: list[DexAuthProvider] = []
        with (
            patch.object(config, "_read_hermes_config", return_value=CONFIG),
            patch.dict(os.environ, {}, clear=True),
        ):
            register(_registration_context(providers))
        self.assertEqual([provider.name for provider in providers], ["dex"])

    def test_missing_endpoints_or_access_rules_are_errors(self) -> None:
        for key in ("issuer", "client_id", "access"):
            settings = copy.deepcopy(SETTINGS)
            del settings[key]
            with self.subTest(key=key), self.assertRaises(ValueError):
                self._load(settings)

    def test_bad_settings_do_not_register_a_provider(self) -> None:
        settings = copy.deepcopy(SETTINGS)
        settings["access"] = {}
        invalid_config = {"dashboard": {"oauth": {"dex": settings}}}
        providers: list[DexAuthProvider] = []
        with (
            patch.object(config, "_read_hermes_config", return_value=invalid_config),
            patch.dict(os.environ, {}, clear=True),
        ):
            with self.assertRaises(ValueError):
                register(_registration_context(providers))
        self.assertEqual(providers, [])

    def test_typo_and_wrong_types_are_errors(self) -> None:
        invalid_settings: tuple[dict[str, object], ...] = (
            {"acess": {}},
            {"tls": None},
            {"tls": {"insecure_skip_verify": "false"}},
            {"tls": {"ca_bundle": 1}},
            {"tls": {"verify": False}},
            {"display_name": ""},
        )
        for extra in invalid_settings:
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                self._load({**SETTINGS, **extra})
        invalid_configs: tuple[object, ...] = (
            {"dashboard": None},
            {"dashboard": {"oauth": []}},
            {"dashboard": {"oauth": {"dex": None}}},
        )
        for invalid_config in invalid_configs:
            with self.subTest(config=invalid_config), self.assertRaises(ValueError):
                config.load_settings(invalid_config, environ={})

    def test_tls_override_must_be_boolean(self) -> None:
        for value in ("1", "yes", "typo"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self._load(env={"HERMES_DEX_INSECURE_SKIP_VERIFY": value})

    def test_custom_ca_and_skip_verify_are_mutually_exclusive(self) -> None:
        with self.assertRaises(ValueError):
            self._load({**SETTINGS, "tls": {"ca_bundle": "/ca.crt", "insecure_skip_verify": True}})

    def test_example_values_load_into_the_provider(self) -> None:
        import hermes_yaml

        values: dict[str, object] = hermes_yaml.safe_load((ROOT / "examples/values.yaml").read_text(encoding="utf-8"))
        settings = config.load_settings(values["config"], environ={})
        assert settings is not None
        provider = DexAuthProvider(**settings)
        self.assertEqual(provider.name, "dex")


if __name__ == "__main__":
    unittest.main()
