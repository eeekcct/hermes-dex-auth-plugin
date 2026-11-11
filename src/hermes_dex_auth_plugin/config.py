"""Read dashboard.oauth.dex from Hermes config.yaml (Helm values.config)."""

import os
from collections.abc import Mapping
from typing import TypedDict, cast

from .policy import AccessPolicy, mapping, text

_ENV = {
    "issuer": "HERMES_DEX_ISSUER",
    "client_id": "HERMES_DEX_CLIENT_ID",
    "client_secret": "HERMES_DEX_CLIENT_SECRET",
    "ca_bundle": "HERMES_DEX_CA_BUNDLE",
    "insecure_skip_verify": "HERMES_DEX_INSECURE_SKIP_VERIFY",
}


class DexSettings(TypedDict):
    issuer: str
    client_id: str
    client_secret: str
    display_name: str
    insecure_skip_verify: bool
    ca_bundle: str
    access_policy: AccessPolicy


def _read_hermes_config() -> Mapping[str, object]:
    from hermes_cli.config import load_config_readonly

    return load_config_readonly()


def _section(config: object) -> Mapping[str, object] | None:
    value = config
    for key in ("dashboard", "oauth", "dex"):
        if not isinstance(value, Mapping):
            raise ValueError("dashboard.oauth.dex must be nested mappings")
        section = cast(Mapping[object, object], value)
        if key not in section:
            return None
        value = section[key]
    return mapping(
        value,
        field="dashboard.oauth.dex",
        keys=(
            "issuer",
            "client_id",
            "display_name",
            "tls",
            "access",
        ),
    )


def load_settings(config: object = None, *, environ: Mapping[str, str] | None = None) -> DexSettings | None:
    if config is None:
        config = _read_hermes_config()
    env = os.environ if environ is None else environ

    def setting(key: str) -> str:
        return env.get(_ENV[key], "")

    section = _section(config)
    if section is None and not any(setting(key) for key in ("issuer", "client_id")):
        return None
    if section is None:
        section = dict[str, object]()

    tls = mapping(section.get("tls", {}), field="tls", keys=("insecure_skip_verify", "ca_bundle"))
    skip_verify = tls.get("insecure_skip_verify", False)
    override = setting("insecure_skip_verify").strip().lower()
    if override:
        if override not in ("true", "false"):
            raise ValueError(f"{_ENV['insecure_skip_verify']} must be true or false")
        skip_verify = override == "true"
    if not isinstance(skip_verify, bool):
        raise ValueError("tls.insecure_skip_verify must be a boolean")
    ca_bundle = setting("ca_bundle").strip() or tls.get("ca_bundle", "")
    if not isinstance(ca_bundle, str):
        raise ValueError("tls.ca_bundle must be a string")
    if ca_bundle and skip_verify:
        raise ValueError("tls.ca_bundle and insecure_skip_verify cannot be used together")

    return {
        "issuer": text(setting("issuer").strip() or section.get("issuer"), field="issuer"),
        "client_id": text(setting("client_id").strip() or section.get("client_id"), field="client_id"),
        "client_secret": setting("client_secret").strip(),
        "display_name": text(section.get("display_name", "Dex"), field="display_name"),
        "insecure_skip_verify": skip_verify,
        "ca_bundle": ca_bundle,
        "access_policy": AccessPolicy.from_config(section.get("access", {})),
    }
