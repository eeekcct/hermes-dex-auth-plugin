"""Shared settings and imports for the Dex plugin package."""

from pathlib import Path

from hermes_dex_auth_plugin import config as config
from hermes_dex_auth_plugin import register as register
from hermes_dex_auth_plugin.config import DexSettings as DexSettings
from hermes_dex_auth_plugin.policy import AccessPolicy as AccessPolicy
from hermes_dex_auth_plugin.provider import DexAuthProvider as DexAuthProvider

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "src" / "hermes_dex_auth_plugin"

OWNER = "test-user-id"
SETTINGS: dict[str, object] = {
    "issuer": "https://dex.example.com/dex",
    "client_id": "hermes-dashboard",
    "access": {"users": [{"connector_id": "github", "user_id": OWNER}]},
}
CONFIG: dict[str, object] = {"dashboard": {"oauth": {"dex": SETTINGS}}}
OWNER_POLICY = AccessPolicy.from_config(SETTINGS["access"])
