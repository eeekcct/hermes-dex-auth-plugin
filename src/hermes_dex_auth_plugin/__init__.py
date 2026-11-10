"""Hermes Dashboard authentication through Dex."""

from __future__ import annotations

from typing import TYPE_CHECKING

from .config import load_settings
from .provider import DexAuthProvider

if TYPE_CHECKING:
    from hermes_cli.plugins import PluginContext


def register(ctx: PluginContext) -> None:
    settings = load_settings()
    if settings is not None:
        # Hermes does not annotate this registration method's provider parameter.
        ctx.register_dashboard_auth_provider(DexAuthProvider(**settings))  # pyright: ignore[reportUnknownMemberType]
