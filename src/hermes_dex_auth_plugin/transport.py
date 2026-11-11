"""Provider-local TLS and same-origin checks for Dex OIDC endpoints."""

import ssl
from collections.abc import Mapping
from typing import TypedDict, Unpack
from urllib.parse import urlsplit

import httpx
from hermes_cli.dashboard_auth import ProviderError
from jwt import PyJWKClient
from plugins.dashboard_auth._shared import JSON_HEADERS, parse_json_body


class _RequestOptions(TypedDict, total=False):
    headers: Mapping[str, str]
    data: Mapping[str, str]


def _origin(url: str) -> tuple[str, str, int]:
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.hostname or parts.username or parts.password:
        raise ValueError("Dex endpoints must be HTTPS URLs without credentials")
    return parts.scheme, parts.hostname, parts.port or 443


class DexTransport:
    def __init__(self, issuer: str, *, insecure_skip_verify: bool = False, ca_bundle: str = "") -> None:
        self._origin = _origin(issuer)
        if urlsplit(issuer).query or urlsplit(issuer).fragment:
            raise ValueError("Dex issuer must not contain a query or fragment")
        if not isinstance(insecure_skip_verify, bool):
            raise ValueError("insecure_skip_verify must be a boolean")
        if not isinstance(ca_bundle, str):
            raise ValueError("ca_bundle must be a string")
        if ca_bundle and insecure_skip_verify:
            raise ValueError("ca_bundle and insecure_skip_verify cannot be used together")
        self._verify: ssl.SSLContext | bool = (
            ssl.create_default_context(cafile=ca_bundle) if ca_bundle else not insecure_skip_verify
        )

    def require_origin(self, url: str) -> None:
        try:
            if urlsplit(url).fragment or _origin(url) != self._origin:
                raise ValueError("Unexpected Dex endpoint origin or fragment")
        except (TypeError, ValueError) as exc:
            raise ProviderError("Dex OIDC endpoints must share the issuer's HTTPS origin") from exc

    def request(self, method: str, url: str, **kwargs: Unpack[_RequestOptions]) -> httpx.Response:
        self.require_origin(url)
        try:
            with httpx.Client(verify=self._verify, follow_redirects=False, timeout=10) as client:
                return client.request(method, url, **kwargs)
        except httpx.RequestError as exc:
            raise ProviderError(f"Dex OIDC endpoint unreachable: {exc}") from exc

    def jwks_client(self, uri: str) -> PyJWKClient:
        self.require_origin(uri)
        transport = self

        class DexJWKClient(PyJWKClient):
            def fetch_data(self) -> dict[str, object]:
                response = transport.request("GET", uri, headers=JSON_HEADERS)
                if response.status_code != 200:
                    raise ProviderError(f"OIDC JWKS endpoint returned {response.status_code}")
                data = parse_json_body(response)
                if self.jwk_set_cache is not None:
                    self.jwk_set_cache.put(data)
                return data

        # Per-key caching has no TTL and would keep trusting keys removed from Dex.
        return DexJWKClient(uri, cache_keys=False, lifespan=300)
