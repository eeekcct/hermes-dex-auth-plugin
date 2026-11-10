"""Dex OIDC provider; Hermes verifies JWTs before policy evaluation."""

from typing import cast

from hermes_cli.dashboard_auth import InvalidCodeError, ProviderError, Session
from jwt import PyJWKClient
from plugins.dashboard_auth._shared import (
    DEFAULT_TOKEN_LEEWAY_SECONDS,
    JSON_HEADERS,
    parse_json_body,
    refresh_token_from,
)
from plugins.dashboard_auth.self_hosted import SelfHostedOIDCProvider

from .policy import AccessPolicy
from .transport import DexTransport


class DexAuthProvider(SelfHostedOIDCProvider):
    name = "dex"
    display_name = "Dex"

    _jwks_client: PyJWKClient | None

    def __init__(
        self,
        *,
        issuer: str,
        client_id: str,
        access_policy: AccessPolicy,
        display_name: str = "Dex",
        insecure_skip_verify: bool = False,
        ca_bundle: str = "",
        client_secret: str = "",
        id_token_leeway: float = DEFAULT_TOKEN_LEEWAY_SECONDS,
    ) -> None:
        if not isinstance(access_policy, AccessPolicy):
            raise ValueError("access_policy must be an AccessPolicy")
        self._access_policy = access_policy
        self.display_name = display_name
        scopes = "openid profile email federated:id offline_access"
        if access_policy.groups:
            scopes += " groups"
        super().__init__(
            issuer=issuer,
            client_id=client_id,
            scopes=scopes,
            client_secret=client_secret,
            id_token_leeway=id_token_leeway,
        )
        self._transport = DexTransport(
            self._issuer,
            insecure_skip_verify=insecure_skip_verify,
            ca_bundle=ca_bundle,
        )

    def _fetch_discovery(self) -> dict[str, object]:
        response = self._transport.request(
            "GET",
            f"{self._issuer}/.well-known/openid-configuration",
            headers=JSON_HEADERS,
        )
        if response.status_code != 200:
            raise ProviderError(f"OIDC discovery returned {response.status_code}")
        payload = parse_json_body(response)
        advertised = str(payload.get("issuer") or "").strip()
        if not advertised or advertised.rstrip("/") != self._issuer:
            raise ProviderError("OIDC discovery issuer mismatch")
        discovery: dict[str, object] = {"issuer": advertised}
        for field in ("authorization_endpoint", "token_endpoint", "jwks_uri", "revocation_endpoint"):
            endpoint = str(payload.get(field) or "").strip()
            if not endpoint and field != "revocation_endpoint":
                raise ProviderError(f"OIDC discovery missing {field}")
            if endpoint:
                self._transport.require_origin(endpoint)
            discovery[field] = endpoint
        methods = payload.get("token_endpoint_auth_methods_supported")
        discovery["token_endpoint_auth_methods_supported"] = methods if isinstance(methods, list) else []
        return discovery

    def _grant(
        self,
        data: dict[str, str],
        *,
        bad_request_exc: type[Exception],
        headers: dict[str, str] | None = None,
        previous_refresh_token: str = "",
    ) -> Session:
        discovery: dict[str, object] = self._get_discovery()
        extra_data, extra_headers = self._token_endpoint_auth(discovery)
        response = self._transport.request(
            "POST",
            cast(str, discovery["token_endpoint"]),
            data={**data, **extra_data},
            headers={**JSON_HEADERS, **(headers or {}), **extra_headers},
        )
        if response.status_code == 400:
            error = parse_json_body(response).get("error", "invalid_request")
            raise bad_request_exc(f"IDP rejected token request: {error}")
        if response.status_code != 200:
            raise ProviderError(f"OIDC token endpoint returned {response.status_code}")
        payload = parse_json_body(response)
        token = payload.get("id_token")
        if not isinstance(token, str) or not token:
            raise ProviderError("OIDC token response missing id_token")
        if str(payload.get("token_type", "")).lower() not in ("", "bearer"):
            raise ProviderError("OIDC token response has an unexpected token_type")
        claims = self._verify_id_token(token)
        return self._session(token, refresh_token_from(payload, previous_refresh_token), claims)

    def _get_jwks_client(self) -> PyJWKClient:
        if self._jwks_client is None:
            self._jwks_client = self._transport.jwks_client(self._jwks_uri())
        return self._jwks_client

    def revoke_session(self, *, refresh_token: str) -> None:
        if not refresh_token:
            return
        try:
            discovery: dict[str, object] = self._get_discovery()
            endpoint = discovery.get("revocation_endpoint")
            if endpoint:
                extra_data, extra_headers = self._token_endpoint_auth(discovery)
                self._transport.request(
                    "POST",
                    cast(str, endpoint),
                    data={
                        "token": refresh_token,
                        "token_type_hint": "refresh_token",
                        "client_id": self._client_id,
                        **extra_data,
                    },
                    headers={**JSON_HEADERS, **extra_headers},
                )
        except Exception:
            # RFC 7009 revocation is best effort; logout still clears the cookie.
            pass

    def _verify_id_token(self, id_token: str) -> dict[str, object]:
        claims: dict[str, object] = super()._verify_id_token(id_token)
        if not self._access_policy.allows(claims):
            raise InvalidCodeError("This Dex identity is not allowed to access the dashboard")
        return claims

    # The superclass aliases this hook for verification on every authenticated request.
    _claims_for = _verify_id_token
