"""Run with the Python environment from nousresearch/hermes-agent:v0.23.0."""

import json
import os
import shutil
import ssl
import tempfile
import threading
import time
import unittest
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from typing import ClassVar, cast
from unittest.mock import Mock, patch

import httpx
import jwt
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from hermes_cli.dashboard_auth import InvalidCodeError, ProviderError, RefreshExpiredError
from jwt.algorithms import RSAAlgorithm
from support import CONFIG, OWNER_POLICY, PACKAGE, ROOT, AccessPolicy, DexAuthProvider

ISSUER = "https://dex.example.com/api/dex"
CLIENT = "hermes-dashboard"
OWNER = "test-user-id"


class GitHubIdentityTests(unittest.TestCase):
    key: ClassVar[rsa.RSAPrivateKey]

    @classmethod
    def setUpClass(cls) -> None:
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def setUp(self) -> None:
        self.provider = DexAuthProvider(
            issuer=ISSUER,
            client_id=CLIENT,
            access_policy=OWNER_POLICY,
        )
        self.discovery = patch.object(
            self.provider, "_get_discovery", return_value={"issuer": ISSUER, "token_endpoint": ISSUER + "/token"}
        )
        self.discovery.start()
        self.addCleanup(self.discovery.stop)
        jwks = patch.object(
            self.provider,
            "_jwks_client",
            SimpleNamespace(get_signing_key_from_jwt=Mock(return_value=SimpleNamespace(key=self.key.public_key()))),
        )
        jwks.start()
        self.addCleanup(jwks.stop)

    def _token(
        self,
        *,
        identity: dict[str, str] | None = None,
        signing_key: rsa.RSAPrivateKey | None = None,
        key_id: str = "test-key",
        **overrides: object,
    ) -> str:
        now = int(time.time())
        claims: dict[str, object] = {
            "iss": ISSUER,
            "aud": CLIENT,
            "sub": "dex-opaque-subject",
            "email": "user@example.test",
            "email_verified": True,
            "iat": now,
            "exp": now + 300,
            "federated_claims": identity or {"connector_id": "github", "user_id": OWNER},
        }
        claims.update(overrides)
        return jwt.encode(claims, signing_key or self.key, algorithm="RS256", headers={"kid": key_id})

    def test_removed_signing_key_is_rejected_after_jwks_cache_expiry(self) -> None:
        replacement_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        old_jwk: dict[str, object] = json.loads(RSAAlgorithm.to_jwk(self.key.public_key()))
        old_jwk["kid"] = "test-key"
        new_jwk: dict[str, object] = json.loads(RSAAlgorithm.to_jwk(replacement_key.public_key()))
        new_jwk["kid"] = "replacement-key"
        old_token = self._token()
        new_token = self._token(signing_key=replacement_key, key_id="replacement-key")
        client = self.provider._transport.jwks_client(ISSUER + "/keys")

        # Advance only the JWKS clock so token expiry and discovery refresh cannot mask stale keys.
        started = time.monotonic()
        with (
            patch.object(self.provider, "_jwks_client", client),
            patch.object(
                self.provider._transport, "request", return_value=httpx.Response(200, json={"keys": [old_jwk]})
            ) as request,
            patch("jwt.jwk_set_cache.time.monotonic", return_value=started) as clock,
        ):
            self.assertIsNotNone(self.provider.verify_session(access_token=old_token))
            request.return_value = httpx.Response(200, json={"keys": [new_jwk]})
            clock.return_value = started + 299
            self.assertIsNotNone(self.provider.verify_session(access_token=old_token))
            self.assertEqual(request.call_count, 1)

            clock.return_value = started + 301
            self.assertIsNotNone(self.provider.verify_session(access_token=new_token))
            self.assertEqual(request.call_count, 2)
            with self.assertRaises((InvalidCodeError, ProviderError)):
                self.provider._verify_id_token(old_token)

    def test_owner_receives_github_session(self) -> None:
        session = self.provider.verify_session(access_token=self._token())
        self.assertIsNotNone(session)
        assert session is not None
        self.assertEqual(session.provider, "dex")

    def test_another_github_user_is_rejected_at_login_and_on_every_request(self) -> None:
        token = self._token(identity={"connector_id": "github", "user_id": "999"})
        with self.assertRaises(InvalidCodeError):
            self.provider._verify_id_token(token)
        self.assertIsNone(self.provider.verify_session(access_token=token))

    def test_another_connector_cannot_reuse_the_same_numeric_user_id(self) -> None:
        token = self._token(identity={"connector_id": "other", "user_id": OWNER})
        self.assertIsNone(self.provider.verify_session(access_token=token))

    def test_missing_or_malformed_identity_is_rejected(self) -> None:
        malformed_identities: tuple[object, ...] = (None, [], "github", {"connector_id": "github"})
        for identity in malformed_identities:
            with self.subTest(identity=identity):
                token = self._token(federated_claims=identity)
                self.assertIsNone(self.provider.verify_session(access_token=token))

    def test_invalid_signature_is_rejected(self) -> None:
        other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with self.assertRaises((InvalidCodeError, ProviderError)):
            self.provider._verify_id_token(self._token(signing_key=other_key))

    def test_wrong_issuer_and_audience_are_rejected(self) -> None:
        invalid_tokens = (
            ("iss", self._token(iss="https://other.example")),
            ("aud", self._token(aud="another-client")),
        )
        for claim, token in invalid_tokens:
            with self.subTest(claim=claim):
                with self.assertRaises((InvalidCodeError, ProviderError)):
                    self.provider._verify_id_token(token)

    def test_expired_token_is_rejected(self) -> None:
        self.assertIsNone(self.provider.verify_session(access_token=self._token(exp=int(time.time()) - 120)))

    def test_owner_allowlist_cannot_be_empty(self) -> None:
        with self.assertRaises(ValueError):
            DexAuthProvider(issuer=ISSUER, client_id=CLIENT, access_policy=cast(AccessPolicy, None))

    def test_verified_group_members_can_log_in_refresh_and_make_requests(self) -> None:
        policy = AccessPolicy.from_config(
            {
                "groups": [{"connector_id": "github", "name": "my-org:platform"}],
            }
        )
        self.provider._access_policy = policy
        allowed = self._token(groups=["my-org:platform"])
        self.assertIsNotNone(self.provider.verify_session(access_token=allowed))
        response = httpx.Response(200, json={"id_token": allowed, "token_type": "Bearer"})
        with patch.object(self.provider._transport, "request", return_value=response):
            self.assertEqual(
                self.provider.complete_login(
                    code="code",
                    state="state",
                    code_verifier="verifier",
                    redirect_uri="http://localhost:9119/auth/callback",
                ).provider,
                "dex",
            )
            self.assertEqual(self.provider.refresh_session(refresh_token="refresh").provider, "dex")
        denied = self._token(groups=["my-org:other"])
        self.assertIsNone(self.provider.verify_session(access_token=denied))
        response = httpx.Response(200, json={"id_token": denied, "token_type": "Bearer"})
        with patch.object(self.provider._transport, "request", return_value=response):
            with self.assertRaises(RefreshExpiredError):
                self.provider.refresh_session(refresh_token="refresh")

    def test_email_only_members_can_log_in_refresh_and_make_requests(self) -> None:
        self.provider._access_policy = AccessPolicy.from_config(
            {"emails": [{"connector_id": "github", "email": "member@example.test"}]}
        )
        token = self._token(email="member@example.test")
        self.assertNotIn("groups", self.provider._scopes.split())
        self.assertIsNotNone(self.provider.verify_session(access_token=token))
        response = httpx.Response(200, json={"id_token": token, "refresh_token": "refresh", "token_type": "Bearer"})
        with patch.object(self.provider._transport, "request", return_value=response):
            session = self.provider.complete_login(
                code="code", state="state", code_verifier="verifier", redirect_uri="http://localhost:9119/auth/callback"
            )
            self.assertEqual(session.email, "member@example.test")
            self.assertEqual(session.access_token, token)
            self.assertEqual(session.refresh_token, "refresh")
            self.assertEqual(self.provider.refresh_session(refresh_token="refresh").email, "member@example.test")

    def test_email_rules_reject_invalid_claims_at_login_refresh_and_request(self) -> None:
        self.provider._access_policy = AccessPolicy.from_config(
            {"emails": [{"connector_id": "github", "email": "user@example.test"}]}
        )
        invalid_tokens = (
            ("different email", self._token(email="other@example.test")),
            ("null email", self._token(email=None)),
            ("empty email", self._token(email="")),
            ("non-string email", self._token(email=["user@example.test"])),
            ("unverified email", self._token(email_verified=False)),
            ("string verified flag", self._token(email_verified="true")),
            ("numeric verified flag", self._token(email_verified=1)),
            ("different connector", self._token(federated_claims={"connector_id": "other", "user_id": OWNER})),
            ("missing user ID", self._token(federated_claims={"connector_id": "github"})),
        )
        for label, token in invalid_tokens:
            with self.subTest(invalid=label):
                self.assertIsNone(self.provider.verify_session(access_token=token))
                response = httpx.Response(200, json={"id_token": token, "token_type": "Bearer"})
                with patch.object(self.provider._transport, "request", return_value=response):
                    with self.assertRaises(InvalidCodeError):
                        self.provider.complete_login(
                            code="code",
                            state="state",
                            code_verifier="verifier",
                            redirect_uri="http://localhost:9119/auth/callback",
                        )
                    with self.assertRaises(RefreshExpiredError):
                        self.provider.refresh_session(refresh_token="refresh")

    def test_matching_email_does_not_bypass_signature_verification(self) -> None:
        self.provider._access_policy = AccessPolicy.from_config(
            {"emails": [{"connector_id": "github", "email": "user@example.test"}]}
        )
        other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        token = self._token(signing_key=other_key)
        self.assertIsNone(self.provider.verify_session(access_token=token))
        response = httpx.Response(200, json={"id_token": token, "token_type": "Bearer"})
        with patch.object(self.provider._transport, "request", return_value=response):
            with self.assertRaises(InvalidCodeError):
                self.provider.complete_login(
                    code="code",
                    state="state",
                    code_verifier="verifier",
                    redirect_uri="http://localhost:9119/auth/callback",
                )
            with self.assertRaises(RefreshExpiredError):
                self.provider.refresh_session(refresh_token="refresh")

    def test_removing_email_permission_rejects_existing_session_and_refresh(self) -> None:
        self.provider._access_policy = AccessPolicy.from_config(
            {"emails": [{"connector_id": "github", "email": "user@example.test"}]}
        )
        token = self._token()
        self.assertIsNotNone(self.provider.verify_session(access_token=token))
        self.provider._access_policy = AccessPolicy.from_config(
            {"emails": [{"connector_id": "github", "email": "other@example.test"}]}
        )
        self.assertIsNone(self.provider.verify_session(access_token=token))
        response = httpx.Response(200, json={"id_token": token, "token_type": "Bearer"})
        with patch.object(self.provider._transport, "request", return_value=response):
            with self.assertRaises(RefreshExpiredError):
                self.provider.refresh_session(refresh_token="refresh")

    def test_group_scope_is_requested_only_when_group_rules_are_configured(self) -> None:
        self.assertNotIn("groups", self.provider._scopes.split())
        provider = DexAuthProvider(
            issuer=ISSUER,
            client_id=CLIENT,
            access_policy=AccessPolicy.from_config(
                {
                    "groups": [{"connector_id": "github", "name": "my-org:platform"}],
                }
            ),
        )
        self.assertIn("groups", provider._scopes.split())

    def test_group_membership_does_not_bypass_signature_or_connector_checks(self) -> None:
        self.provider._access_policy = AccessPolicy.from_config(
            {
                "groups": [{"connector_id": "github", "name": "my-org:platform"}],
            }
        )
        wrong_connector = self._token(
            identity={"connector_id": "other", "user_id": OWNER},
            groups=["my-org:platform"],
        )
        self.assertIsNone(self.provider.verify_session(access_token=wrong_connector))
        other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        invalid_signature = self._token(signing_key=other_key, groups=["my-org:platform"])
        with self.assertRaises((InvalidCodeError, ProviderError)):
            self.provider._verify_id_token(invalid_signature)

    def test_login_and_refresh_reject_another_users_valid_token(self) -> None:
        token = self._token(identity={"connector_id": "github", "user_id": "999"})
        response = httpx.Response(200, json={"id_token": token, "refresh_token": "refresh", "token_type": "Bearer"})
        with patch.object(self.provider._transport, "request", return_value=response):
            with self.assertRaises(InvalidCodeError):
                self.provider.complete_login(
                    code="code",
                    state="state",
                    code_verifier="verifier",
                    redirect_uri="http://192.168.0.152:9119/auth/callback",
                )
            with self.assertRaises(RefreshExpiredError):
                self.provider.refresh_session(refresh_token="refresh")

    def test_login_and_refresh_require_bearer_token_type(self) -> None:
        token = self._token()
        invalid_types: tuple[dict[str, object], ...] = (
            {},
            {"token_type": ""},
            {"token_type": None},
            {"token_type": "Basic"},
            {"token_type": "Bearer "},
            {"token_type": 1},
            {"token_type": True},
            {"token_type": []},
            {"token_type": {}},
        )
        for extra in invalid_types:
            with self.subTest(extra=extra):
                response = httpx.Response(200, json={"id_token": token, **extra})
                with patch.object(self.provider._transport, "request", return_value=response):
                    with self.assertRaisesRegex(ProviderError, "unexpected token_type"):
                        self.provider.complete_login(
                            code="code",
                            state="state",
                            code_verifier="verifier",
                            redirect_uri="http://localhost:9119/auth/callback",
                        )
                    with self.assertRaisesRegex(ProviderError, "unexpected token_type"):
                        self.provider.refresh_session(refresh_token="refresh")

    def test_bearer_token_type_is_case_insensitive(self) -> None:
        token = self._token()
        for token_type in ("bearer", "Bearer", "BEARER"):
            with self.subTest(token_type=token_type):
                response = httpx.Response(200, json={"id_token": token, "token_type": token_type})
                with patch.object(self.provider._transport, "request", return_value=response):
                    session = self.provider.complete_login(
                        code="code",
                        state="state",
                        code_verifier="verifier",
                        redirect_uri="http://localhost:9119/auth/callback",
                    )
                    self.assertEqual(session.access_token, token)
                    self.assertEqual(self.provider.refresh_session(refresh_token="refresh").access_token, token)

    def test_invalid_token_times_keep_login_and_refresh_error_semantics(self) -> None:
        future = int(time.time()) + 3600
        tokens = (
            ("expired", self._token(exp=1)),
            ("future issuance", self._token(iat=future)),
            ("not yet valid", self._token(nbf=future)),
        )
        for label, token in tokens:
            with self.subTest(token=label):
                self.assertIsNone(self.provider.verify_session(access_token=token))
                response = httpx.Response(200, json={"id_token": token, "token_type": "Bearer"})
                with patch.object(self.provider._transport, "request", return_value=response):
                    with self.assertRaises(InvalidCodeError):
                        self.provider.complete_login(
                            code="code",
                            state="state",
                            code_verifier="verifier",
                            redirect_uri="http://localhost:9119/auth/callback",
                        )
                    with self.assertRaises(RefreshExpiredError):
                        self.provider.refresh_session(refresh_token="refresh")

    def test_provider_outages_remain_provider_errors_during_grants(self) -> None:
        response = httpx.Response(200, json={"id_token": self._token(), "token_type": "Bearer"})
        outage = ProviderError("JWKS unavailable")
        with (
            patch.object(self.provider._transport, "request", return_value=response),
            patch.object(self.provider, "_verify_id_token", side_effect=outage),
        ):
            with self.assertRaises(ProviderError) as login_error:
                self.provider.complete_login(
                    code="code",
                    state="state",
                    code_verifier="verifier",
                    redirect_uri="http://localhost:9119/auth/callback",
                )
            self.assertIs(login_error.exception, outage)
            with self.assertRaises(ProviderError) as refresh_error:
                self.provider.refresh_session(refresh_token="refresh")
            self.assertIs(refresh_error.exception, outage)

    def test_rejected_grants_keep_login_and_refresh_error_semantics(self) -> None:
        response = httpx.Response(400, json={"error": "invalid_grant"})
        with patch.object(self.provider._transport, "request", return_value=response):
            with self.assertRaises(InvalidCodeError):
                self.provider.complete_login(
                    code="code",
                    state="state",
                    code_verifier="verifier",
                    redirect_uri="http://192.168.0.152:9119/auth/callback",
                )
            with self.assertRaises(RefreshExpiredError):
                self.provider.refresh_session(refresh_token="expired")


class PluginLoadingTests(unittest.TestCase):
    def test_bundled_backend_registers_using_values_configuration(self) -> None:
        from hermes_cli.dashboard_auth.registry import clear_providers, list_providers
        from hermes_cli.plugins import PluginManager

        clear_providers()
        self.addCleanup(clear_providers)
        with tempfile.TemporaryDirectory() as root:
            plugins = Path(root) / "plugins"
            destination = plugins / "dashboard_auth/dex-auth"
            destination.mkdir(parents=True)
            for path in [*PACKAGE.glob("*.py"), ROOT / "plugin.yaml"]:
                shutil.copyfile(path, destination / path.name)
            with (
                patch.dict(
                    os.environ,
                    {
                        "HERMES_BUNDLED_PLUGINS": str(plugins),
                        "HERMES_HOME": str(Path(root) / "home"),
                    },
                    clear=True,
                ),
                patch("hermes_cli.config.load_config_readonly", return_value=CONFIG),
            ):
                manager = PluginManager()
                manager.discover_and_load()
                self.assertEqual([p.name for p in list_providers()], ["dex"])
                self.assertEqual(manager._plugins["dashboard_auth/dex-auth"].manifest.source, "bundled")

    def test_source_checkout_registers_as_a_directory_plugin(self) -> None:
        from hermes_cli.dashboard_auth.registry import clear_providers, list_providers
        from hermes_cli.plugins import PluginManager

        clear_providers()
        self.addCleanup(clear_providers)
        with tempfile.TemporaryDirectory() as root:
            home = Path(root) / "home"
            destination = home / "plugins" / "dex-auth"
            destination.mkdir(parents=True)
            shutil.copytree(
                PACKAGE, destination / "src" / "hermes_dex_auth_plugin", ignore=shutil.ignore_patterns("__pycache__")
            )
            for filename in ("__init__.py", "plugin.yaml"):
                shutil.copyfile(ROOT / filename, destination / filename)
            (home / "config.yaml").write_text(
                json.dumps({**CONFIG, "plugins": {"enabled": ["dex-auth"]}}), encoding="utf-8"
            )
            with patch.dict(
                os.environ,
                {"HERMES_BUNDLED_PLUGINS": str(Path(root) / "bundled"), "HERMES_HOME": str(home)},
                clear=True,
            ):
                manager = PluginManager()
                manager.discover_and_load()
                self.assertEqual([p.name for p in list_providers()], ["dex"])
                self.assertEqual(manager._plugins["dex-auth"].manifest.source, "user")

    def test_installed_entrypoint_registers_using_values_configuration(self) -> None:
        from hermes_cli.dashboard_auth.registry import clear_providers, list_providers
        from hermes_cli.plugins import PluginManager

        clear_providers()
        self.addCleanup(clear_providers)
        with tempfile.TemporaryDirectory() as root:
            home = Path(root) / "home"
            home.mkdir()
            (home / "config.yaml").write_text(
                json.dumps({**CONFIG, "plugins": {"enabled": ["dex-auth"]}}), encoding="utf-8"
            )
            with patch.dict(
                os.environ,
                {"HERMES_BUNDLED_PLUGINS": str(Path(root) / "bundled"), "HERMES_HOME": str(home)},
                clear=True,
            ):
                manager = PluginManager()
                manager.discover_and_load()
                self.assertEqual([p.name for p in list_providers()], ["dex"])
                self.assertEqual(manager._plugins["dex-auth"].manifest.source, "entrypoint")


@dataclass
class _OIDCFixture:
    certificate: x509.Certificate
    calls: list[tuple[str, str, bytes]] = field(default_factory=list[tuple[str, str, bytes]])
    overrides: dict[str, tuple[int, dict[str, object]]] = field(
        default_factory=dict[str, tuple[int, dict[str, object]]]
    )
    issuer: str = ""
    cert_path: Path = field(init=False)
    provider: DexAuthProvider = field(init=False)


class TLSTests(unittest.TestCase):
    key: ClassVar[rsa.RSAPrivateKey]

    @classmethod
    def setUpClass(cls) -> None:
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    @contextmanager
    def _oidc_server(self, *, hostname: str = "localhost", expired: bool = False) -> Generator[_OIDCFixture]:
        now = datetime.now(timezone.utc)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
        certificate = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(self.key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=2))
            .not_valid_after(now + timedelta(days=-1 if expired else 1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(self.key, hashes.SHA256())
        )
        fixture = _OIDCFixture(certificate=certificate)

        class Handler(BaseHTTPRequestHandler):
            def handle(self) -> None:
                try:
                    super().handle()
                except BrokenPipeError, ConnectionResetError:
                    # Clients can disconnect when rejecting a TLS certificate.
                    pass

            def log_message(self, format: str, *args: object) -> None:
                pass

            def do_GET(self) -> None:
                self._respond()

            def do_POST(self) -> None:
                self._respond()

            def _respond(self) -> None:
                body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
                fixture.calls.append((self.command, self.path, body))
                now = int(time.time())
                token = jwt.encode(
                    {
                        "iss": fixture.issuer,
                        "aud": CLIENT,
                        "sub": "dex-owner",
                        "email": "user@example.test",
                        "email_verified": True,
                        "iat": now,
                        "exp": now + 300,
                        "federated_claims": {"connector_id": "github", "user_id": OWNER},
                    },
                    TLSTests.key,
                    algorithm="RS256",
                    headers={"kid": "test-key"},
                )
                jwk: dict[str, object] = json.loads(RSAAlgorithm.to_jwk(TLSTests.key.public_key()))
                jwk["kid"] = "test-key"
                payloads: dict[str, dict[str, object]] = {
                    "/api/dex/.well-known/openid-configuration": {
                        "issuer": fixture.issuer,
                        "authorization_endpoint": fixture.issuer + "/auth",
                        "token_endpoint": fixture.issuer + "/token",
                        "jwks_uri": fixture.issuer + "/keys",
                        "revocation_endpoint": fixture.issuer + "/revoke",
                    },
                    "/api/dex/keys": {"keys": [jwk]},
                    "/api/dex/token": {"id_token": token, "refresh_token": "refresh", "token_type": "Bearer"},
                    "/api/dex/revoke": {},
                }
                payload = payloads[self.path]
                status, payload = fixture.overrides.get(self.path, (200, payload))
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                if status == 302:
                    self.send_header("Location", fixture.issuer + "/redirect-target")
                self.end_headers()
                self.wfile.write(json.dumps(payload).encode())

        with tempfile.TemporaryDirectory() as root:
            cert_path, key_path = Path(root) / "tls.crt", Path(root) / "tls.key"
            cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
            fixture.cert_path = cert_path
            key_path.write_bytes(
                self.key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                )
            )
            server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert_path, key_path)
            server.socket = context.wrap_socket(server.socket, server_side=True)
            fixture.issuer = f"https://localhost:{server.server_port}/api/dex"
            fixture.provider = DexAuthProvider(
                issuer=fixture.issuer,
                client_id=CLIENT,
                access_policy=OWNER_POLICY,
                insecure_skip_verify=True,
            )
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                with patch.dict(os.environ, {"NO_PROXY": "localhost,127.0.0.1"}):
                    yield fixture
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)

    def test_real_https_discovery_login_jwks_refresh_and_logout(self) -> None:
        with self._oidc_server() as fixture:
            provider = fixture.provider
            provider.start_login(redirect_uri="http://localhost:9119/auth/callback")
            session = provider.complete_login(
                code="code",
                state="state",
                code_verifier="verifier",
                redirect_uri="http://localhost:9119/auth/callback",
            )
            self.assertEqual(session.provider, "dex")
            self.assertIsNotNone(provider.verify_session(access_token=session.access_token))
            self.assertEqual(provider.refresh_session(refresh_token=session.refresh_token).user_id, session.user_id)
            provider.revoke_session(refresh_token=session.refresh_token)
            paths = [path for _, path, _ in fixture.calls]
            self.assertEqual(paths.count("/api/dex/.well-known/openid-configuration"), 1)
            self.assertEqual(paths.count("/api/dex/keys"), 1)
            self.assertEqual(paths.count("/api/dex/token"), 2)
            self.assertIn("/api/dex/revoke", paths)

    def test_default_tls_verification_rejects_self_signed_certificate(self) -> None:
        with self._oidc_server() as fixture:
            fixture.provider = DexAuthProvider(
                issuer=fixture.issuer,
                client_id=CLIENT,
                access_policy=OWNER_POLICY,
            )
            with self.assertRaises(ProviderError):
                fixture.provider._get_discovery()
            self.assertEqual(fixture.calls, [])

    def test_custom_ca_bundle_allows_verified_https(self) -> None:
        with self._oidc_server() as fixture:
            provider = DexAuthProvider(
                issuer=fixture.issuer,
                client_id=CLIENT,
                access_policy=OWNER_POLICY,
                ca_bundle=str(fixture.cert_path),
            )
            session = provider.complete_login(
                code="code",
                state="state",
                code_verifier="verifier",
                redirect_uri="http://localhost:9119/auth/callback",
            )
            self.assertEqual(session.provider, "dex")

    def test_issuer_queries_fragments_credentials_and_invalid_ports_are_rejected(self) -> None:
        for issuer in (
            "https://dex.example.com/?query=1",
            "https://dex.example.com/#fragment",
            "https://user:password@dex.example.com",
            "https://dex.example.com:invalid",
        ):
            with self.subTest(issuer=issuer), self.assertRaises((ValueError, ProviderError)):
                DexAuthProvider(issuer=issuer, client_id=CLIENT, access_policy=OWNER_POLICY)

    def test_expired_or_wrong_hostname_certificate_works_when_skip_is_enabled(self) -> None:
        for hostname, expired in (("wrong.example", False), ("localhost", True)):
            with (
                self.subTest(hostname=hostname, expired=expired),
                self._oidc_server(hostname=hostname, expired=expired) as fixture,
            ):
                session = fixture.provider.complete_login(
                    code="code",
                    state="state",
                    code_verifier="verifier",
                    redirect_uri="http://localhost:9119/auth/callback",
                )
                self.assertEqual(session.provider, "dex")

    def test_skip_does_not_change_global_ca_settings(self) -> None:
        with self._oidc_server() as fixture:
            environment = dict(os.environ)
            fixture.provider._get_discovery()
            context = ssl.create_default_context()
            self.assertTrue(context.check_hostname)
            self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
            self.assertEqual(dict(os.environ), environment)

    def test_token_and_jwks_use_the_same_tls_verification_setting(self) -> None:
        for endpoint in ("token", "keys"):
            with self.subTest(endpoint=endpoint), self._oidc_server() as fixture:
                provider = fixture.provider
                provider._get_discovery()
                fixture.calls.clear()
                provider._transport._verify = True
                with self.assertRaises(ProviderError):
                    if endpoint == "token":
                        provider.refresh_session(refresh_token="refresh")
                    else:
                        # Use a real signed token so the JWKS lookup reaches TLS.
                        token = jwt.encode({"sub": "owner"}, self.key, algorithm="RS256", headers={"kid": "test-key"})
                        provider._verify_id_token(token)
                self.assertEqual(fixture.calls, [])

    def test_discovery_cannot_change_issuer_or_send_tokens_to_another_origin(self) -> None:
        for overrides in (
            {"issuer": "https://other.example"},
            {"issuer": None},
            {"token_endpoint": "https://other.example/token"},
            {"jwks_uri": "http://localhost/keys"},
            {"revocation_endpoint": "https://other.example/revoke"},
        ):
            with self.subTest(overrides=overrides), self._oidc_server() as fixture:
                issuer = fixture.issuer
                fixture.overrides["/api/dex/.well-known/openid-configuration"] = (
                    200,
                    {
                        "issuer": issuer,
                        "authorization_endpoint": issuer + "/auth",
                        "token_endpoint": issuer + "/token",
                        "jwks_uri": issuer + "/keys",
                        **overrides,
                    },
                )
                with self.assertRaises(ProviderError):
                    fixture.provider._get_discovery()
                self.assertEqual(len(fixture.calls), 1)

    def test_discovery_token_and_jwks_redirects_are_not_followed(self) -> None:
        for endpoint in (".well-known/openid-configuration", "token", "keys"):
            with self.subTest(endpoint=endpoint), self._oidc_server() as fixture:
                fixture.overrides["/api/dex/" + endpoint] = (302, {})
                with self.assertRaises(ProviderError):
                    fixture.provider.complete_login(
                        code="code",
                        state="state",
                        code_verifier="verifier",
                        redirect_uri="http://localhost:9119/auth/callback",
                    )
                self.assertNotIn("/api/dex/redirect-target", [path for _, path, _ in fixture.calls])

    def test_non_boolean_options_and_cleartext_issuers_are_rejected(self) -> None:
        with self.assertRaises(ValueError):
            DexAuthProvider(
                issuer=ISSUER,
                client_id=CLIENT,
                access_policy=OWNER_POLICY,
                insecure_skip_verify=cast(bool, "false"),
            )
        with self.assertRaises(ValueError):
            DexAuthProvider(
                issuer="http://localhost/api/dex",
                client_id=CLIENT,
                access_policy=OWNER_POLICY,
                insecure_skip_verify=True,
            )


if __name__ == "__main__":
    unittest.main()
