# hermes-dex-auth-plugin

[English](README.md) | [日本語](README.ja.md)

An authentication plugin for signing in to Hermes Dashboard through Dex.
It connects to a Dex issuer and restricts login with allowlists of user IDs,
email addresses, and groups.
The target runtime is Hermes **v0.23.1** / Python **3.14.9**.
The Hermes plugin name is `dex-auth`; the authentication provider ID is `dex`.
Configuration lives under `dashboard.oauth.dex`.

## Project layout

```text
src/hermes_dex_auth_plugin/
  __init__.py   Hermes registration
  config.py     Configuration loading and validation
  policy.py     User ID, email, and group access rules
  provider.py   OIDC flow and ID token access checks
  transport.py  TLS, same-origin restrictions, and JWKS fetching
  py.typed      Type information marker for the distributed package
tests/          Configuration, policy, and authentication flow tests
examples/       Helm values example
__init__.py     Registration entry point for a source directory
plugin.yaml     Hermes plugin manifest
pyproject.toml  Packaging, dependencies, and development tools
README.md       English documentation
README.ja.md    Japanese documentation
```

The plugin supports copying directly into a Docker image and installing in
other Hermes environments. Both use the registration code in
`src/hermes_dex_auth_plugin/`.

## Configuration with Helm values

When deploying with `hermes-agent-chart`, `values.config` is passed to the Hermes
`config.yaml`. Add the following `dashboard` section under `config`, alongside
your existing model and other settings.
See [examples/values.yaml](examples/values.yaml) for the complete example.

```yaml
config:
  dashboard:
    oauth:
      dex:
        issuer: https://dex.example.com
        client_id: hermes-dashboard
        display_name: Dex
        access:
          users:
            - connector_id: github
              user_id: "YOUR_USER_ID"
          emails:
            - connector_id: github
              email: "user@example.com"
          groups:
            - connector_id: github
              name: "my-org:platform"
```

- Login is allowed if any rule in `users`, `emails`, or `groups` matches (OR).
- Each rule matches the combination of `connector_id` and the user ID, email
  address, or group name exactly.
- User IDs must be strings. IDs from Dex connectors other than GitHub are
  supported, including IDs that are not numeric.
- `emails` matches the ID token's `email` claim case-sensitively.
  Wildcards such as `*@example.com` are not supported.
- Unused rule lists may be omitted. Login is denied if no rule matches;
  an entirely empty allowlist is a configuration error.
- Every login requires non-empty strings for `federated_claims.connector_id`,
  `federated_claims.user_id`, and `email`, and the boolean `email_verified: true`.
  This also applies when access is granted by user ID or group without an email rule.
- To use group rules, configure the Dex connector to return groups.
  A GitHub group can look like `my-org:platform`.

Rules are evaluated against an ID token after Hermes verifies its signature,
issuer, audience, and expiration. The same access check runs during login,
token refresh, and authenticated requests.
Changes to groups reported by Dex take effect when a new ID token is issued.
With the chart, changes to the values configuration trigger Pod recreation
through `checksum/config`.

The allowlist controls **who can sign in to Dashboard**. It does not assign
Dashboard operation permissions such as read-only or administrator roles.
If other authentication providers are enabled, their login conditions also
provide a way to sign in.

Register `https://<dashboard>/auth/callback` as the client callback in Dex.
Set the public Dashboard URL with `HERMES_DASHBOARD_PUBLIC_URL`.
The requested scopes are `openid profile email federated:id offline_access`;
`groups` is added when group rules are configured.

## TLS and environment variables

TLS certificate verification is enabled by default. For a private CA, mount
the certificate bundle separately and set its path in `tls.ca_bundle`.

```yaml
config:
  dashboard:
    oauth:
      dex:
        # Set issuer / client_id / access under the same dex section.
        tls:
          ca_bundle: /etc/dex/ca.crt
          insecure_skip_verify: false
```

To skip certificate verification in an existing environment, set
`insecure_skip_verify: true`. This setting applies only to this plugin's
discovery, token, JWKS, and revocation requests.
Combining it with `ca_bundle` is an error. Endpoints must share the issuer's
HTTPS origin, and redirects are not followed.

Environment variables take precedence over values configuration. Empty strings
are treated as unset.

| Environment variable | Setting |
|---|---|
| `HERMES_DEX_ISSUER` | `issuer` |
| `HERMES_DEX_CLIENT_ID` | `client_id` |
| `HERMES_DEX_CLIENT_SECRET` | Secret for a confidential client; do not put it in values |
| `HERMES_DEX_CA_BUNDLE` | `tls.ca_bundle` |
| `HERMES_DEX_INSECURE_SKIP_VERIFY` | `tls.insecure_skip_verify`; accepts only `true` / `false` |

The provider is not registered if `dashboard.oauth.dex` is absent and neither
issuer nor client ID is supplied through environment variables.
When configuration is present, the issuer, client ID, and access rules are
validated before registration.

## Including the plugin in an image

Fetch this repository at a pinned commit SHA during the image build.
Copy the contents of `src/hermes_dex_auth_plugin/` and the root `plugin.yaml`
into `/opt/hermes/plugins/dashboard_auth/dex-auth/`.
For example, with the repository as the build context:

```dockerfile
COPY src/hermes_dex_auth_plugin/ /opt/hermes/plugins/dashboard_auth/dex-auth/
COPY plugin.yaml /opt/hermes/plugins/dashboard_auth/dex-auth/plugin.yaml
```

The destination contains both `__init__.py` and `plugin.yaml`. At startup,
Hermes discovers the directory and calls `register(ctx)` in `__init__.py`
to register the Dex provider.

Runtime dependencies are listed in `pyproject.toml` and are also included in
Hermes v0.23.1. Do not copy `tests` or the development `.venv` into the runtime image.

When migrating from the previous plugin, the provider name changes from
`argocd-github` to `dex`. Replace `HERMES_ARGOCD_*` environment variables with
the `HERMES_DEX_*` variables above or values configuration.
Users must sign in again after migration. When switching to an image with the
plugin included, also remove the previous ConfigMap mount.

## Installation and distribution outside Docker

### Installing from a source directory

```sh
hermes plugins install eeekcct/hermes-dex-auth-plugin --no-enable
hermes plugins enable dex-auth
```

The root `__init__.py` is an entry point that exposes `register(ctx)` from
`src/hermes_dex_auth_plugin/`. For a PM-managed Hermes installation, use this
route so Hermes also manages the dependencies declared in `pyproject.toml`.
After configuration, restart Hermes to load the plugin.

### Distributing a Python package

```powershell
uv build
```

This creates a wheel (`.whl`) and a source distribution (`.tar.gz`) in `dist/`.
The wheel includes the implementation, `plugin.yaml`, and type information.
If the package is installed in the Python environment running Hermes, Hermes
loads `hermes_dex_auth_plugin` through the `dex-auth` entry point in
`hermes_agent.plugins`. After activation with `hermes plugins enable dex-auth`,
it calls `register(ctx)`.
This distribution route is for environments where the user manages the Python
installation. Copying directly into Docker does not require building or
installing a wheel.

## Development and testing

The plugin reuses Hermes's OIDC implementation, so tests require the target
version of the Hermes source. Hermes itself is not installed as a dependency
of this project. `uv sync --locked` installs this plugin in editable mode and
installs the development dependencies.
Tests import the regular `hermes_dex_auth_plugin` package and find the Hermes
source through `PYTHONPATH`.

The `[tool.pyright]` section in `pyproject.toml` uses the sibling
`../hermes-agent` directory for type analysis. VS Code completion and
Go to Definition are provided by Pylance, which uses Pyright's type analysis.
Pyright is a development dependency installed by `uv sync --locked`.
Both the implementation and tests are checked in strict mode; Ruff's `ANN`
rules also check for missing type annotations.
Open this repository as a folder and select `.venv/Scripts/python.exe`
(`.venv/bin/python` on Linux / macOS) with `Python: Select Interpreter`.
The default in `.vscode/settings.json` is `.venv`, but an interpreter selected
earlier is not switched automatically.
Then run `Python: Restart Language Server` or `Developer: Reload Window`
to enable method completion on `ctx.` and F12 navigation.
`PYTHONPATH` configures test imports; `extraPaths` configures editor type analysis.
Unvalidated configuration and claims are accepted as `object`; validated
settings are returned as `DexSettings` (`TypedDict`).
The Hermes registration API without type annotations has a type diagnostic
suppression only at its call site.

Run these commands in PowerShell from the repository root:

```powershell
# Fetch the source if ../hermes-agent does not exist yet.
git clone --depth 1 --branch v0.23.1 https://github.com/NousResearch/hermes-agent.git ../hermes-agent
uv sync --locked
$env:PYTHONPATH = (Resolve-Path ../hermes-agent).Path
uv run --locked python -m unittest discover -s tests -v
uv run --locked pyright
uv run --locked ruff check .
uv run --locked ruff format --check .
```

Tests use a localhost HTTPS server and temporary signing keys. They do not
connect to an external Dex instance or real accounts.
They cover user ID, email, and group rules; required claims and verified email;
configuration errors; Hermes plugin registration; signature verification;
discovery, login, refresh, JWKS, and revocation; the Bearer `token_type`
requirement; and TLS / redirect restrictions.
CI runs the same tests inside the target Hermes image.

References: [Dex scopes and claims](https://dexidp.io/docs/configuration/custom-scopes-claims-clients/),
[GitHub connector group configuration](https://dexidp.io/docs/connectors/github/).
