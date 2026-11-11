# hermes-dex-auth-plugin

[English](README.md) | [日本語](README.ja.md)

Dex を使って Hermes Dashboard にログインするための認証プラグインです。
任意の Dex issuer に接続し、ユーザー ID・メールアドレス・グループの許可リストでログインを制限します。
動作確認対象は Hermes **v0.23.1** / Python **3.14.9** です。
Hermes に登録するプラグイン名は `dex-auth`、認証 provider の識別子は `dex` です。
設定パスは `dashboard.oauth.dex` を使います。

## 構成

```text
src/hermes_dex_auth_plugin/
  __init__.py   Hermes への登録
  config.py     設定の読み込みと検証
  policy.py     ユーザー ID・メール・グループのアクセス判定
  provider.py   OIDC フローと ID token のアクセス判定
  transport.py  TLS、同一 origin 制限、JWKS 取得
  py.typed      配布パッケージの型情報マーカー
tests/          設定・ポリシー・認証フローのテスト
examples/       Helm values の設定例
__init__.py     ソースディレクトリを使う場合の登録入口
plugin.yaml     Hermes プラグイン定義
pyproject.toml  パッケージ・依存・開発ツールの設定
README.md       英語のドキュメント
README.ja.md    日本語のドキュメント
```

Docker イメージへの直接コピーと、Docker 以外の Hermes 環境への導入に対応します。
どちらも `src/hermes_dex_auth_plugin/` の同じ登録処理を使います。

## Helm values での設定

既存の `hermes-agent-chart` は `values.config` を Hermes の `config.yaml` に渡します。
既存のモデル設定などと合わせて、次の `dashboard` セクションを `config` 配下へ追加します。
完全な設定例は [examples/values.yaml](examples/values.yaml) にあります。

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

- `users`・`emails`・`groups` のいずれかのルールに一致するとログインを許可します（OR 判定）。
- 各ルールは `connector_id` とユーザー ID / メールアドレス / グループ名の組み合わせで完全一致させます。
- ユーザー ID は文字列です。GitHub の数値 ID 以外の Dex connector の ID も扱えます。
- `emails` は ID token の `email` と、大文字・小文字も区別して比較します。
  `*@example.com` のようなワイルドカードには対応しません。
- 使用しないルールのリストは省略できます。どのルールにも一致しない場合は拒否し、許可リストがすべて空なら設定エラーにします。
- すべてのログインで、空でない文字列の `federated_claims.connector_id`・`federated_claims.user_id`・`email` と、
  真偽値の `email_verified: true` を必須にします。メールルールを使わず、ユーザー ID やグループで許可する場合も同じです。
- グループを使う場合は、Dex connector 側もグループを返すよう設定してください。
  GitHub の例では `my-org:platform` のような値が返ります。

ルールの評価には、Hermes が署名・issuer・audience・有効期限を検証した ID token を使います。
ログイン時、トークン更新時、認証済みリクエスト時に同じ判定を行います。
Dex からのグループ変更は、新しい ID token が発行された時点で反映されます。
values の設定変更はチャートの `checksum/config` によって Pod 再作成へ反映されます。

この許可リストは **Dashboard にログインできるか**を制御します。
閲覧専用・管理者など Dashboard 内の操作権限を分ける機能は含みません。
他の認証 provider を同時に有効にすると、その provider の許可条件でもログインできます。

Dex に登録する callback は `https://<dashboard>/auth/callback` です。
公開 URL は既存の `HERMES_DASHBOARD_PUBLIC_URL` で設定します。
要求する scope は `openid profile email federated:id offline_access`、
グループの許可ルールがある場合は `groups` も追加します。

## TLS と環境変数

通常は標準の TLS 証明書検証を使用します。プライベート CA を使う場合は、
証明書を別途マウントして `tls.ca_bundle` にそのパスを指定できます。

```yaml
config:
  dashboard:
    oauth:
      dex:
        # issuer / client_id / access も同じ dex 配下に設定します。
        tls:
          ca_bundle: /etc/dex/ca.crt
          insecure_skip_verify: false
```

既存環境で証明書検証を省略する場合は `insecure_skip_verify: true` を指定します。
この設定は、このプラグインの discovery・token・JWKS・失効要求だけに適用されます。
`ca_bundle` との併用はエラーです。接続先は同じ HTTPS origin に限定し、
リダイレクトは追跡しません。

環境変数を設定した場合は values より優先します。空文字は未設定として扱います。

| 環境変数 | 設定項目 |
|---|---|
| `HERMES_DEX_ISSUER` | `issuer` |
| `HERMES_DEX_CLIENT_ID` | `client_id` |
| `HERMES_DEX_CLIENT_SECRET` | confidential client 用の Secret。values には書きません |
| `HERMES_DEX_CA_BUNDLE` | `tls.ca_bundle` |
| `HERMES_DEX_INSECURE_SKIP_VERIFY` | `tls.insecure_skip_verify`。`true` / `false` のみ |

`dashboard.oauth.dex` がなく、issuer / client ID の環境変数もない場合は登録しません。
設定がある場合は、issuer・client ID・許可ルールを検証してから登録します。

## イメージへの組み込み

イメージのビルド時に、このリポジトリをコミット SHA 固定で取得します。
`src/hermes_dex_auth_plugin/` の中身とルートの `plugin.yaml` を、
`/opt/hermes/plugins/dashboard_auth/dex-auth/` にコピーします。
取得したリポジトリをビルドコンテキストにする場合の例です。

```dockerfile
COPY src/hermes_dex_auth_plugin/ /opt/hermes/plugins/dashboard_auth/dex-auth/
COPY plugin.yaml /opt/hermes/plugins/dashboard_auth/dex-auth/plugin.yaml
```

配置先には `__init__.py` と `plugin.yaml` が並びます。Hermes は起動時にこのディレクトリを検出し、
`__init__.py` の `register(ctx)` を呼んで Dex provider を登録します。

ライブラリは `pyproject.toml` に記載しています。Hermes v0.23.1 の環境にも含まれます。
`tests`・開発用 `.venv` は実行イメージにコピーしません。

旧プラグインから移行する場合は、provider 名は `argocd-github` から `dex` に変わり、
環境変数 `HERMES_ARGOCD_*` は上記の `HERMES_DEX_*` / values の設定に置き換えます。
移行時は再ログインが必要です。同梱イメージへ切り替える際に旧 ConfigMap の
マウントも削除してください。

## Docker 以外への導入と配布

### ソースディレクトリを使う場合

```sh
hermes plugins install eeekcct/hermes-dex-auth-plugin --no-enable
hermes plugins enable dex-auth
```

ルートの `__init__.py` は `src/hermes_dex_auth_plugin/` の `register(ctx)` を呼ぶための入口です。
PM 管理の Hermes ではこの経路を使うことで、`pyproject.toml` に記載した依存関係も Hermes が管理します。
設定後、Hermes を再起動してプラグインを読み込みます。

### Python パッケージとして配布する場合

```powershell
uv build
```

`dist/` に wheel（`.whl`）とソース配布物（`.tar.gz`）を生成します。
wheel には実装・`plugin.yaml`・型情報を含めます。Hermes を実行する Python 環境にこのパッケージが
導入されていれば、`hermes_agent.plugins` の entry point `dex-auth` から `hermes_dex_auth_plugin` を読み込み、
`hermes plugins enable dex-auth` による有効化後に `register(ctx)` を呼びます。
この経路は、Python 環境を利用者側で構築する場合の配布用です。
Docker に直接コピーする方式では wheel の作成・インストールは不要です。

## 開発とテスト

プラグインは Hermes の OIDC 実装を再利用するため、テストには対象バージョンの
Hermes ソースが必要です。Hermes 自体はこのプロジェクトの依存としてインストールしません。
`uv sync --locked` は、このプラグイン自身を editable install し、開発用依存もインストールします。
テストは通常の `hermes_dex_auth_plugin` パッケージを import し、Hermes ソースを `PYTHONPATH` から参照します。

`pyproject.toml` の `[tool.pyright]` は、隣の `../hermes-agent` を型定義の参照先にしています。
VS Code の補完・定義ジャンプは Pylance 拡張が担当し、内部で Pyright の型解析を使います。
Pyright は開発用依存に含まれ、`uv sync --locked` でインストールされます。
本体とテストを strict モードで検査し、Ruff の `ANN` ルールで型注釈の追加漏れも確認します。
このリポジトリをフォルダーとして開き、`Python: Select Interpreter` で
`.venv/Scripts/python.exe`（Linux / macOS は `.venv/bin/python`）を選んでください。
`.vscode/settings.json` の既定値は `.venv` ですが、既に選択済みの環境は自動では切り替わりません。
その後 `Python: Restart Language Server`、または `Developer: Reload Window` を実行すると、
`ctx.` のメソッド補完と F12 の定義ジャンプを使えます。
`PYTHONPATH` はテスト実行用、`extraPaths` はエディターの型解析用の指定です。
未検証の設定や claims は `object` として受け取り、検証後の設定は `DexSettings`（`TypedDict`）で返します。
Hermes 側で型が未定義の登録 API は、呼び出し箇所のみ型診断の対象外にしています。

PowerShell で、このリポジトリのルートから実行します。

```powershell
# ../hermes-agent がまだない場合に取得します。
git clone --depth 1 --branch v0.23.1 https://github.com/NousResearch/hermes-agent.git ../hermes-agent
uv sync --locked
$env:PYTHONPATH = (Resolve-Path ../hermes-agent).Path
uv run --locked python -m unittest discover -s tests -v
uv run --locked pyright
uv run --locked ruff check .
uv run --locked ruff format --check .
```

テストは localhost の HTTPS サーバーと一時的な署名鍵を使い、外部の Dex や実アカウントには接続しません。
ユーザー ID・メール・グループ判定、必須 claims・確認済みメール、設定エラー、Hermes のプラグイン登録、署名検証、
discovery・ログイン・更新・JWKS・失効、`token_type` の Bearer 必須条件と TLS / リダイレクト制限を確認します。
CI は対象の Hermes イメージ内で同じテストを実行します。

参考: [Dex の scopes / claims](https://dexidp.io/docs/configuration/custom-scopes-claims-clients/)、
[GitHub connector のグループ設定](https://dexidp.io/docs/connectors/github/)。
