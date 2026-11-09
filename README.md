# auto-kr

Universal Kiro (`app.kiro.dev` / `prod.us-east-1.auth.desktop.kiro.dev`) authentication toolkit: Social Device Flow (`Github` / `Google`), AWS SSO OIDC Builder ID Device Flow, WAF-free GitHub OAuth URL resolver, and pluggable credential sink (`stdout`, `file`, `http`, `sqlite`).

## Modules

| Module | Path | Responsibility |
|---|---|---|
| `kiro_auth` | `packages/auto_kr/kiro_auth.py` | Social Device Flow (`request_kiro_social_device_code` / `poll_kiro_social_token`), AWS Builder ID OIDC registration (`register_builder_id_client`), and `/github/authorize` -> `github.com/login/oauth/authorize` WAF bypass (`resolve_waf_free_github_oauth_url`) |
| `router_store` | `packages/auto_kr/router_store.py` | `CredentialBundle` schema, `scrypt` + `AES-256-GCM` (`enc:v1:`) cipher, and `dispatch_credential_sink` (`stdout`, `file:<path>`, `http://<host>:<port>`, `sqlite:<db_path>`) |
| `cli` | `packages/auto_kr/cli.py` | CLI (`init-social`, `poll-social`, `init-builder-id`, `waf-free-gh-url`, `sink`, `pair --stdin`, `doctor`) |

## Quickstart

```bash
cp .env.example .env
make test
make hygiene
make init-social IDP=Github
make waf-free-gh-url
make init-builder-id
```
