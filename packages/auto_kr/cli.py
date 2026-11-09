"""cli.py — CLI entry point for auto-kr (Kiro Social Device Flow, WAF-free GitHub OAuth URL resolver, Builder ID, and universal sink)."""
from __future__ import annotations

import argparse
import json
import sys

from .kiro_auth import (
    exchange_kiro_social_code,
    execute_kiro_pairing_from_bundle,
    poll_kiro_social_token,
    prepare_kiro_pairing_from_bundle,
    register_builder_id_client,
    request_kiro_social_device_code,
    resolve_waf_free_github_oauth_url,
)
from .router_store import CredentialBundle, dispatch_credential_sink, load_dotenv_file


def cmd_init_social(args) -> None:
    res = request_kiro_social_device_code(login_provider=args.idp)
    print(json.dumps(res, indent=2))


def cmd_poll_social(args) -> None:
    res = poll_kiro_social_token(args.device_code)
    if res.get("ok") and args.sink:
        bundle = CredentialBundle(
            auth_type="oauth",
            auth_method="github",
            name=args.name,
            access_token=res["access_token"],
            refresh_token=res.get("refresh_token", ""),
            profile_arn=res.get("profile_arn", ""),
            expires_in=res.get("expires_in", 3600),
        )
        res["sink_result"] = dispatch_credential_sink(bundle, sink=args.sink)
    print(json.dumps(res, indent=2))


def cmd_init_builder_id(args) -> None:
    res = register_builder_id_client()
    print(json.dumps(res, indent=2))


def cmd_waf_free_gh(args) -> None:
    res = resolve_waf_free_github_oauth_url()
    print(json.dumps(res, indent=2))


def cmd_emit_sink(args) -> None:
    bundle = CredentialBundle(
        auth_type="apikey" if args.auth_method == "api_key" else "oauth",
        auth_method=args.auth_method,
        name=args.name,
        access_token=args.access_token,
        refresh_token=args.refresh_token,
        api_key=args.access_token if args.auth_method == "api_key" else "",
        profile_arn=args.profile_arn,
        region=args.region,
    )
    res = dispatch_credential_sink(bundle, sink=args.sink, stream=sys.stdout)
    if args.sink != "stdout":
        print(json.dumps(res, indent=2))


def main(argv: list[str] | None = None) -> int:
    load_dotenv_file()
    p = argparse.ArgumentParser(prog="auto-kr")
    sub = p.add_subparsers(dest="cmd", required=True)

    s_is = sub.add_parser("init-social", help="Initiate Kiro Social Device Flow (Github or Google)")
    s_is.add_argument("--idp", choices=("Github", "Google"), default="Github")
    s_is.set_defaults(func=cmd_init_social)

    s_ps = sub.add_parser("poll-social", help="Poll Kiro Social Device Code for tokens and optionally route to sink")
    s_ps.add_argument("--device-code", required=True)
    s_ps.add_argument("--name", default="kiro-social")
    s_ps.add_argument("--sink", default="", help="Optional sink: stdout | file:path.jsonl | http://host:port | sqlite[:path]")
    s_ps.set_defaults(func=cmd_poll_social)

    s_ib = sub.add_parser("init-builder-id", help="Register OIDC client and initiate AWS Builder ID Device Flow")
    s_ib.set_defaults(func=cmd_init_builder_id)

    s_wf = sub.add_parser("waf-free-gh-url", help="Resolve Cognito redirect and rewrite /github/authorize to github.com/login/oauth/authorize")
    s_wf.set_defaults(func=cmd_waf_free_gh)

    s_es = sub.add_parser("sink", help="Route a Kiro credential to stdout, JSONL file, HTTP gateway, or SQLite")
    s_es.add_argument("--name", default="kiro-account")
    s_es.add_argument("--access-token", required=True)
    s_es.add_argument("--refresh-token", default="")
    s_es.add_argument("--profile-arn", default="")
    s_es.add_argument("--auth-method", default="github", choices=("github", "google", "builder-id", "api_key"))
    s_es.add_argument("--region", default="us-east-1")
    s_es.add_argument("--sink", default="stdout", help="stdout | file:tokens.jsonl | http://127.0.0.1:20128 | sqlite[:db_path]")
    s_es.set_defaults(func=cmd_emit_sink)

    s_pr = sub.add_parser("pair", help="Consume SessionBundle JSONL from --stdin or --session-file and emit Kiro pairing plans / tokens")
    s_pr.add_argument("--stdin", action="store_true", help="Read SessionBundle JSONL lines from stdin")
    s_pr.add_argument("--session-file", default="", help="Path to SessionBundle JSON/JSONL file")
    s_pr.add_argument("--mode", choices=("pkce", "device"), default="pkce")
    s_pr.add_argument("--execute", action="store_true", help="Execute WAF-free GitHub OAuth + PKCE exchange using SessionBundle cookies")
    s_pr.add_argument("--code", default="", help="Optional authorization code to exchange immediately")
    s_pr.add_argument("--code-verifier", default="", help="PKCE code_verifier when exchanging --code")
    s_pr.add_argument("--sink", default="stdout", help="Target sink when exchanging code: stdout | file:path | http://... | sqlite[:path]")
    s_pr.set_defaults(func=cmd_pair)

    s_dr = sub.add_parser("doctor", help="Inspect declared BYOP contracts (input stream, auth modes, and output sinks)")
    s_dr.set_defaults(func=cmd_doctor)

    args = p.parse_args(argv)
    args.func(args)
    return 0


def cmd_doctor(args) -> None:
    import os

    print(
        json.dumps(
            {
                "ok": True,
                "declared_contracts": {
                    "input_contract": {
                        "format": "SessionBundle JSONL (v1.0) via --stdin or --session-file",
                        "standalone_modes": ["init-social", "init-builder-id", "waf-free-gh-url"],
                    },
                    "sink_driver": {
                        "supported": ["stdout", "file:<path.jsonl>", "http://<gateway>", "sqlite[:<db_path>]"],
                        "router_url": os.environ.get("ROUTER_URL", "http://127.0.0.1:20128"),
                        "encryption_key_configured": bool(os.environ.get("STORAGE_ENCRYPTION_KEY")),
                    },
                },
            },
            indent=2,
        )
    )


def _read_session_bundles(args) -> list[dict]:
    raw = ""
    if args.stdin:
        raw = sys.stdin.read().strip()
    elif args.session_file:
        with open(args.session_file, encoding="utf-8") as f:
            raw = f.read().strip()
    if not raw:
        return []
    if raw.startswith("["):
        return json.loads(raw)
    return [json.loads(ln) for ln in raw.splitlines() if ln.strip()]


def cmd_pair(args) -> None:
    bundles = _read_session_bundles(args)
    for b in bundles:
        if args.execute:
            res = execute_kiro_pairing_from_bundle(b)
            if res.get("ok"):
                cred = CredentialBundle(
                    auth_type="oauth",
                    auth_method="github",
                    name=res["username"],
                    email=res.get("email", ""),
                    access_token=res["access_token"],
                    refresh_token=res["refresh_token"],
                    profile_arn=res.get("profile_arn", ""),
                    expires_in=res.get("expires_in", 3600),
                )
                sink_res = dispatch_credential_sink(cred, sink=args.sink, stream=sys.stdout)
                if args.sink != "stdout":
                    sys.stdout.write(json.dumps({"ok": True, "username": res["username"], "sink_result": sink_res}) + "\n")
                    sys.stdout.flush()
            else:
                sys.stdout.write(json.dumps(res) + "\n")
                sys.stdout.flush()
        elif args.code and args.code_verifier:
            proxy_url = b.get("proxy_url") or ""
            proxies = {"http": proxy_url, "https": proxy_url} if proxy_url else None
            tok = exchange_kiro_social_code(args.code, args.code_verifier, proxies=proxies)
            cred = CredentialBundle(
                auth_type="oauth",
                auth_method="github",
                name=b.get("username") or b.get("email") or "kiro-github",
                email=b.get("email", ""),
                access_token=tok["access_token"],
                refresh_token=tok["refresh_token"],
                profile_arn=tok["profile_arn"],
                expires_in=tok["expires_in"],
            )
            dispatch_credential_sink(cred, sink=args.sink, stream=sys.stdout)
        else:
            plan = prepare_kiro_pairing_from_bundle(b, mode=args.mode)
            sys.stdout.write(json.dumps(plan) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    raise SystemExit(main())
