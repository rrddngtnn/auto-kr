import io
import json
import os
import sqlite3
import tempfile

from auto_kr.kiro_auth import (
    _extract_github_oauth_form,
    build_kiro_social_pkce_url,
    execute_kiro_pairing_from_bundle,
    generate_pkce_pair,
    prepare_kiro_pairing_from_bundle,
    rewrite_kiro_github_authorize_url,
)
from auto_kr.router_store import (
    CredentialBundle,
    decrypt_field,
    dispatch_credential_sink,
    encrypt_field,
)

TEST_SECRET = "0000000000000000000000000000000000000000000000000000000000000001"


def test_waf_url_rewrite_and_pkce():
    u = "https://prod.us-east-1.auth.desktop.kiro.dev/github/authorize?client_id=Ov23lilbEuhqkZak4Bfh&scope=read%3Auser+user%3Aemail+openid&state=xyz"
    rw = rewrite_kiro_github_authorize_url(u)
    assert rw == "https://github.com/login/oauth/authorize?client_id=Ov23lilbEuhqkZak4Bfh&scope=read%3Auser+user%3Aemail&state=xyz"
    v, c = generate_pkce_pair()
    assert len(v) >= 40 and len(c) >= 40
    pkce = build_kiro_social_pkce_url("Github", state="st123")
    assert "idp=Github" in pkce["login_url"] and "state=st123" in pkce["login_url"]


def test_encryption_and_universal_sinks():
    enc = encrypt_field("kiro-secret-token", secret=TEST_SECRET)
    assert enc.startswith("enc:v1:")
    assert decrypt_field(enc, secret=TEST_SECRET) == "kiro-secret-token"

    bundle = CredentialBundle(
        name="kiro-unit",
        access_token="at_test_123",
        refresh_token="rt_test_456",
        profile_arn="arn:aws:codewhisperer:us-east-1:123456789012:profile/TEST",
    )

    # 1. stdout sink
    buf = io.StringIO()
    r_out = dispatch_credential_sink(bundle, sink="stdout", stream=buf)
    assert r_out["ok"] and json.loads(buf.getvalue())["access_token"] == "at_test_123"

    with tempfile.TemporaryDirectory() as tmp:
        # 2. file JSONL sink
        jpath = os.path.join(tmp, "out.jsonl")
        r_file = dispatch_credential_sink(bundle, sink=f"file:{jpath}")
        assert r_file["ok"] and os.path.isfile(jpath)

        # 3. sqlite sink
        db_path = os.path.join(tmp, "router.sqlite")
        con = sqlite3.connect(db_path)
        con.execute(
            """
            CREATE TABLE provider_connections (
                id TEXT PRIMARY KEY, provider TEXT, auth_type TEXT, name TEXT,
                api_key TEXT, access_token TEXT, refresh_token TEXT,
                provider_specific_data TEXT, is_active INTEGER, test_status TEXT,
                created_at TEXT, updated_at TEXT
            )
            """
        )
        con.commit()
        con.close()
        r_db = dispatch_credential_sink(bundle, sink=f"sqlite:{db_path}", secret=TEST_SECRET)
        assert r_db["ok"] and r_db["connection_id"]


def test_session_bundle_pairing_plan():
    class _FakeResp:
        def __init__(self, loc):
            self.headers = {"location": loc}

    class _FakeHttp:
        def get(self, url, allow_redirects=False, timeout=15):
            if "/login?idp=Github" in url:
                return _FakeResp("https://kiro-prod-us-east-1.auth.us-east-1.amazoncognito.com/oauth2/authorize?state=s1")
            return _FakeResp(
                "https://prod.us-east-1.auth.desktop.kiro.dev/github/authorize?client_id=Ov23lilbEuhqkZak4Bfh&scope=read%3Auser+user%3Aemail+openid&state=s2"
            )

    plan = prepare_kiro_pairing_from_bundle(
        {"username": "dev-zen-100", "email": "zen@alpha.example.test", "country": "sg", "proxy_url": "http://127.0.0.1:8080"},
        mode="pkce",
        http_session=_FakeHttp(),
    )
    assert plan["username"] == "dev-zen-100"
    assert plan["direct_github_oauth_url"].startswith("https://github.com/login/oauth/authorize?client_id=Ov23lilbEuhqkZak4Bfh")

    # Verify form parser & missing cookie guard on execute_kiro_pairing_from_bundle
    html = '<form action="/login/oauth/authorize" method="post"><input type="hidden" name="authenticity_token" value="tok123"><input type="hidden" name="client_id" value="Ov23lilbEuhqkZak4Bfh"></form>'
    parsed_form = _extract_github_oauth_form(html)
    assert parsed_form and parsed_form["authenticity_token"] == "tok123" and parsed_form["authorize"] == "1"

    no_cookie_res = execute_kiro_pairing_from_bundle(
        {"username": "dev-zen-100", "cookies": {}},
        http_session=_FakeHttp(),
    )
    assert not no_cookie_res["ok"] and no_cookie_res["error"] == "missing_github_session_cookies"


if __name__ == "__main__":
    test_waf_url_rewrite_and_pkce()
    test_encryption_and_universal_sinks()
    test_session_bundle_pairing_plan()
    print("[PASS] auto-kr offline suite passed (3/3)")
