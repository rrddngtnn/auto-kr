"""kiro_auth.py — Kiro Social Device Flow (Github/Google), AWS SSO OIDC Builder ID Device Flow, and WAF-free GitHub URL rewriter."""
from __future__ import annotations

import base64
import hashlib
import os
import requests

KIRO_AUTH_SERVICE = "https://prod.us-east-1.auth.desktop.kiro.dev"
KIRO_SOCIAL_DEVICE_AUTH_URL = f"{KIRO_AUTH_SERVICE}/oauth/device/authorization"
KIRO_SOCIAL_DEVICE_POLL_URL = f"{KIRO_AUTH_SERVICE}/oauth/device/poll"
KIRO_SOCIAL_TOKEN_URL = f"{KIRO_AUTH_SERVICE}/oauth/token"
KIRO_SOCIAL_REFRESH_URL = f"{KIRO_AUTH_SERVICE}/refreshToken"
KIRO_WAF_GH_PREFIX = f"{KIRO_AUTH_SERVICE}/github/authorize"
GITHUB_OAUTH_AUTHORIZE_URL = "https://github.com/login/oauth/authorize"

KIRO_OIDC_REGISTER_URL = "https://oidc.us-east-1.amazonaws.com/client/register"
KIRO_OIDC_DEVICE_AUTH_URL = "https://oidc.us-east-1.amazonaws.com/device_authorization"
KIRO_OIDC_TOKEN_URL = "https://oidc.us-east-1.amazonaws.com/token"
KIRO_START_URL = "https://view.awsapps.com/start"
KIRO_ISSUER_URL = "https://identitycenter.amazonaws.com/ssoins-722374e8c3c8e6c6"
KIRO_SCOPES = ["codewhisperer:completions", "codewhisperer:analysis", "codewhisperer:conversations"]


def rewrite_kiro_github_authorize_url(cognito_redirect_url: str) -> str:
    """Rewrite Kiro's AWS WAF-gated /github/authorize URL directly to github.com/login/oauth/authorize."""
    if cognito_redirect_url.startswith(KIRO_WAF_GH_PREFIX):
        rewritten = GITHUB_OAUTH_AUTHORIZE_URL + cognito_redirect_url[len(KIRO_WAF_GH_PREFIX):]
        return rewritten.replace("+openid", "").replace("%2Bopenid", "")
    return cognito_redirect_url


def generate_pkce_pair() -> tuple[str, str]:
    verifier = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode("ascii")
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


def build_kiro_social_pkce_url(login_provider: str = "Github", state: str | None = None) -> dict:
    from urllib.parse import quote

    verifier, challenge = generate_pkce_pair()
    st = state or base64.urlsafe_b64encode(os.urandom(16)).rstrip(b"=").decode("ascii")
    idp = "Google" if login_provider.lower() == "google" else "Github"
    redirect_uri = "kiro://kiro.kiroAgent/authenticate-success"
    login_url = (
        f"{KIRO_AUTH_SERVICE}/login?idp={idp}"
        f"&redirect_uri={quote(redirect_uri, safe='')}"
        f"&code_challenge={challenge}&code_challenge_method=S256"
        f"&state={st}&prompt=select_account"
    )
    return {
        "login_url": login_url,
        "code_verifier": verifier,
        "code_challenge": challenge,
        "state": st,
        "redirect_uri": redirect_uri,
        "idp": idp,
    }


def resolve_waf_free_github_oauth_url(proxies: dict | None = None, timeout: int = 15) -> dict:
    """Initiate Kiro Github PKCE login, follow to Cognito, and return the WAF-free github.com/login/oauth/authorize URL + cookies."""
    pkce = build_kiro_social_pkce_url("Github")
    s = requests.Session()
    if proxies:
        s.proxies.update(proxies)
    r1 = s.get(pkce["login_url"], allow_redirects=False, timeout=timeout)
    cognito_url = r1.headers.get("location", "")
    if not cognito_url:
        raise RuntimeError(f"Expected 302 from /login, got {r1.status_code}")
    r2 = s.get(cognito_url, allow_redirects=False, timeout=timeout)
    wrapper_url = r2.headers.get("location", "")
    if wrapper_url:
        direct_gh_url = rewrite_kiro_github_authorize_url(wrapper_url)
    elif r2.status_code == 202:
        direct_gh_url = cognito_url
    else:
        raise RuntimeError(f"Expected 302 from Cognito, got {r2.status_code}")
    return {
        **pkce,
        "cognito_url": cognito_url,
        "waf_wrapper_url": wrapper_url,
        "direct_github_oauth_url": direct_gh_url,
        "cognito_status": r2.status_code,
        "cognito_cookies": s.cookies.get_dict(),
    }


def request_kiro_social_device_code(
    login_provider: str = "Github",
    client_id: str = "kiro-cli",
    proxies: dict | None = None,
    timeout: int = 15,
) -> dict:
    r = requests.post(
        KIRO_SOCIAL_DEVICE_AUTH_URL,
        json={"clientId": client_id, "loginProvider": login_provider},
        proxies=proxies,
        timeout=timeout,
    )
    r.raise_for_status()
    data = r.json()
    return {
        "provider": "kiro",
        "login_provider": login_provider,
        "device_code": data["deviceCode"],
        "user_code": data["userCode"],
        "auth_url": data["verificationUriComplete"],
        "expires_in": int(data.get("expiresInMilliseconds", 300000)) // 1000,
        "interval": int(data.get("intervalInMilliseconds", 5000)) // 1000,
    }


def poll_kiro_social_token(
    device_code: str,
    client_id: str = "kiro-cli",
    proxies: dict | None = None,
    timeout: int = 15,
) -> dict:
    r = requests.post(
        KIRO_SOCIAL_DEVICE_POLL_URL,
        json={"clientId": client_id, "deviceCode": device_code},
        proxies=proxies,
        timeout=timeout,
    )
    if r.status_code in (400, 428):
        body = r.json() if r.content else {}
        err = body.get("error", "")
        return {
            "ok": False,
            "pending": err in ("authorization_pending", "slow_down", ""),
            "error": err,
        }
    r.raise_for_status()
    data = r.json()
    if data.get("accessToken"):
        return {
            "ok": True,
            "pending": False,
            "access_token": data["accessToken"],
            "refresh_token": data.get("refreshToken") or "",
            "profile_arn": data.get("profileArn") or "",
            "expires_in": data.get("expiresIn") or 3600,
        }
    return {"ok": False, "pending": True, "raw": data}


def register_builder_id_client(proxies: dict | None = None, timeout: int = 15) -> dict:
    r = requests.post(
        KIRO_OIDC_REGISTER_URL,
        json={
            "clientName": "kiro-oauth-client",
            "clientType": "public",
            "scopes": KIRO_SCOPES,
            "grantTypes": ["urn:ietf:params:oauth:grant-type:device_code", "refresh_token"],
            "issuerUrl": KIRO_ISSUER_URL,
        },
        proxies=proxies,
        timeout=timeout,
    )
    r.raise_for_status()
    data = r.json()
    r2 = requests.post(
        KIRO_OIDC_DEVICE_AUTH_URL,
        json={
            "clientId": data["clientId"],
            "clientSecret": data["clientSecret"],
            "startUrl": KIRO_START_URL,
        },
        proxies=proxies,
        timeout=timeout,
    )
    r2.raise_for_status()
    dev = r2.json()
    return {
        "provider": "kiro",
        "auth_method": "builder-id",
        "client_id": data["clientId"],
        "client_secret": data["clientSecret"],
        "device_code": dev["deviceCode"],
        "user_code": dev["userCode"],
        "auth_url": dev["verificationUriComplete"],
        "expires_in": dev.get("expiresIn", 600),
        "interval": dev.get("interval", 5),
    }


def exchange_kiro_social_code(
    code: str,
    code_verifier: str,
    redirect_uri: str = "kiro://kiro.kiroAgent/authenticate-success",
    proxies: dict | None = None,
    timeout: int = 15,
) -> dict:
    """Exchange a Kiro social authorization code + PKCE verifier for access/refresh tokens and profileArn."""
    r = requests.post(
        KIRO_SOCIAL_TOKEN_URL,
        json={
            "code": code,
            "code_verifier": code_verifier,
            "redirect_uri": redirect_uri,
        },
        proxies=proxies,
        timeout=timeout,
    )
    r.raise_for_status()
    data = r.json()
    return {
        "access_token": data["accessToken"],
        "refresh_token": data.get("refreshToken") or "",
        "profile_arn": data.get("profileArn") or "",
        "expires_in": data.get("expiresIn") or 3600,
    }


def prepare_kiro_pairing_from_bundle(
    session_bundle: dict,
    mode: str = "pkce",
    http_session=None,
) -> dict:
    """Consume a standardized SessionBundle dict and prepare a Kiro pairing plan with proxy & WAF-free URL."""
    proxy_url = session_bundle.get("proxy_url") or ""
    proxies = {"http": proxy_url, "https": proxy_url} if proxy_url else None
    username = session_bundle.get("username") or session_bundle.get("email") or "kiro-user"
    if mode == "device":
        dev = request_kiro_social_device_code(login_provider="Github", proxies=proxies)
        return {
            "username": username,
            "email": session_bundle.get("email", ""),
            "country": session_bundle.get("country", "sg"),
            "proxy_url": proxy_url,
            "storage_state_path": session_bundle.get("storage_state_path", ""),
            "mode": "device",
            **dev,
        }
    pkce = build_kiro_social_pkce_url("Github")
    if http_session is not None:
        r1 = http_session.get(pkce["login_url"], allow_redirects=False, timeout=15)
        cognito_url = r1.headers.get("location", "")
        r2 = http_session.get(cognito_url, allow_redirects=False, timeout=15) if cognito_url else None
        wrapper_url = r2.headers.get("location", "") if r2 is not None else ""
        direct_gh_url = rewrite_kiro_github_authorize_url(wrapper_url)
    else:
        wf = resolve_waf_free_github_oauth_url(proxies=proxies)
        pkce = wf
        direct_gh_url = wf["direct_github_oauth_url"]
    return {
        "username": username,
        "email": session_bundle.get("email", ""),
        "country": session_bundle.get("country", "sg"),
        "proxy_url": proxy_url,
        "storage_state_path": session_bundle.get("storage_state_path", ""),
        "mode": "pkce",
        "code_verifier": pkce["code_verifier"],
        "state": pkce["state"],
        "direct_github_oauth_url": direct_gh_url,
    }


def _extract_github_oauth_form(html: str) -> dict[str, str] | None:
    import re

    m_form = re.search(
        r'<form[^>]+action="(/login/oauth/authorize)"[^>]*>(.*?)</form>',
        html,
        re.DOTALL | re.IGNORECASE,
    )
    if not m_form:
        return None
    body = m_form.group(2)
    fields: dict[str, str] = {}
    for m_in in re.finditer(r"<input[^>]+>", body, re.IGNORECASE):
        tag = m_in.group(0)
        m_name = re.search(r'name="([^"]+)"', tag)
        m_val = re.search(r'value="([^"]*)"', tag)
        if m_name:
            fields[m_name.group(1)] = m_val.group(1) if m_val else ""
    fields["authorize"] = "1"
    return fields


def _load_bundle_cookies(session_bundle: dict) -> dict[str, str]:
    import json
    from pathlib import Path

    cookies = dict(session_bundle.get("cookies") or {})
    st_path = session_bundle.get("storage_state_path") or ""
    if not cookies and st_path and Path(st_path).is_file():
        try:
            raw = json.loads(Path(st_path).read_text(encoding="utf-8"))
            for c in raw.get("cookies", []):
                if c.get("name") and c.get("value"):
                    cookies[c["name"]] = c["value"]
        except Exception:
            pass
    return cookies


def execute_kiro_pairing_from_bundle(
    session_bundle: dict,
    http_session=None,
    timeout: int = 20,
) -> dict:
    """Execute end-to-end WAF-free GitHub OAuth + Cognito callback + PKCE code exchange using SessionBundle cookies."""
    from urllib.parse import parse_qs, urlparse

    proxy_url = session_bundle.get("proxy_url") or ""
    proxies = {"http": proxy_url, "https": proxy_url} if proxy_url else None
    gh_cookies = _load_bundle_cookies(session_bundle)
    if not gh_cookies.get("user_session"):
        return {
            "ok": False,
            "error": "missing_github_session_cookies",
            "hint": "Populate SessionBundle.cookies['user_session'] or storage_state_path before --execute",
            "plan": prepare_kiro_pairing_from_bundle(session_bundle, mode="pkce", http_session=http_session),
        }

    s = http_session or requests.Session()
    if proxies and hasattr(s, "proxies"):
        s.proxies.update(proxies)

    pkce = build_kiro_social_pkce_url("Github")
    r1 = s.get(pkce["login_url"], allow_redirects=False, timeout=timeout)
    cognito_url = r1.headers.get("location", "")
    if not cognito_url:
        return {"ok": False, "error": f"expected_302_from_login_got_{r1.status_code}"}

    r2 = s.get(cognito_url, allow_redirects=False, timeout=timeout)
    wrapper_url = r2.headers.get("location", "")
    if not wrapper_url:
        return {"ok": False, "error": f"expected_302_from_cognito_got_{r2.status_code}"}

    direct_gh_url = rewrite_kiro_github_authorize_url(wrapper_url)
    for k, v in gh_cookies.items():
        s.cookies.set(k, v, domain="github.com")

    r3 = s.get(direct_gh_url, allow_redirects=False, timeout=timeout)
    idp_loc = r3.headers.get("location", "")
    if r3.status_code == 200:
        form_data = _extract_github_oauth_form(r3.text)
        if not form_data:
            return {"ok": False, "error": "github_oauth_form_not_found_or_login_required"}
        r3_post = s.post(
            GITHUB_OAUTH_AUTHORIZE_URL,
            data=form_data,
            headers={"Referer": direct_gh_url, "Origin": "https://github.com"},
            allow_redirects=False,
            timeout=timeout,
        )
        idp_loc = r3_post.headers.get("location", "")

    if not idp_loc or "oauth/idpresponse" not in idp_loc:
        return {"ok": False, "error": "missing_cognito_idpresponse_redirect", "location": idp_loc}

    r4 = s.get(idp_loc, allow_redirects=False, timeout=timeout)
    kiro_loc = r4.headers.get("location", "")
    parsed_kiro = urlparse(kiro_loc)
    qs = parse_qs(parsed_kiro.query)
    code_list = qs.get("code") or []
    if not code_list:
        return {"ok": False, "error": "missing_kiro_auth_code", "location": kiro_loc}

    tok = exchange_kiro_social_code(
        code_list[0],
        pkce["code_verifier"],
        redirect_uri=pkce["redirect_uri"],
        proxies=proxies,
        timeout=timeout,
    )
    return {
        "ok": True,
        "username": session_bundle.get("username") or session_bundle.get("email") or "kiro-github",
        "email": session_bundle.get("email", ""),
        **tok,
    }
