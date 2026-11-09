"""router_store.py — Universal CredentialSink (stdout, jsonl, http gateway, sqlite enc:v1) for Kiro credentials."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
import datetime
import json
import os
from pathlib import Path
import sqlite3
import sys
from typing import TextIO
import uuid
import requests
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


def load_dotenv_file(path: str | Path | None = None) -> None:
    candidates = [Path(path)] if path else [Path.cwd() / ".env", Path(__file__).resolve().parents[2] / ".env"]
    for p in candidates:
        if not p.is_file():
            continue
        for raw_line in p.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            k = k.strip()
            v = v.strip().strip("'").strip('"')
            if k and k not in os.environ:
                os.environ[k] = v
        break


load_dotenv_file()

DEFAULT_OMNI_DB = Path(os.environ.get("ROUTER_DB_PATH", str(Path.home() / "omniroute" / "databases" / "storage.sqlite")))
DEFAULT_OMNI_SALT = os.environ.get("STORAGE_ENCRYPTION_SALT", "omniroute-field-encryption-v1").encode("utf-8")
DEFAULT_ROUTER_URL = os.environ.get("ROUTER_URL", "http://127.0.0.1:20128")


def _resolve_secret(secret: str | None = None) -> str:
    load_dotenv_file()
    val = secret or os.environ.get("STORAGE_ENCRYPTION_KEY", "")
    if not val:
        raise ValueError("STORAGE_ENCRYPTION_KEY is required in environment or .env for SQLite encryption")
    return val


@dataclass
class CredentialBundle:
    version: str = "1.0"
    provider: str = "kiro"
    auth_type: str = "oauth"
    auth_method: str = "github"
    name: str = ""
    email: str = ""
    access_token: str = ""
    refresh_token: str = ""
    api_key: str = ""
    profile_arn: str = ""
    region: str = "us-east-1"
    expires_in: int = 3600
    created_at: str = field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    )

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self, indent: int | None = None) -> str:
        return json.dumps(self.to_dict(), indent=indent)


def encrypt_field(
    plaintext: str,
    secret: str | None = None,
    salt: bytes = DEFAULT_OMNI_SALT,
) -> str:
    key_str = _resolve_secret(secret)
    kdf = Scrypt(salt=salt, length=32, n=16384, r=8, p=1)
    key = kdf.derive(key_str.encode("utf-8"))
    iv = os.urandom(16)
    aes = AESGCM(key)
    ct_with_tag = aes.encrypt(iv, plaintext.encode("utf-8"), None)
    ct, tag = ct_with_tag[:-16], ct_with_tag[-16:]
    return f"enc:v1:{iv.hex()}:{ct.hex()}:{tag.hex()}"


def decrypt_field(
    token: str,
    secret: str | None = None,
    salt: bytes = DEFAULT_OMNI_SALT,
) -> str:
    if not token.startswith("enc:v1:"):
        return token
    key_str = _resolve_secret(secret)
    _, _, iv_hex, ct_hex, tag_hex = token.split(":", 4)
    kdf = Scrypt(salt=salt, length=32, n=16384, r=8, p=1)
    key = kdf.derive(key_str.encode("utf-8"))
    aes = AESGCM(key)
    raw = aes.decrypt(bytes.fromhex(iv_hex), bytes.fromhex(ct_hex) + bytes.fromhex(tag_hex), None)
    return raw.decode("utf-8")


def install_kiro_to_db(
    name: str,
    access_token: str,
    refresh_token: str = "",
    profile_arn: str = "",
    auth_method: str = "github",
    region: str = "us-east-1",
    db_path: str | Path = DEFAULT_OMNI_DB,
    secret: str | None = None,
) -> str:
    """Insert a Kiro connection into StyxRouter/OmniRoute SQLite."""
    conn_id = str(uuid.uuid4())
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    auth_type = "apikey" if auth_method == "api_key" else "oauth"
    enc_key = encrypt_field(access_token, secret=secret) if auth_type == "apikey" else None
    enc_at = encrypt_field(access_token, secret=secret)
    enc_rt = encrypt_field(refresh_token, secret=secret) if refresh_token else None
    psd = json.dumps(
        {
            "authMethod": auth_method,
            "profileArn": profile_arn or None,
            "region": region,
        }
    )

    con = sqlite3.connect(str(db_path), timeout=30)
    try:
        con.execute(
            """
            INSERT INTO provider_connections (
                id, provider, auth_type, name, api_key, access_token, refresh_token,
                provider_specific_data, is_active, test_status, created_at, updated_at
            ) VALUES (?, 'kiro', ?, ?, ?, ?, ?, ?, 1, 'active', ?, ?)
            """,
            (conn_id, auth_type, name, enc_key, enc_at, enc_rt, psd, now, now),
        )
        con.commit()
    finally:
        con.close()
    return conn_id


def import_kiro_api_key_http(
    api_key: str,
    region: str = "us-east-1",
    router_url: str = DEFAULT_ROUTER_URL,
    timeout: int = 20,
) -> dict:
    """Import a 365-day Kiro API key via POST /api/oauth/kiro/api-key."""
    r = requests.post(
        f"{router_url.rstrip('/')}/api/oauth/kiro/api-key",
        json={"apiKey": api_key, "region": region},
        timeout=timeout,
    )
    r.raise_for_status()
    return r.json()


def dispatch_credential_sink(
    bundle: CredentialBundle,
    sink: str = "stdout",
    stream: TextIO = sys.stdout,
    secret: str | None = None,
) -> dict:
    """Route a CredentialBundle to stdout, file:<path>, http:<router_url>, or sqlite:<db_path>."""
    if sink == "stdout":
        stream.write(bundle.to_json() + "\n")
        stream.flush()
        return {"sink": "stdout", "ok": True}
    if sink.startswith("file:"):
        out_path = Path(sink[len("file:"):])
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("a", encoding="utf-8") as f:
            f.write(bundle.to_json() + "\n")
        return {"sink": "file", "path": str(out_path), "ok": True}
    if sink.startswith("http:") or sink.startswith("https:"):
        token_val = bundle.api_key or bundle.access_token
        res = import_kiro_api_key_http(token_val, region=bundle.region, router_url=sink)
        return {"sink": "http", "response": res, "ok": True}
    if sink == "sqlite" or sink.startswith("sqlite:"):
        db_target = Path(sink[len("sqlite:"):]) if sink.startswith("sqlite:") and len(sink) > 7 else DEFAULT_OMNI_DB
        cid = install_kiro_to_db(
            name=bundle.name or bundle.email or "kiro-account",
            access_token=bundle.api_key or bundle.access_token,
            refresh_token=bundle.refresh_token,
            profile_arn=bundle.profile_arn,
            auth_method=bundle.auth_method,
            region=bundle.region,
            db_path=db_target,
            secret=secret,
        )
        return {"sink": "sqlite", "connection_id": cid, "db_path": str(db_target), "ok": True}
    raise ValueError(f"Unsupported sink specification: {sink}")
