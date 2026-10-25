from __future__ import annotations
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any
from uuid import uuid4

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jose import JWTError, jwt

from app.config import settings

@lru_cache(maxsize=1)
def load_private_key() -> rsa.RSAPrivateKey:
    path = Path(settings.rsa_key_path)
    if not path.is_absolute():
        path = Path(__file__).resolve().parents[3] / path
    if not path.exists():
        raise FileNotFoundError(
            f"RSA private key not found: {path}. "
            f"Run: python scripts/gen_keys.py"
        )
    return serialization.load_pem_private_key(path.read_bytes(), password=None)

@lru_cache(maxsize=1)
def load_public_key() -> rsa.RSAPublicKey:
    return load_private_key().public_key()

def _private_pem() -> str:
    return load_private_key().private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

def _public_pem() -> str:
    return load_public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

def sign_access_token(
        sub: str | int,
        client_id: str,
        scopes: list[str],
        ttl_sec: int | None = None,
        extra_claims: dict[str, Any] | None = None,
) -> str:
    if ttl_sec is None:
        ttl_sec = settings.access_token_ttl_sec

    now = datetime.now(timezone.utc)
    payload: dict[str, Any] = {
        "iss": settings.issuer,
        "sub": str(sub),
        "aud": client_id,
        "scope": " ".join(scopes),
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=ttl_sec)).timestamp()),
        "jti": uuid4().hex,
        "typ": "access",
    }
    if extra_claims:
        payload.update(extra_claims)

    headers = {
        "alg": "RS256",
        "kid": settings.rsa_key_id,
        "typ": "JWT",
    }
    return jwt.encode(payload, _private_pem(), algorithm="RS256", headers=headers)

def sign_id_token(
        sub: str | int,
        client_id: str,
        user: Any,
        scopes: list[str],
        nonce: str | None = None,
        ttl_sec: int | None = 300,
) -> str:
    now = datetime.now(timezone.utc)
    payload: dict[str, Any] = {
        "iss": settings.issuer,
        "sub": str(sub),
        "aud": client_id,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=ttl_sec)).timestamp()),
        "auth_time": int(now.timestamp()),
    }
    if nonce:
        payload["nonce"] = nonce

    if "email" in scopes:
        payload["email"] = user.email
        payload["email_verified"] = True

    if "profile" in scopes:
        username = user.email.split("@")[0]
        payload["preferred_username"] = username
        payload["name"] = username

    headers = {
        "alg": "RS256",
        "kid": settings.rsa_key_id,
        "typ": "JWT",
    }
    return jwt.encode(payload, _private_pem(), algorithm="RS256", headers=headers)

def verify_token(
        token: str,
        audience: str | None = None,
        issuer: str | None = None,
) -> dict:
    if not token or not isinstance(token, str):
        raise ValueError("Empty token")

    try:
        payload = jwt.decode(
            token,
            _public_pem(),
            algorithms=["RS256"],
            audience=audience,
            issuer=issuer or settings.issuer,
            options={"verify_aud": audience is not None},
        )
    except JWTError as e:
        raise ValueError(f"Invalid token: {e}") from e

    if not isinstance(payload, dict):
        raise ValueError("Invalid token payload")

    return payload