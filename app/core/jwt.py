from __future__ import annotations

from app.config import settings
from app.core.security.jwt_rsa import sign_access_token, verify_token

TOKEN_TYPE_ACCESS = "access"

def create_access_token(sub: str | int, ttl_min: int | None = None) -> str:
    if ttl_min is None:
        ttl_min = settings.access_token_ttl_sec // 60

    return sign_access_token(
        sub=sub,
        client_id="vault-internal",
        scopes=["openid"],
        ttl_sec=ttl_min * 60,
    )

def decode_token(token: str) -> dict:
    try:
        return verify_token(token)
    except ValueError:
        raise