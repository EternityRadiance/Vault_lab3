from __future__ import annotations
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from uuid import uuid4
from sqlalchemy.orm import Session

from app.config import settings
from app.core.security.jwt_rsa import sign_access_token, sign_id_token
from app.models.refresh_token import RefreshToken
from app.models.user import User

def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)

def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()

def generate_refresh_token(
        db: Session,
        *,
        user_id: int,
        client_id: int,
        scope: str,
        family_id: str | None = None,
) -> tuple[str, RefreshToken]:
    raw_token = secrets.token_urlsafe(48)
    token_hash = sha256_hex(raw_token)
    family_id = family_id or uuid4().hex

    record = RefreshToken(
        jti=uuid4().hex,
        family_id=family_id,
        token_hash=token_hash,
        user_id=user_id,
        client_id=client_id,
        scope=scope,
        expires_at=_utcnow() + timedelta(days=settings.refresh_token_ttl_days),
    )
    db.add(record)
    return raw_token, record

def issue_token_response(
        *,
        user: User,
        client_id: str,
        scopes: list[str],
        raw_refresh: str | None,
        include_id_token: bool,
        nonce: str | None = None,
) -> dict:
    access = sign_access_token(
        sub=user.id,
        client_id=client_id,
        scopes=scopes,
    )

    response = {
        "access_token": access,
        "token_type": "Bearer",
        "expires_in": settings.access_token_ttl_sec,
        "scope": " ".join(scopes),
    }

    if raw_refresh:
        response["refresh_token"] = raw_refresh

    if include_id_token and "openid" in scopes:
        response["id_token"] = sign_id_token(
            sub=user.id,
            client_id=client_id,
            user=user,
            scopes=scopes,
            nonce=nonce,
        )

    return response