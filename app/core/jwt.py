from __future__ import annotations
from datetime import datetime, timedelta, timezone
from uuid import uuid4
from jose import JWTError, jwt

from app.config import settings

TOKEN_TYPE_ACCESS = "access"

def create_access_token(sub: str | int, ttl_min: int | None = None) -> str:
    if ttl_min is None:
        ttl_min = settings.access_token_ttl_min

    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(sub),
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=ttl_min)).timestamp()),
        "jti": uuid4().hex,
        "typ": TOKEN_TYPE_ACCESS,
    }

    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)

def decode_token(token: str) -> dict:
    if not token or not isinstance(token, str):
        raise ValueError("Пустой токен.")

    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret,
            algorithms=[settings.jwt_algorithm],
        )
    except JWTError as e:
        raise ValueError("Невалидный токен") from e

    if not isinstance(payload, dict):
        raise ValueError("Некорректный payload токена.")

    if payload.get("typ") != TOKEN_TYPE_ACCESS:
        raise ValueError("Не access-токен.")

    return payload