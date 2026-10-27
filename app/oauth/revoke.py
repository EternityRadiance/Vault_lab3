from __future__ import annotations
from datetime import datetime, timezone
from fastapi import APIRouter, Form, Request
from fastapi.responses import JSONResponse
from jose import JWTError, jwt
from sqlalchemy import select, update
from sqlalchemy.orm import Session
from fastapi import Depends

from app.audit.events import OAuthEvents
from app.audit.service import get_client_info, write_event
from app.config import settings
from app.core.security.jwt_rsa import load_public_key
from app.db.session import get_db
from app.models.refresh_token import RefreshToken
from app.models.user_session import UserSession
from app.oauth.client_auth import authenticate_client
from app.oauth.tokens import sha256_hex
from app.redis_client import blacklist_jti

router = APIRouter(tags=["oauth"])

def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)

def _revoke_refresh_token(db: Session, raw_token: str, request: Request) -> None:
    token_hash = sha256_hex(raw_token)
    rt = db.execute(
        select(RefreshToken).where(RefreshToken.token_hash == token_hash)
    ).scalar_one_or_none()

    if rt is None:
        return

    if rt.revoked_at is None:
        now = _utcnow()
        rt.revoked_at = now

        db.execute(
            update(UserSession)
            .where(UserSession.family_id == rt.family_id, UserSession.revoked_at.is_(None))
            .values(revoked_at=now)
        )
        db.commit()

        info = get_client_info(request)
        write_event(
            db,
            OAuthEvents.TOKEN_REVOKED,
            actor_id=rt.user_id,
            client_id=rt.client_id,
            ip=info["ip"],
            user_agent=info["user_agent"],
            metadata={"token_type": "refresh_token", "family_id": rt.family_id},
        )

def _revoke_access_token(raw_token: str, request: Request, db: Session) -> None:
    try:
        payload = jwt.decode(
            raw_token,
            load_public_key(),
            algorithms=["RS256"],
            options={"verify_aud": False, "verify_iss": False},
        )
    except JWTError:
        return

    jti = payload.get("jti")
    exp = payload.get("exp")
    if not jti or not exp:
        return

    ttl = exp - int(datetime.now(timezone.utc).timestamp())
    if ttl > 0:
        blacklist_jti(jti, ttl)

        info = get_client_info(request)
        write_event(
            db,
            OAuthEvents.TOKEN_REVOKED,
            actor_id=None,
            client_id=payload.get("aud") if isinstance(payload.get("aud"), str) else None,
            ip=info["ip"],
            user_agent=info["user_agent"],
            metadata={"token_type": "access_token", "jti": jti},
        )

@router.post("/oauth/revoke")
def revoke(
    request: Request,
    token: str = Form(...),
    token_type_hint: str | None = Form(default=None),
    client_id: str | None = Form(default=None),
    client_secret: str | None = Form(default=None),
    db: Session = Depends(get_db),
):
    client = authenticate_client(db, request, client_id, client_secret)

    if token_type_hint == "refresh_token":
        _revoke_refresh_token(db, token, request)
    elif token_type_hint == "access_token":
        _revoke_access_token(token, request, db)
    else:
        _revoke_refresh_token(db, token, request)
        _revoke_access_token(token, request, db)

    return JSONResponse(status_code=200, content={})