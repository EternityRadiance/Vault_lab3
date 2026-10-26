from __future__ import annotations
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit.events import OAuthEvents
from app.audit.service import get_client_info, write_event
from app.config import settings
from app.core.deps import get_current_user
from app.db.session import get_db
from app.models.auth_code import AuthCode
from app.models.oauth_client import OAuthClient
from app.models.user import User

from app.oauth.errors import (
    ACCESS_DENIED,
    INVALID_REQUEST,
    INVALID_SCOPE,
    UNAUTHORIZED_CLIENT,
    UNSUPPORTED_RESPONSE_TYPE,
    oauth_json_error,
    oauth_redirect_error,
)

router = APIRouter(tags=["oauth"])

def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)

def _sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()

@router.get("/oauth/authorize", include_in_schema=False)
def authorize(
    request: Request,
    response_type: str = Query(...),
    client_id: str = Query(...),
    redirect_uri: str = Query(...),
    scope: str = Query(default=""),
    state: str | None = Query(default=None),
    code_challenge: str | None = Query(default=None),
    code_challenge_method: str | None = Query(default=None),
    nonce: str | None = Query(default=None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    info = get_client_info(request)

    client = db.execute(
        select(OAuthClient).where(OAuthClient.client_id == client_id)
    ).scalar_one_or_none()

    if client is None or not client.is_active:
        write_event(
            db,
            OAuthEvents.AUTHORIZE_FAILURE,
            actor_id=current_user.id,
            ip=info["ip"],
            user_agent=info["user_agent"],
            metadata={
                "client_id": client_id,
                "reason": "unknown_or_inactive_client",
            },
        )
        oauth_json_error(INVALID_REQUEST, "Unknown or inactive client")

    if redirect_uri not in (client.redirect_uris or []):
        write_event(
            db,
            OAuthEvents.AUTHORIZE_FAILURE,
            actor_id=current_user.id,
            client_id=client.client_id,
            ip=info["ip"],
            user_agent=info["user_agent"],
            metadata={
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "reason": "invalid_redirect_uri",
            },
        )
        oauth_json_error(INVALID_REQUEST, "Invalid redirect_uri")

    if response_type != "code":
        return oauth_redirect_error(
            redirect_uri, UNSUPPORTED_RESPONSE_TYPE, state,
            f"Only 'code' is supported, got {response_type!r}",
        )

    if not state:
        return oauth_redirect_error(
            redirect_uri, INVALID_REQUEST, None,
            "state is required",
        )

    requested_scopes = scope.split() if scope else []
    allowed_scopes = set(client.scopes or [])
    if not set(requested_scopes).issubset(allowed_scopes):
        return oauth_redirect_error(
            redirect_uri, INVALID_SCOPE, state,
            f"Allowed scopes: {sorted(allowed_scopes)}",
        )

    if "authorization_code" not in (client.grant_types or []):
        write_event(
            db,
            OAuthEvents.AUTHORIZE_FAILURE,
            actor_id=current_user.id,
            client_id=client.client_id,
            ip=info["ip"],
            user_agent=info["user_agent"],
            metadata={
                "client_id": client_id,
                "reason": "grant_not_allowed",
            },
        )
        return oauth_redirect_error(
            redirect_uri, UNAUTHORIZED_CLIENT, state,
            "authorization_code grant not allowed for this client",
        )

    if client.is_confidential is False and settings.pkce_required_for_public:
        if not code_challenge:
            return oauth_redirect_error(
                redirect_uri, INVALID_REQUEST, state,
                "code_challenge is required for public clients",
            )
        if code_challenge_method != "S256":
            return oauth_redirect_error(
                redirect_uri, INVALID_REQUEST, state,
                "code_challenge_method must be S256",
            )

    raw_code = secrets.token_urlsafe(48)
    code_hash = _sha256_hex(raw_code)

    auth_code = AuthCode(
        code_hash=code_hash,
        client_id=client.client_id,
        user_id=current_user.id,
        redirect_uri=redirect_uri,
        scope=" ".join(requested_scopes),
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
        nonce=nonce,
        expires_at=_utcnow() + timedelta(seconds=settings.auth_code_ttl_sec),
    )
    db.add(auth_code)
    db.commit()

    write_event(
        db,
        OAuthEvents.AUTHORIZE_SUCCESS,
        actor_id=current_user.id,
        client_id=client.client_id,
        ip=info["ip"],
        user_agent=info["user_agent"],
        metadata={
            "client_id": client.client_id,
            "scope": " ".join(requested_scopes),
            "redirect_uri": redirect_uri,
            "has_pkce": bool(code_challenge),
        },
    )

    params = {"code": raw_code, "state": state}
    location = f"{redirect_uri}?{urlencode(params)}"
    return RedirectResponse(url=location, status_code=302)