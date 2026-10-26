from __future__ import annotations
from fastapi import APIRouter, Depends, Form, Request
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.oauth.client_auth import authenticate_client
from app.oauth.errors import UNSUPPORTED_GRANT_TYPE, oauth_json_error
from app.oauth.grants.authorization_code import handle_authorization_code_grant
from app.oauth.grants.password import handle_password_grant

router = APIRouter(tags=["oauth"])

@router.post("/oauth/token", include_in_schema=False)
def token(
    request: Request,
    grant_type: str = Form(...),
    client_id: str | None = Form(default=None),
    client_secret: str | None = Form(default=None),
    scope: str | None = Form(default=None),
    username: str | None = Form(default=None),
    password: str | None = Form(default=None),
    code: str | None = Form(default=None),
    redirect_uri: str | None = Form(default=None),
    code_verifier: str | None = Form(default=None),
    db: Session = Depends(get_db),
) -> dict:
    client = authenticate_client(db, request, client_id, client_secret)

    if grant_type == "password":
        return handle_password_grant(
            db, request,
            client=client,
            username=username,
            password=password,
            scope=scope,
        )

    if grant_type == "authorization_code":
        return handle_authorization_code_grant(
            db, request,
            client=client,
            code=code,
            redirect_uri=redirect_uri,
            code_verifier=code_verifier,
        )

    oauth_json_error(
        UNSUPPORTED_GRANT_TYPE,
        f"grant_type={grant_type!r} is not supported",
    )