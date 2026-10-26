"""
demo-RP -- демонстрационный Relying Party для Vault как OIDC-провайдера.

Запуск: uvicorn demo_rp.main:app --port 8001
"""

from __future__ import annotations

import base64
import hashlib
import secrets
from pathlib import Path
from urllib.parse import urlencode

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from jose import jwt, jwk


VAULT_URL = "http://127.0.0.1:8000"
CLIENT_ID = "9c05f478b92149e5b7b3d99b89006587"
REDIRECT_URI = "http://127.0.0.1:8001/callback"
SCOPES = ["openid", "profile", "email"]


app = FastAPI(title="Vault Demo RP")
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _gen_pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    challenge = _b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    return verifier, challenge


def _get_jwks() -> dict:
    resp = httpx.get(f"{VAULT_URL}/.well-known/jwks.json", timeout=5)
    resp.raise_for_status()
    return resp.json()


def _verify_id_token(id_token: str, nonce: str | None = None) -> dict:
    header = jwt.get_unverified_header(id_token)
    jwks = _get_jwks()
    key_data = next((k for k in jwks["keys"] if k["kid"] == header.get("kid")), None)
    if key_data is None:
        raise ValueError("No matching key in JWKS")
    public_key = jwk.construct(key_data, algorithm="RS256")
    payload = jwt.decode(
        id_token, public_key, algorithms=["RS256"],
        audience=CLIENT_ID, issuer=VAULT_URL,
    )
    if nonce and payload.get("nonce") != nonce:
        raise ValueError("nonce mismatch")
    return payload


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    access_token = request.cookies.get("access_token")
    id_token = request.cookies.get("id_token")

    if not access_token:
        return templates.TemplateResponse(
            "index.html",
            {"request": request, "logged_in": False, "issuer": VAULT_URL},
        )

    email = None
    try:
        payload = _verify_id_token(id_token) if id_token else {}
        email = payload.get("email") or payload.get("sub")
    except Exception:
        response = RedirectResponse("/logout", status_code=303)
        response.delete_cookie("access_token")
        response.delete_cookie("id_token")
        response.delete_cookie("refresh_token")
        return response

    return templates.TemplateResponse(
        "index.html",
        {"request": request, "logged_in": True, "email": email, "issuer": VAULT_URL},
    )


@app.get("/login")
def login(request: Request):
    verifier, challenge = _gen_pkce()
    state = secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(16)

    params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "scope": " ".join(SCOPES),
        "state": state,
        "nonce": nonce,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    url = f"{VAULT_URL}/oauth/authorize?{urlencode(params)}"

    response = RedirectResponse(url, status_code=302)
    response.set_cookie("pkce_verifier", verifier, httponly=True, max_age=300)
    response.set_cookie("oauth_state", state, httponly=True, max_age=300)
    response.set_cookie("oauth_nonce", nonce, httponly=True, max_age=300)
    return response


@app.get("/callback")
def callback(request: Request, code: str | None = None, state: str | None = None, error: str | None = None):
    if error:
        raise HTTPException(400, f"OAuth error: {error}")
    if not code or not state:
        raise HTTPException(400, "Missing code or state")

    expected_state = request.cookies.get("oauth_state")
    if not expected_state or expected_state != state:
        raise HTTPException(400, "Invalid state")

    verifier = request.cookies.get("pkce_verifier")
    nonce = request.cookies.get("oauth_nonce")
    if not verifier:
        raise HTTPException(400, "Missing PKCE verifier")

    token_resp = httpx.post(
        f"{VAULT_URL}/oauth/token",
        data={
            "grant_type": "authorization_code",
            "client_id": CLIENT_ID,
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "code_verifier": verifier,
        },
        timeout=10,
    )
    if token_resp.status_code != 200:
        raise HTTPException(400, f"Token exchange failed: {token_resp.text}")

    data = token_resp.json()
    access_token = data["access_token"]
    id_token = data.get("id_token")
    refresh_token = data.get("refresh_token")

    if id_token:
        _verify_id_token(id_token, nonce=nonce)

    response = RedirectResponse("/", status_code=303)
    response.set_cookie("access_token", access_token, httponly=True, max_age=3600)
    if id_token:
        response.set_cookie("id_token", id_token, httponly=True, max_age=3600)
    if refresh_token:
        response.set_cookie("refresh_token", refresh_token, httponly=True, max_age=86400 * 30)

    response.delete_cookie("pkce_verifier")
    response.delete_cookie("oauth_state")
    response.delete_cookie("oauth_nonce")
    return response


@app.post("/logout")
def logout(request: Request):
    refresh_token = request.cookies.get("refresh_token")
    if refresh_token:
        try:
            httpx.post(
                f"{VAULT_URL}/oauth/revoke",
                data={"token": refresh_token, "token_type_hint": "refresh_token"},
                timeout=5,
            )
        except Exception:
            pass

    response = RedirectResponse("/", status_code=303)
    response.delete_cookie("access_token")
    response.delete_cookie("id_token")
    response.delete_cookie("refresh_token")
    return response


@app.get("/profile", response_class=HTMLResponse)
def profile(request: Request):
    access_token = request.cookies.get("access_token")
    id_token = request.cookies.get("id_token")
    if not access_token:
        return RedirectResponse("/login", status_code=303)

    try:
        id_payload = _verify_id_token(id_token) if id_token else {}
        access_payload = jwt.get_unverified_claims(access_token)
    except Exception:
        return RedirectResponse("/logout", status_code=303)

    return templates.TemplateResponse(
        "profile.html",
        {
            "request": request,
            "issuer": VAULT_URL,
            "id_claims": id_payload,
            "access_claims": access_payload,
        },
    )
