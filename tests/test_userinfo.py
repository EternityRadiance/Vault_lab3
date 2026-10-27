from __future__ import annotations
from fastapi.testclient import TestClient
from urllib.parse import urlparse, parse_qs

from app.models.oauth_client import OAuthClient


def _get_access_token(client, oauth_client, user, scope, password="Very strong user password"):
    login = client.post(
        "/auth/login",
        json={"email": user.email, "password": password},
    )
    user_token = login.json()["access_token"]

    resp = client.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": oauth_client.client_id,
            "redirect_uri": oauth_client.redirect_uris[0],
            "scope": scope,
            "state": "x",
            "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            "code_challenge_method": "S256",
        },
        headers={"Authorization": f"Bearer {user_token}"},
        follow_redirects=False,
    )
    code = parse_qs(urlparse(resp.headers["location"]).query)["code"][0]

    token_resp = client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "client_id": oauth_client.client_id,
            "code": code,
            "redirect_uri": oauth_client.redirect_uris[0],
            "code_verifier": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
        },
    )
    return token_resp.json()


class TestUserinfo:
    def test_userinfo_with_openid_only(
        self, client: TestClient, oauth_client: OAuthClient, regular_user
    ):
        tokens = _get_access_token(client, oauth_client, regular_user, "openid")
        resp = client.get(
            "/oauth/userinfo",
            headers={"Authorization": f"Bearer {tokens['access_token']}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "sub" in data
        assert "email" not in data
        assert "name" not in data

    def test_userinfo_with_email_scope(
        self, client: TestClient, oauth_client: OAuthClient, regular_user
    ):
        tokens = _get_access_token(client, oauth_client, regular_user, "openid email")
        resp = client.get(
            "/oauth/userinfo",
            headers={"Authorization": f"Bearer {tokens['access_token']}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["email"] == regular_user.email
        assert data["email_verified"] is True

    def test_userinfo_without_token(self, client: TestClient):
        resp = client.get("/oauth/userinfo")
        assert resp.status_code == 401