from __future__ import annotations
from fastapi.testclient import TestClient
from jose import jwt

from app.models.oauth_client import OAuthClient


class TestClientCredentials:
    def test_confidential_client_gets_token(
        self,
        client: TestClient,
        oauth_confidential_client: OAuthClient,
    ):
        resp = client.post(
            "/oauth/token",
            data={
                "grant_type": "client_credentials",
                "client_id": oauth_confidential_client.client_id,
                "client_secret": "test-conf-secret-12345",
                "scope": "openid",
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        assert "refresh_token" not in data
        assert "id_token" not in data

        payload = jwt.get_unverified_claims(data["access_token"])
        assert payload["sub"] == oauth_confidential_client.client_id
        assert payload["aud"] == oauth_confidential_client.client_id

    def test_public_client_rejected(
        self,
        client: TestClient,
        oauth_client: OAuthClient,
    ):
        resp = client.post(
            "/oauth/token",
            data={
                "grant_type": "client_credentials",
                "client_id": oauth_client.client_id,
                "scope": "openid",
            },
        )
        assert resp.status_code in (400, 401)
        detail = resp.json()["detail"]
        assert detail["error"] in ("unauthorized_client", "invalid_client")