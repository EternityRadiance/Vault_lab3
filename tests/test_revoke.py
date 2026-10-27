from __future__ import annotations
from fastapi.testclient import TestClient

from app.models.oauth_client import OAuthClient


class TestRevoke:
    def test_revoke_access_token(
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
        access_token = resp.json()["access_token"]

        resp = client.post(
            "/oauth/introspect",
            data={
                "token": access_token,
                "token_type_hint": "access_token",
                "client_id": oauth_confidential_client.client_id,
                "client_secret": "test-conf-secret-12345",
            },
        )
        assert resp.status_code == 200
        assert resp.json()["active"] is True

        resp = client.post(
            "/oauth/revoke",
            data={
                "token": access_token,
                "token_type_hint": "access_token",
                "client_id": oauth_confidential_client.client_id,
                "client_secret": "test-conf-secret-12345",
            },
        )
        assert resp.status_code == 200

        resp = client.post(
            "/oauth/introspect",
            data={
                "token": access_token,
                "token_type_hint": "access_token",
                "client_id": oauth_confidential_client.client_id,
                "client_secret": "test-conf-secret-12345",
            },
        )
        assert resp.status_code == 200
        assert resp.json()["active"] is False