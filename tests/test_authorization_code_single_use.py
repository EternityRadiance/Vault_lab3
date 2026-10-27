from __future__ import annotations
from urllib.parse import urlparse, parse_qs
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.audit_event import AuditEvent
from app.models.oauth_client import OAuthClient
from tests.conftest import auth_header


VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


class TestAuthCodeSingleUse:
    def test_code_cannot_be_used_twice(
        self,
        client: TestClient,
        oauth_client: OAuthClient,
        regular_token: str,
        db_session: Session,
    ):
        resp = client.get(
            "/oauth/authorize",
            params={
                "response_type": "code",
                "client_id": oauth_client.client_id,
                "redirect_uri": oauth_client.redirect_uris[0],
                "scope": "openid email",
                "state": "xyz",
                "code_challenge": CHALLENGE,
                "code_challenge_method": "S256",
            },
            headers=auth_header(regular_token),
            follow_redirects=False,
        )
        assert resp.status_code == 302
        location = resp.headers["location"]
        code = parse_qs(urlparse(location).query)["code"][0]

        resp = client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "client_id": oauth_client.client_id,
                "code": code,
                "redirect_uri": oauth_client.redirect_uris[0],
                "code_verifier": VERIFIER,
            },
        )
        assert resp.status_code == 200
        assert "access_token" in resp.json()

        resp = client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "client_id": oauth_client.client_id,
                "code": code,
                "redirect_uri": oauth_client.redirect_uris[0],
                "code_verifier": VERIFIER,
            },
        )
        assert resp.status_code == 400
        assert "already been used" in resp.json()["detail"]["error_description"].lower()

        events = (
            db_session.query(AuditEvent)
            .filter_by(event_type="auth_code.reuse_detected")
            .all()
        )
        assert len(events) >= 1