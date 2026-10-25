from __future__ import annotations
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.audit_event import AuditEvent
from app.models.user import User
from tests.conftest import auth_header

class TestRegister:
    def test_register_201(self, client: TestClient):
        resp = client.post(
            "/auth/register",
            json={
                "email": "new@example.com",
                "password": "some long long string as password",
            },
        )
        assert resp.status_code == 201
        body = resp.json()
        assert "access_token" in body
        assert body["token_type"] == "bearer"
        assert len(body["access_token"]) > 50


    def test_register_create_audit(
            self, client: TestClient, db_session: Session
    ):
        client.post(
            "/auth/register",
            json={
                "email": "audit@example.com",
                "password": "some long long string as password",
            },
        )
        events = db_session.query(AuditEvent).filter_by(event_type="user.created").all()
        assert len(events) == 1
        assert events[0].metadata_json["email"] == "audit@example.com"

    def test_register_duplicate_email(
            self, client: TestClient, regular_user: User
    ):
        resp = client.post(
            "/auth/register",
            json={
                "email": regular_user.email,
                "password": "some long long string as password",
            },
        )
        assert resp.status_code == 409
        assert "already registered" in resp.json()["detail"].lower()

    def test_register_weak_password(self, client: TestClient):
        resp = client.post(
            "/auth/register",
            json={"email": "weak@example.com", "password": "qwerty"},
        )
        assert resp.status_code == 400
        assert "короче" in resp.json()["detail"] or "слабый" in resp.json()["detail"].lower()

    def test_invalid_email(self, client: TestClient):
        resp = client.post(
            "/auth/register",
            json={"email": "not-an-email", "password": "some long long string as password",},
        )
        assert resp.status_code == 422

class TestLogin:
    def test_login_correct_password(self, client: TestClient, regular_user: User):
        resp = client.post(
            "/auth/login",
            json={
                "email": regular_user.email,
                "password": "Very strong user password",
            },
        )
        assert resp.status_code == 200
        assert "access_token" in resp.json()

    def test_login_wrong_password(self, client: TestClient, regular_user: User):
        resp = client.post(
            "/auth/login",
            json={
                "email": regular_user.email,
                "password": "wrong password",
            },
        )
        assert resp.status_code == 401
        assert resp.json()["detail"] == "Invalid credentials"

    def test_login_unknown_email(self, client: TestClient):
        resp = client.post(
            "/auth/login",
            json={"email": "nobody@example.com", "password": "whatever password"},
        )
        assert resp.status_code == 401
        assert resp.json()["detail"] == "Invalid credentials"

    def test_login_and_unknown_message(self, client: TestClient, regular_user: User):
        resp_wrong = client.post(
            "/auth/login",
            json={"email": regular_user.email, "password": "wrong password"},
        )
        resp_unknown = client.post(
            "/auth/login",
            json={"email": "nobody@example.com", "password": "wrong password"},
        )
        assert resp_wrong.json() == resp_unknown.json()
        assert resp_wrong.status_code == resp_unknown.status_code == 401

    def test_login_writes_audit_failure(self, client: TestClient, regular_user: User, db_session: Session
    ):
        client.post(
            "/auth/login",
            json={"email": regular_user.email, "password": "wrong password"},
        )
        events = (
            db_session.query(AuditEvent)
            .filter_by(event_type="user.login.failure")
            .all()
        )
        assert len(events) == 1
        assert events[0].metadata_json["reason"] == "bad_password"

    def test_login_writes_audit_success(
        self, client: TestClient, regular_user: User, db_session: Session
    ):
        client.post(
            "/auth/login",
            json={
                "email": regular_user.email,
                "password": "Very strong user password",
            },
        )
        events = (
            db_session.query(AuditEvent)
            .filter_by(event_type="user.login.success")
            .all()
        )
        assert len(events) == 1

class TestMe:
    def test_me_without_token(self, client: TestClient):
        resp = client.get("auth/me")
        assert resp.status_code == 401

    def test_me_invalid_token(self, client: TestClient):
        resp = client.get("auth/me", headers=auth_header("some_token"))
        assert resp.status_code == 401

    def test_me_valid_token(
            self, client: TestClient, regular_user: User, regular_token: str
    ):
        resp = client.get("/auth/me", headers=auth_header(regular_token))
        assert resp.status_code == 200
        body = resp.json()
        assert body["id"] == regular_user.id
        assert body["email"] == regular_user.email
        assert body["is_admin"] is False

    def test_me_not_leak_hashed(
            self, client: TestClient, regular_token: str
    ):
        resp = client.get("auth/me", headers=auth_header(regular_token))
        body = resp.json()
        assert "hashed_password" not in body
        assert "password" not in body