from __future__ import annotations
from fastapi.testclient import TestClient
from tests.conftest import auth_header

def gql(client: TestClient, query: str, variables: dict | None = None, token: str | None = None):

    headers = {"Content-Type": "application/json"}
    if token:
        headers.update(auth_header(token))

    return client.post(
        "/graphql/",
        json={"query": query, "variables": variables or {}},
        headers=headers,
    ).json()

class TestMeQuery:
    def test_me_without_token(self, client: TestClient):
        result = gql(client, "{ me { id email } }")
        assert result["data"] is None
        assert any("Authentication" in e["message"] for e in result["errors"])

    def test_me_with_token(self, client: TestClient, regular_token: str):
        result = gql(client, "{ me { id email isActive isAdmin } }", token=regular_token)
        assert "errors" not in result or result["errors"] is None
        me = result["data"]["me"]
        assert me["email"] == "user@example.com"
        assert me["isActive"] is True
        assert me["isAdmin"] is False

class TestUserQuery:
    def test_user_without_token(self, client: TestClient):
        result = gql(client, "{ users { id email } }")
        assert result["data"] is None
        assert any("Authentication" in e["message"] for e in result["errors"])

    def test_user_with_forbidden(
            self, client: TestClient, admin_token: str, admin_user, regular_user
    ):
        result = gql(client, "{ users { id email isAdmin } }", token=admin_token)
        assert result["data"] is not None
        users = result["data"]["users"]
        emails = {u["email"] for u in users}
        assert admin_user.email in emails
        assert regular_user.email in emails

class TestRegisterUserMutation:
    def test_register_returns_token(self, client: TestClient):
        result = gql(
            client,
            """
            mutation {
                registerUser(email: "gqluser@example.com", password: "long long password must be here") {
                    accessToken
                    tokenType
                }
            }
            """,
        )
        assert result["data"] is not None
        payload = result["data"]["registerUser"]
        assert payload["tokenType"] == "bearer"
        assert len(payload["accessToken"]) > 50   

    def test_register_weak_password(self, client: TestClient):
        result = gql(
            client,
            """
            mutation {
                registerUser(email: "weakgql@example.com", password: "qwerty") {
                    accessToken
                }
            }
            """,
        )
        assert result["data"] is None
        assert any("короче" in e["message"].lower() or "слабый" in e["message"].lower()
                   for e in result["errors"])

class TestCreateClientMutation:
    def test_create_client_without_token(self, client: TestClient):
        result = gql(
            client,
            'mutation { createClient(name: "X") { id name } }',
        )
        assert result["data"] is None
        assert any("Authentication" in e["message"] for e in result["errors"])

    def test_create_client_with_forbidden(
        self, client: TestClient, regular_token: str
    ):
        result = gql(
            client,
            'mutation { createClient(name: "X") { id name } }',
            token=regular_token,
        )
        assert result["data"] is None
        assert any("Admin" in e["message"] for e in result["errors"])

    def test_create_with_admin(self, client: TestClient, admin_token: str):
        result = gql(
            client,
            """
            mutation {
                createClient(name: "Test Client", isConfidential: true) {
                    id
                    clientId
                    name
                    isConfidential
                    redirectUris
                }
            }
            """,
            token=admin_token,
        )
        assert result["data"] is not None
        c = result["data"]["createClient"]
        assert c["name"] == "Test Client"
        assert c["isConfidential"] is True
        assert c["redirectUris"] == []
        assert len(c["clientId"]) == 32

class TestAuditEventsQuery:
    def test_audit_without_token_fails(self, client: TestClient):
        result = gql(client, "{ auditEvents { id eventType } }")
        assert result["data"] is None

    def test_audit_events_admin(
        self, client: TestClient, admin_token: str, regular_user
    ):
        client.post(
            "/auth/login",
            json={
                "email": regular_user.email,
                "password": "Very strong user password",
            },
        )

        result = gql(
            client,
            "{ auditEvents(limit: 10) { id eventType actorId metadata } }",
            token=admin_token,
        )
        assert result["data"] is not None
        events = result["data"]["auditEvents"]
        assert any(e["eventType"] == "user.login.success" for e in events)