from __future__ import annotations
from fastapi.testclient import TestClient
from jose import jwt, jwk

from app.core.security.jwt_rsa import sign_access_token


class TestJWKS:
    def test_jwks_returns_keys(self, client: TestClient):
        resp = client.get("/.well-known/jwks.json")
        assert resp.status_code == 200
        data = resp.json()
        assert "keys" in data
        assert len(data["keys"]) >= 1

        key = data["keys"][0]
        assert key["kty"] == "RSA"
        assert key["alg"] == "RS256"
        assert key["use"] == "sig"
        assert "kid" in key
        assert "n" in key
        assert "e" in key
        assert key["e"] == "AQAB"

    def test_jwks_key_verifies_token(self, client: TestClient):
        token = sign_access_token(
            sub=42,
            client_id="test-client",
            scopes=["openid", "email"],
        )

        jwks = client.get("/.well-known/jwks.json").json()
        header = jwt.get_unverified_header(token)
        key_data = next(k for k in jwks["keys"] if k["kid"] == header["kid"])
        public_key = jwk.construct(key_data, algorithm="RS256")

        payload = jwt.decode(
            token,
            public_key,
            algorithms=["RS256"],
            options={"verify_aud": False, "verify_iss": False},
        )
        assert payload["sub"] == "42"
        assert payload["aud"] == "test-client"
        assert "openid" in payload["scope"]


class TestDiscovery:
    def test_openid_configuration(self, client: TestClient):
        resp = client.get("/.well-known/openid-configuration")
        assert resp.status_code == 200
        data = resp.json()

        assert data["issuer"] == "http://127.0.0.1:8000"
        assert data["authorization_endpoint"].endswith("/oauth/authorize")
        assert data["token_endpoint"].endswith("/oauth/token")
        assert data["jwks_uri"].endswith("/.well-known/jwks.json")
        assert "authorization_code" in data["grant_types_supported"]
        assert "S256" in data["code_challenge_methods_supported"]
        assert data["id_token_signing_alg_values_supported"] == ["RS256"]