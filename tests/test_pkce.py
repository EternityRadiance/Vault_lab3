import pytest

from app.core.security.pkce import compute_challenge, verify_pkce

RFC_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
RFC_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

class TestComputeChallenge:
    def test_s256_matches_rfc(self):
        assert compute_challenge(RFC_VERIFIER, "S256") == RFC_CHALLENGE

    def test_plain_returns_verifier(self):
        assert compute_challenge("abc123", "plain") == "abc123"

    def test_unknown_method(self):
        with pytest.raises(ValueError):
            compute_challenge("abc", "MD5")

class TestVerifyPkce:
    def test_valid(self):
        assert verify_pkce(RFC_VERIFIER, RFC_CHALLENGE, "S256") is True

    def test_wrong_verifier(self):
        assert verify_pkce("x" * 43, RFC_CHALLENGE, "S256") is False

    def test_wrong_challenge(self):
        assert verify_pkce(RFC_VERIFIER, "wrong" * 10, "S256") is False

    def test_too_short(self):
        assert verify_pkce("short", RFC_CHALLENGE, "S256") is False

    def test_too_long(self):
        assert verify_pkce("x" * 200, RFC_CHALLENGE, "S256") is False

    def test_missing_verifier(self):
        assert verify_pkce(None, RFC_CHALLENGE, "S256") is False

    def test_missing_challenge(self):
        assert verify_pkce(RFC_VERIFIER, None, "S256") is False

    def test_plain_method(self):
        verifier = "a" * 43
        assert verify_pkce(verifier, verifier, "plain") is True