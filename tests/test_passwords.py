from __future__ import annotations
import pytest

from app.core.passwords import (
    WeakPasswordError,
    hash_password,
    validate_policy,
    verify_password,
)

class TestHashPassword:
    def test_hash_argon2id(self):
        h = hash_password("Idk what am I doing here.")
        assert isinstance(h, str)
        assert h.startswith("$argon2id$")
        assert "m=65536,t=3,p=4" in h

    def test_hash_same_password(self):
        h1 = hash_password("Same password in a row.")
        h2 = hash_password("Same password in a row.")
        assert h1 != h2

    def test_hash_empty_password(self):
        with pytest.raises(WeakPasswordError):
            hash_password("")

    def test_hash_non_string(self):
        with pytest.raises(WeakPasswordError):
            hash_password(None)

class TestVerifyPassword:
    def test_correct(self):
        h = hash_password("Some random long string")
        assert verify_password("Some random long string", h) is True

    def test_wrong(self):
        h = hash_password("Some random long string")
        assert verify_password("I want some pizza", h) is False

    def test_empty_password(self):
        h = hash_password("Some random long string")
        assert verify_password("", h) is False

    def test_empty_hash(self):
        assert verify_password("Some random long string", "") is False

    def test_invalid_hash(self):
        assert verify_password("Some random password", "not-a-virus-xd") is False

    def test_repeatedly(self):
        h = hash_password("Some random long string")
        for _ in range(3):
            assert verify_password("Some random long string", h) is True

class TestValidatePolicy:
    def test_strong_passphrase(self):
        validate_policy("Some random long long string")
        validate_policy("Xy7#kL9$mN2@pQ8")

    def test_short_password(self):
        with pytest.raises(WeakPasswordError, match="короче"):
            validate_policy("short")

    def test_common_password(self):
        with pytest.raises(WeakPasswordError, match="Слишком слабый"):
            validate_policy("password1234")

    def test_repeated_password(self):
        with pytest.raises(WeakPasswordError, match="Слишком слабый"):
            validate_policy("aaaaaaaaaaaaaaa")

    def test_email_password(self):
        with pytest.raises(WeakPasswordError):
            validate_policy("test@example.com", user_inputs=["test@example.com"])

    def test_empty_password(self):
        with pytest.raises(WeakPasswordError):
            validate_policy("")

    def test_non_string_password(self):
        with pytest.raises(WeakPasswordError):
            validate_policy(None)
