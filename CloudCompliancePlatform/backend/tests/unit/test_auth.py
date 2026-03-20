"""
Unit tests for JWT auth module.
Covers hash_password, verify_password, create_access_token,
create_refresh_token, decode_token.
"""
import pytest
from jose import JWTError

from app.auth.jwt import (
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    verify_password,
)


def test_hash_password_returns_hash():
    hashed = hash_password("mysecret")
    assert hashed != "mysecret"
    assert len(hashed) > 10


def test_verify_password_correct():
    hashed = hash_password("correct_password")
    assert verify_password("correct_password", hashed) is True


def test_verify_password_wrong():
    hashed = hash_password("correct_password")
    assert verify_password("wrong_password", hashed) is False


def test_create_access_token_decodes():
    token = create_access_token("user@example.com")
    decoded = decode_token(token)
    assert decoded["sub"] == "user@example.com"
    assert decoded["type"] == "access"


def test_create_access_token_with_extra_claims():
    token = create_access_token("user@example.com", extra_claims={"role": "admin"})
    decoded = decode_token(token)
    assert decoded["role"] == "admin"


def test_create_refresh_token_decodes():
    token = create_refresh_token("user@example.com")
    decoded = decode_token(token)
    assert decoded["sub"] == "user@example.com"
    assert decoded["type"] == "refresh"


def test_decode_invalid_token_raises():
    with pytest.raises(JWTError):
        decode_token("not.a.valid.jwt.token")


def test_decode_tampered_token_raises():
    token = create_access_token("user@example.com")
    tampered = token[:-5] + "XXXXX"
    with pytest.raises(JWTError):
        decode_token(tampered)
