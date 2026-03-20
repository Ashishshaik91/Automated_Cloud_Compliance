"""
Unit tests for cryptographic utilities.
"""

import pytest

from app.utils.crypto import (
    compute_evidence_hash,
    generate_secure_token,
    sha256_hash,
    sign_payload,
    verify_signature,
)


class TestCrypto:
    def test_sha256_hash_string(self) -> None:
        h = sha256_hash("hello world")
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)

    def test_sha256_hash_bytes(self) -> None:
        h1 = sha256_hash("test")
        h2 = sha256_hash(b"test")
        assert h1 == h2

    def test_sha256_deterministic(self) -> None:
        assert sha256_hash("abc") == sha256_hash("abc")
        assert sha256_hash("abc") != sha256_hash("def")

    def test_evidence_hash_chain(self) -> None:
        record1 = {"check_id": 1, "status": "fail"}
        record2 = {"check_id": 2, "status": "pass"}
        hash1 = compute_evidence_hash(record1, "genesis")
        hash2 = compute_evidence_hash(record2, hash1)
        # Chain: each hash depends on previous
        assert hash1 != hash2
        assert compute_evidence_hash(record1, "genesis") == hash1  # deterministic

    def test_generate_secure_token(self) -> None:
        t1 = generate_secure_token()
        t2 = generate_secure_token()
        assert len(t1) == 64  # 32 bytes → 64 hex chars
        assert t1 != t2  # Should be unique

    def test_sign_and_verify(self, monkeypatch) -> None:
        """Test HMAC signature round-trip."""
        from unittest.mock import MagicMock
        mock_settings = MagicMock()
        mock_settings.app_secret_key.get_secret_value.return_value = "test-secret-key-32chars-minimum!"
        monkeypatch.setattr("app.utils.crypto.settings", mock_settings)

        payload = {"check_id": 1, "hash": "abc123"}
        sig = sign_payload(payload)
        assert verify_signature(payload, sig) is True
        assert verify_signature({"check_id": 2, "hash": "abc123"}, sig) is False
