"""
Cryptographic utilities for evidence provenance and tamper-proofing.
Uses SHA-256 hash chains and HMAC signing.
"""

import hashlib
import hmac
import json
import os
import time
from typing import Any

from app.config import get_settings

settings = get_settings()


def sha256_hash(data: str | bytes) -> str:
    """Compute SHA-256 hash of data. Returns hex digest."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def compute_evidence_hash(evidence: dict[str, Any], previous_hash: str = "") -> str:
    """
    Compute a chained hash for an evidence record.
    Chains with previous_hash to create an immutable hash chain.
    """
    canonical = json.dumps(evidence, sort_keys=True, ensure_ascii=True)
    chain_input = previous_hash + canonical
    return sha256_hash(chain_input)


def sign_payload(payload: dict[str, Any]) -> str:
    """
    HMAC-SHA256 sign a payload using the app secret key.
    Returns hex signature.
    """
    secret = settings.app_secret_key.get_secret_value().encode("utf-8")
    message = json.dumps(payload, sort_keys=True, ensure_ascii=True).encode("utf-8")
    return hmac.new(secret, message, hashlib.sha256).hexdigest()


def verify_signature(payload: dict[str, Any], signature: str) -> bool:
    """Constant-time signature verification."""
    expected = sign_payload(payload)
    return hmac.compare_digest(expected, signature)


def generate_secure_token(nbytes: int = 32) -> str:
    """Generate a cryptographically secure random token."""
    return os.urandom(nbytes).hex()


def timestamp_now() -> int:
    """Return current Unix timestamp."""
    return int(time.time())
