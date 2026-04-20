"""
JWT Authentication module — token creation and verification.
"""

from datetime import datetime, timedelta, timezone
from typing import Any

import structlog
from jose import JWTError, jwt
from passlib.context import CryptContext
import uuid

from app.config import get_settings

settings = get_settings()
logger = structlog.get_logger(__name__)

pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")


def hash_password(password: str) -> str:
    """Hash a plaintext password using argon2."""
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify plaintext password against argon2 hash (constant-time)."""
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(
    subject: str,
    extra_claims: dict[str, Any] | None = None,
    expires_minutes: int | None = None,
) -> str:
    """Create a JWT access token. expires_minutes overrides the global default."""
    now = datetime.now(timezone.utc)
    ttl = expires_minutes if expires_minutes is not None else settings.jwt_access_token_expire_minutes
    expire = now + timedelta(minutes=ttl)
    payload: dict[str, Any] = {
        "sub": subject,
        "iat": now,
        "exp": expire,
        "type": "access",
        "jti": str(uuid.uuid4()),
    }
    if extra_claims:
        payload.update(extra_claims)
    return jwt.encode(
        payload,
        settings.jwt_private_key,
        algorithm=settings.jwt_algorithm,
    )


def create_refresh_token(subject: str) -> str:
    """Create a long-lived JWT refresh token."""
    now = datetime.now(timezone.utc)
    expire = now + timedelta(days=settings.jwt_refresh_token_expire_days)
    payload = {
        "sub": subject,
        "iat": now,
        "exp": expire,
        "type": "refresh",
        "jti": str(uuid.uuid4()),
    }
    return jwt.encode(
        payload,
        settings.jwt_private_key,
        algorithm=settings.jwt_algorithm,
    )


def decode_token(token: str) -> dict[str, Any]:
    """
    Decode and validate a JWT token.
    Raises JWTError on invalid/expired tokens.
    Supports dual-verify for zero-downtime migration from HS256 to RS256.

    When jwt_dual_verify=True and an HS256 token is accepted, the payload
    is flagged with 'legacy_alg': 'HS256' so callers can deny elevated ops.
    When jwt_dual_verify=False (production default), HS256 tokens are rejected.
    """
    try:
        # Always try RS256 first
        return jwt.decode(
            token,
            settings.jwt_public_key,
            algorithms=["RS256"],
        )
    except JWTError as e:
        # Dual-verify: HS256 fallback for zero-downtime migration only
        if settings.jwt_dual_verify and settings.jwt_secret_key.get_secret_value():
            try:
                payload = jwt.decode(
                    token,
                    settings.jwt_secret_key.get_secret_value(),
                    algorithms=["HS256"],
                )
                # Flag as legacy — callers must not grant elevated privileges
                payload["legacy_alg"] = "HS256"
                logger.warning("Legacy HS256 token accepted via dual-verify", sub=payload.get("sub"))
                return payload
            except JWTError:
                pass
        raise e
