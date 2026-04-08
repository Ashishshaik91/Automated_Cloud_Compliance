"""
TOTP (Time-based One-Time Password) helpers — RFC 6238 via pyotp.

Public API:
  generate_secret()                    → base32 secret string
  get_totp_uri(secret, email, issuer)  → otpauth:// URI for QR
  get_qr_png_b64(uri)                  → base64-encoded PNG (for JSON transport)
  verify_totp(secret, code)            → bool (±1 window = 90s tolerance)
  generate_backup_codes()              → list[str] (8 × 8-char uppercase)
  hash_backup_code(code)               → bcrypt hash string
  verify_backup_code(code, hashes)     → (bool, remaining_hashes)
"""

from __future__ import annotations

import base64
import io
import os
import secrets
import string

import pyotp
import qrcode
import structlog
from passlib.context import CryptContext

logger = structlog.get_logger(__name__)

# Use argon2 for backup codes (same context as passwords)
_backup_ctx = CryptContext(schemes=["argon2"], deprecated="auto")

TOTP_ISSUER = "CloudCompliancePlatform"
BACKUP_CODE_LEN = 8
BACKUP_CODE_COUNT = 8
BACKUP_CODE_ALPHABET = string.ascii_uppercase + string.digits


# ---------------------------------------------------------------------------
# Secret generation
# ---------------------------------------------------------------------------

def generate_secret() -> str:
    """Generate a cryptographically random base32 TOTP secret (20 bytes → 32 chars)."""
    return pyotp.random_base32()


# ---------------------------------------------------------------------------
# URI + QR code
# ---------------------------------------------------------------------------

def get_totp_uri(secret: str, email: str, issuer: str = TOTP_ISSUER) -> str:
    """Return the otpauth:// URI for provisioning an authenticator app."""
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=email, issuer_name=issuer)


def get_qr_png_b64(uri: str) -> str:
    """
    Generate a QR code PNG for the given otpauth URI.
    Returns a base64-encoded string suitable for embedding in JSON.
    """
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode()


# ---------------------------------------------------------------------------
# TOTP verification
# ---------------------------------------------------------------------------

def verify_totp(secret: str, code: str) -> bool:
    """
    Verify a 6-digit TOTP code against the given secret.

    Uses a ±1 window (valid_window=1) which allows codes from the previous
    and next 30-second interval (90 seconds total tolerance).
    Returns False on any error (wrong secret format, etc.).
    """
    try:
        totp = pyotp.TOTP(secret)
        return totp.verify(code.strip(), valid_window=1)
    except Exception as e:
        logger.warning("TOTP verification error", error=str(e))
        return False


# ---------------------------------------------------------------------------
# Backup codes
# ---------------------------------------------------------------------------

def generate_backup_codes() -> tuple[list[str], list[str]]:
    """
    Generate BACKUP_CODE_COUNT one-time backup codes.

    Returns:
        plaintext_codes: list[str]  — show to user ONCE, never stored
        hashed_codes:    list[str]  — store these in the DB
    """
    plaintext: list[str] = []
    hashed: list[str] = []
    for _ in range(BACKUP_CODE_COUNT):
        code = "".join(secrets.choice(BACKUP_CODE_ALPHABET) for _ in range(BACKUP_CODE_LEN))
        plaintext.append(code)
        hashed.append(_backup_ctx.hash(code))
    return plaintext, hashed


def verify_backup_code(
    submitted: str,
    hashed_codes: list[str],
) -> tuple[bool, list[str]]:
    """
    Attempt to consume a backup code.

    Returns:
        (True, remaining_hashes)   — on success (consumed code removed)
        (False, original_hashes)   — on failure
    """
    submitted = submitted.strip().upper()
    for i, hashed in enumerate(hashed_codes):
        try:
            if _backup_ctx.verify(submitted, hashed):
                remaining = hashed_codes[:i] + hashed_codes[i + 1:]
                return True, remaining
        except Exception:
            continue
    return False, hashed_codes
