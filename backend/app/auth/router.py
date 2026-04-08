"""
Auth router — login (two-step MFA), register, refresh, and all MFA endpoints.

Login flow (when MFA is enabled):
  1. POST /auth/login          →  { mfa_required: true, mfa_token: "<5-min JWT>" }
  2. POST /auth/mfa/verify     →  { access_token, refresh_token, ... }

Login flow (MFA not enrolled):
  1. POST /auth/login          →  { mfa_required: false, access_token, refresh_token }
"""

from datetime import datetime, timezone
from typing import Annotated

import structlog
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.jwt import (
    create_access_token,
    create_refresh_token,
    decode_token,
    verify_password,
)
from app.auth.totp import (
    generate_backup_codes,
    generate_secret,
    get_qr_png_b64,
    get_totp_uri,
    verify_backup_code,
    verify_totp,
)
from app.auth.dependencies import CurrentUser
from app.models.database import get_db
from app.models.user import User
from app.schemas.auth import (
    LoginResponse,
    MFAConfirmRequest,
    MFADisableRequest,
    MFAEnrolResponse,
    MFAVerifyRequest,
    RefreshRequest,
    TokenResponse,
    UserCreate,
    UserResponse,
)

router = APIRouter()
logger = structlog.get_logger(__name__)

# Short-lived token type used between step-1 and step-2 of MFA login
_MFA_TOKEN_TYPE = "mfa_pending"
_MFA_TOKEN_EXPIRY_MINUTES = 5


def _create_mfa_pending_token(user_id: int) -> str:
    """Create a short-lived JWT that authorises only the /mfa/verify endpoint."""
    return create_access_token(
        str(user_id),
        extra_claims={"type": _MFA_TOKEN_TYPE},
        expires_minutes=_MFA_TOKEN_EXPIRY_MINUTES,
    )


def _require_mfa_pending_token(raw_token: str) -> int:
    """Decode and validate an mfa_pending token. Returns user_id."""
    try:
        payload = decode_token(raw_token)
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid MFA token")
    if payload.get("type") != _MFA_TOKEN_TYPE:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid MFA token type")
    return int(payload["sub"])


def _full_token_response(user: User) -> TokenResponse:
    access = create_access_token(
        str(user.id),
        extra_claims={"role": user.role, "org_id": user.organization_id},
    )
    refresh = create_refresh_token(str(user.id))
    return TokenResponse(access_token=access, refresh_token=refresh, token_type="bearer")


# ---------------------------------------------------------------------------
# Standard login (step 1)
# ---------------------------------------------------------------------------

@router.post("/login", response_model=LoginResponse, summary="Authenticate (step 1 of 2 when MFA enabled)")
async def login(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> LoginResponse:
    """
    Authenticate with email + password.
    - If MFA not enrolled: returns full tokens immediately.
    - If MFA enrolled: returns a 5-minute mfa_token; caller must hit /mfa/verify.
    """
    user = await User.get_by_email(db, form_data.username)
    if not user or not verify_password(form_data.password, user.hashed_password):
        logger.warning("Failed login attempt", email=form_data.username)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account is disabled")

    # Stamp last_login for CIS 1.3 inactive-credential detection
    user.last_login_at = datetime.now(timezone.utc)
    await db.commit()

    if user.mfa_enabled and user.mfa_secret:
        # Step 1 complete — caller must verify TOTP next
        mfa_token = _create_mfa_pending_token(user.id)
        logger.info("MFA challenge issued", user_id=user.id)
        return LoginResponse(mfa_required=True, mfa_token=mfa_token)

    # No MFA — issue full tokens immediately
    tokens = _full_token_response(user)
    logger.info("User logged in (no MFA)", user_id=user.id, role=user.role)
    return LoginResponse(
        mfa_required=False,
        access_token=tokens.access_token,
        refresh_token=tokens.refresh_token,
    )


# ---------------------------------------------------------------------------
# MFA — step 2: verify TOTP / backup code
# ---------------------------------------------------------------------------

@router.post("/mfa/verify", response_model=TokenResponse, summary="Complete MFA login (step 2)")
async def mfa_verify(
    body: MFAVerifyRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> TokenResponse:
    """Exchange mfa_token + TOTP/backup code for full access + refresh tokens."""
    user_id = _require_mfa_pending_token(body.mfa_token)
    user = await User.get_by_id(db, user_id)
    if not user or not user.is_active or not user.mfa_enabled or not user.mfa_secret:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid MFA session")

    if body.use_backup:
        ok, remaining = verify_backup_code(body.code, user.mfa_backup_codes or [])
        if not ok:
            logger.warning("Failed backup code attempt", user_id=user.id)
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid backup code")
        user.mfa_backup_codes = remaining
        await db.commit()
        logger.info("Backup code consumed", user_id=user.id, remaining=len(remaining))
    else:
        if not verify_totp(user.mfa_secret, body.code):
            logger.warning("Failed TOTP attempt", user_id=user.id)
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired TOTP code")

    tokens = _full_token_response(user)
    logger.info("MFA verified, session issued", user_id=user.id)
    return tokens


# ---------------------------------------------------------------------------
# MFA — enrolment
# ---------------------------------------------------------------------------

@router.post("/mfa/enrol", response_model=MFAEnrolResponse, summary="Begin TOTP enrolment")
async def mfa_enrol(
    current_user: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> MFAEnrolResponse:
    """
    Generate a new TOTP secret + QR code for the authenticated user.
    MFA is NOT active until /mfa/confirm is called with the first valid code.
    """
    if current_user.mfa_enabled:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="MFA is already enabled")

    secret = generate_secret()
    uri = get_totp_uri(secret, current_user.email)
    qr = get_qr_png_b64(uri)
    plaintext_codes, hashed_codes = generate_backup_codes()

    # Store secret (not yet enabled — confirmed by /mfa/confirm)
    current_user.mfa_secret = secret
    current_user.mfa_backup_codes = hashed_codes
    await db.commit()

    logger.info("MFA enrolment initiated", user_id=current_user.id)
    return MFAEnrolResponse(qr_png_b64=qr, manual_secret=secret, backup_codes=plaintext_codes)


@router.post("/mfa/confirm", status_code=status.HTTP_204_NO_CONTENT, summary="Activate MFA after verifying first code")
async def mfa_confirm(
    body: MFAConfirmRequest,
    current_user: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> None:
    """Verify the first TOTP code to prove the user has scanned the QR correctly, then activate MFA."""
    if current_user.mfa_enabled:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="MFA already active")
    if not current_user.mfa_secret:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No pending enrolment — call /mfa/enrol first")
    if not verify_totp(current_user.mfa_secret, body.code):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid TOTP code — check your authenticator app clock")

    current_user.mfa_enabled = True
    current_user.mfa_enrolled_at = datetime.now(timezone.utc)
    await db.commit()
    logger.info("MFA activated", user_id=current_user.id)


@router.post("/mfa/disable", status_code=status.HTTP_204_NO_CONTENT, summary="Disable MFA (requires current TOTP)")
async def mfa_disable(
    body: MFADisableRequest,
    current_user: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> None:
    """Disable MFA on the authenticated account. Requires a valid current TOTP or backup code."""
    if not current_user.mfa_enabled:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="MFA is not enabled")

    if body.use_backup:
        ok, _ = verify_backup_code(body.code, current_user.mfa_backup_codes or [])
    else:
        ok = verify_totp(current_user.mfa_secret or "", body.code)

    if not ok:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid code — cannot disable MFA")

    current_user.mfa_enabled = False
    current_user.mfa_secret = None
    current_user.mfa_backup_codes = None
    current_user.mfa_enrolled_at = None
    await db.commit()
    logger.info("MFA disabled", user_id=current_user.id)


# ---------------------------------------------------------------------------
# Token refresh + /me
# ---------------------------------------------------------------------------

@router.post("/refresh", response_model=TokenResponse)
async def refresh_tokens(
    body: RefreshRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> TokenResponse:
    """Exchange a refresh token for new access + refresh tokens."""
    credentials_exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid refresh token",
    )
    try:
        payload = decode_token(body.refresh_token)
        if payload.get("type") != "refresh":
            raise credentials_exc
        user_id = payload.get("sub")
    except Exception:
        raise credentials_exc

    user = await User.get_by_id(db, int(user_id))
    if not user or not user.is_active:
        raise credentials_exc

    return _full_token_response(user)


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(
    user_in: UserCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> UserResponse:
    """Register a new user account."""
    existing = await User.get_by_email(db, user_in.email)
    if existing:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="An account with this email already exists")
    user = await User.create(db, user_in)
    logger.info("New user registered", user_id=user.id)
    return UserResponse.model_validate(user)


@router.get("/me", response_model=UserResponse)
async def get_me(current_user: CurrentUser) -> UserResponse:
    """Return the currently authenticated user's profile."""
    return UserResponse.model_validate(current_user)
