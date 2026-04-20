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
import secrets
import time

import structlog
from fastapi import APIRouter, Depends, HTTPException, status, Request, Response, Query
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

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
from app.models.invite import InviteToken
from app.core.redis import get_redis
import redis.asyncio as aioredis
from slowapi import Limiter
from slowapi.util import get_remote_address

router = APIRouter()
logger = structlog.get_logger(__name__)
limiter = Limiter(key_func=get_remote_address)

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


def _set_tokens_in_cookie(response: Response, user: User) -> None:
    access = create_access_token(
        str(user.id),
        extra_claims={"role": user.role, "org_id": user.organization_id},
    )
    refresh = create_refresh_token(str(user.id))
    
    response.set_cookie(
        key="access_token",
        value=access,
        httponly=True,
        secure=True,
        samesite="strict",
        max_age=900,
        path="/"
    )
    response.set_cookie(
        key="refresh_token",
        value=refresh,
        httponly=True,
        secure=True,
        samesite="strict",
        max_age=86400 * 7,
        path="/api/v1/auth/refresh"
    )

# ---------------------------------------------------------------------------
# Standard login (step 1)
# ---------------------------------------------------------------------------

@router.post("/login", response_model=LoginResponse, summary="Authenticate (step 1 of 2 when MFA enabled)")
@limiter.limit("5/minute")
@limiter.limit("20/hour")
async def login(
    request: Request,
    response: Response,
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: Annotated[AsyncSession, Depends(get_db)],
    redis_client: aioredis.Redis = Depends(get_redis),
) -> LoginResponse:
    """
    Authenticate with email + password.
    - If MFA not enrolled: returns success immediately (tokens in cookie).
    - If MFA enrolled: returns a 5-minute mfa_token; caller must hit /mfa/verify.
    Account is locked for 15 minutes after 10 consecutive failures.
    """
    email_key = f"login_attempts:{form_data.username.lower()}"
    lockout_key = f"login_locked:{form_data.username.lower()}"

    # Check lockout
    if await redis_client.exists(lockout_key):
        ttl = await redis_client.ttl(lockout_key)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Account temporarily locked. Try again in {ttl} seconds.",
        )

    user = await User.get_by_email(db, form_data.username)
    if not user or not verify_password(form_data.password, user.hashed_password):
        # Increment failure counter
        attempts = await redis_client.incr(email_key)
        if attempts == 1:
            await redis_client.expire(email_key, 900)  # 15-min window
        if attempts >= 10:
            await redis_client.setex(lockout_key, 900, "1")  # 15-min lockout
            await redis_client.delete(email_key)
            logger.warning("Account locked after 10 failures", email=form_data.username)
        else:
            logger.warning("Failed login attempt", email=form_data.username, attempts=attempts)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account is disabled")

    # Clear failure counter on success
    await redis_client.delete(email_key)

    # Stamp last_login for CIS 1.3 inactive-credential detection
    user.last_login_at = datetime.now(timezone.utc)
    await db.commit()

    if user.mfa_enabled and user.mfa_secret:
        # Step 1 complete — caller must verify TOTP next
        mfa_token = _create_mfa_pending_token(user.id)
        logger.info("MFA challenge issued", user_id=user.id)
        return LoginResponse(mfa_required=True, mfa_token=mfa_token)

    # No MFA — issue full tokens immediately in cookies
    _set_tokens_in_cookie(response, user)
    logger.info("User logged in (no MFA)", user_id=user.id, role=user.role)
    return LoginResponse(
        mfa_required=False,
        access_token="cookie-based",
        refresh_token="cookie-based",
    )

# ---------------------------------------------------------------------------
# MFA — step 2: verify TOTP / backup code
# ---------------------------------------------------------------------------

@router.post("/mfa/verify", response_model=LoginResponse, summary="Complete MFA login (step 2)")
async def mfa_verify(
    request: Request,
    response: Response,
    body: MFAVerifyRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> LoginResponse:
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

    _set_tokens_in_cookie(response, user)
    logger.info("MFA verified, session issued", user_id=user.id)
    return LoginResponse(
        mfa_required=False,
        access_token="cookie-based",
        refresh_token="cookie-based"
    )


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
# Token refresh, logout, ticket + /me
# ---------------------------------------------------------------------------

@router.post("/logout", summary="Logout and invalidate token")
async def logout(
    request: Request,
    response: Response,
    current_user: CurrentUser,
    redis_client: aioredis.Redis = Depends(get_redis)
):
    """Logout and add BOTH access and refresh token JTIs to Redis denylist."""
    # Revoke access token
    access_token = request.cookies.get("access_token")
    if access_token:
        try:
            payload = decode_token(access_token)
            jti = payload.get("jti")
            if jti:
                ttl = int(payload.get("exp", time.time())) - int(time.time())
                if ttl > 0:
                    await redis_client.setex(f"revoked_token:{jti}", ttl, "1")
        except Exception:
            pass

    # Revoke refresh token
    refresh_token = request.cookies.get("refresh_token")
    if refresh_token:
        try:
            payload = decode_token(refresh_token)
            jti = payload.get("jti")
            if jti:
                # Refresh tokens have longer TTL — use remaining exp time
                ttl = int(payload.get("exp", time.time())) - int(time.time())
                if ttl > 0:
                    await redis_client.setex(f"revoked_token:{jti}", ttl, "1")
        except Exception:
            pass

    response.delete_cookie("access_token", path="/")
    response.delete_cookie("refresh_token", path="/api/v1/auth/refresh")
    return {"message": "logged out"}


@router.get("/me", response_model=UserResponse, summary="Get current authenticated user")
async def get_me(current_user: CurrentUser) -> UserResponse:
    """Return the profile of the currently authenticated user (reads HttpOnly cookie)."""
    return UserResponse(
        id=current_user.id,
        email=current_user.email,
        full_name=current_user.full_name,
        role=current_user.role,
        is_active=current_user.is_active,
        mfa_enabled=current_user.mfa_enabled,
        organization_id=current_user.organization_id,
        created_at=current_user.created_at,
    )


@router.post("/ws-ticket", summary="Get short-lived WebSocket ticket")
async def get_ws_ticket(
    current_user: CurrentUser, 
    redis_client: aioredis.Redis = Depends(get_redis)
):
    ticket = secrets.token_urlsafe(32)
    # Store ticket -> user_id mapping, expires in 60 seconds
    await redis_client.setex(f"ws_ticket:{ticket}", 60, str(current_user.id))
    return {"ticket": ticket}


@router.post("/refresh", response_model=LoginResponse)
async def refresh_tokens(
    request: Request,
    response: Response,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> LoginResponse:
    """Exchange a refresh token for new access + refresh tokens."""
    credentials_exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid refresh token",
    )
    refresh_token = request.cookies.get("refresh_token")
    if not refresh_token:
        raise credentials_exc

    try:
        payload = decode_token(refresh_token)
        if payload.get("type") != "refresh":
            raise credentials_exc
        user_id = payload.get("sub")
    except Exception:
        raise credentials_exc

    user = await User.get_by_id(db, int(user_id))
    if not user or not user.is_active:
        raise credentials_exc

    _set_tokens_in_cookie(response, user)
    return LoginResponse(
        mfa_required=False,
        access_token="cookie-based",
        refresh_token="cookie-based"
    )


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(
    user_in: UserCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
    invite_token: str = Query(..., description="Admin-issued invite token"),
) -> UserResponse:
    """Register a new user account using an invite token."""
    # 1. Validate Invite Token
    result = await db.execute(select(InviteToken).filter_by(token=invite_token, used=False))
    invite = result.scalar_one_or_none()
    
    if not invite:
        raise HTTPException(status_code=400, detail="Invalid or expired invite token")
        
    # Handle both naive and aware datetimes based on the DB return
    if invite.expires_at.tzinfo is None:
        now = datetime.utcnow()
    else:
        now = datetime.now(timezone.utc)
        
    if invite.expires_at < now:
        raise HTTPException(status_code=400, detail="Invalid or expired invite token")
    
    # 2. Check existing user
    existing = await User.get_by_email(db, user_in.email)
    if existing:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="An account with this email already exists")
        
    # 3. Create User
    user = await User.create(db, user_in)
    
    # 4. Consume Invite
    invite.used = True
    await db.commit()
    
    logger.info("New user registered", user_id=user.id, invite_token=invite_token)
    return UserResponse.model_validate(user)


# NOTE: /me GET is defined at line 304. The duplicate below was removed.
