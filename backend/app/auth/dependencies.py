"""
FastAPI dependencies: extract and validate the current user from JWT token.
Expanded with 4-level RBAC: admin > auditor > dev > viewer.
"""

from datetime import datetime, timezone
from typing import Annotated, Optional

import structlog
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.jwt import decode_token
from app.models.database import get_db
from app.models.org import UserAccountRole
from app.models.user import User

logger = structlog.get_logger(__name__)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")

# Role ordering for hierarchy checks
_ROLE_RANK = {"viewer": 0, "dev": 1, "auditor": 2, "admin": 3}


def _require_role(minimum_role: str):
    """Factory that returns a FastAPI dependency enforcing a minimum role rank."""

    async def _inner(current_user: Annotated[User, Depends(get_current_user)]) -> User:
        if _ROLE_RANK.get(current_user.role, -1) < _ROLE_RANK[minimum_role]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires '{minimum_role}' role or higher. You have '{current_user.role}'.",
            )
        return current_user

    return _inner


async def get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> User:
    """Validate JWT and return the current authenticated user."""
    credentials_exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = decode_token(token)
        if payload.get("type") != "access":
            raise credentials_exc
        user_id: str = payload.get("sub", "")
        if not user_id:
            raise credentials_exc
    except JWTError:
        logger.warning("Invalid JWT token")
        raise credentials_exc

    user = await User.get_by_id(db, int(user_id))
    if user is None:
        raise credentials_exc
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is disabled",
        )
    return user


async def require_admin(current_user: Annotated[User, Depends(get_current_user)]) -> User:
    """Require admin role."""
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrator privileges required",
        )
    return current_user


async def get_user_account_role(
    user: User,
    account_id: int,
    db: AsyncSession,
) -> Optional[UserAccountRole]:
    """
    Fetch the user's active, non-expired role assignment for a specific cloud account.
    Returns None if no valid assignment exists (caller should raise 403).
    """
    assignment = await UserAccountRole.get_for_user_and_account(db, user.id, account_id)
    if assignment is None:
        return None
    # Enforce time-limited access
    if assignment.expires_at and datetime.now(timezone.utc) > assignment.expires_at:
        logger.warning(
            "Expired role assignment accessed",
            user_id=user.id,
            account_id=account_id,
            expired_at=assignment.expires_at.isoformat(),
        )
        return None
    return assignment


# ─── Convenience type aliases ─────────────────────────────────────────────────

CurrentUser = Annotated[User, Depends(get_current_user)]
AdminUser = Annotated[User, Depends(require_admin)]
AuditorUser = Annotated[User, Depends(_require_role("auditor"))]
DevUser = Annotated[User, Depends(_require_role("dev"))]
ViewerUser = Annotated[User, Depends(_require_role("viewer"))]  # any authenticated user
