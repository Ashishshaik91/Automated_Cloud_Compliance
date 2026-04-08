"""
Pydantic schemas for Auth endpoints.
"""

from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, EmailStr, Field, field_validator

RoleType = Literal["admin", "auditor", "dev", "viewer"]


class UserCreate(BaseModel):
    email: EmailStr
    full_name: str = Field(..., min_length=2, max_length=255)
    password: str = Field(..., min_length=12, max_length=72)

    @field_validator("password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        """Enforce minimum password complexity."""
        if not any(c.isupper() for c in v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not any(c.islower() for c in v):
            raise ValueError("Password must contain at least one lowercase letter")
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain at least one digit")
        if not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in v):
            raise ValueError("Password must contain at least one special character")
        return v


class UserResponse(BaseModel):
    model_config = {"from_attributes": True}

    id: int
    email: str
    full_name: str
    role: str
    is_active: bool
    organization_id: Optional[int] = None
    created_at: datetime
    account_roles: list = []  # List[AccountRoleSchema] populated by endpoint


class AdminUserCreate(BaseModel):
    """Admin-only schema to create a user with an explicit role and org assignment."""

    email: EmailStr
    full_name: str = Field(..., min_length=2, max_length=255)
    password: str = Field(..., min_length=12, max_length=72)
    role: RoleType = "dev"
    organization_id: Optional[int] = None

    @field_validator("password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        if not any(c.isupper() for c in v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not any(c.islower() for c in v):
            raise ValueError("Password must contain at least one lowercase letter")
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain at least one digit")
        if not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in v):
            raise ValueError("Password must contain at least one special character")
        return v


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class RefreshRequest(BaseModel):
    refresh_token: str


# ---------------------------------------------------------------------------
# MFA schemas
# ---------------------------------------------------------------------------

class LoginResponse(BaseModel):
    """
    Returned by POST /auth/login.
    If mfa_required=True the caller must POST to /auth/mfa/verify with the
    mfa_token (5-min, type=mfa_pending) and a 6-digit TOTP code.
    If mfa_required=False a full TokenResponse is embedded directly.
    """
    mfa_required: bool
    # Present only when mfa_required=False
    access_token: Optional[str] = None
    refresh_token: Optional[str] = None
    token_type: str = "bearer"
    # Present only when mfa_required=True
    mfa_token: Optional[str] = None


class MFAVerifyRequest(BaseModel):
    """Exchange mfa_token + TOTP code (or backup code) for full session tokens."""
    mfa_token: str
    code: str = Field(..., min_length=6, max_length=8, description="6-digit TOTP or 8-char backup code")
    use_backup: bool = False


class MFAEnrolResponse(BaseModel):
    """Returned by POST /auth/mfa/enrol — show QR once, never again."""
    qr_png_b64: str          # base64 PNG, embed as <img src="data:image/png;base64,...">
    manual_secret: str       # show alongside QR for manual entry
    backup_codes: list[str]  # plaintext — user must save these


class MFAConfirmRequest(BaseModel):
    """POST /auth/mfa/confirm — verify the first code to activate MFA."""
    code: str = Field(..., min_length=6, max_length=6)


class MFADisableRequest(BaseModel):
    """POST /auth/mfa/disable — requires current TOTP to prove possession."""
    code: str = Field(..., min_length=6, max_length=8)
    use_backup: bool = False
