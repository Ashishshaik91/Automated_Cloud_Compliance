"""
Pydantic schemas for Organization and UserAccountRole endpoints.
"""

from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, Field


# ─── Organization ──────────────────────────────────────────────────────────────

class OrgCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=255)
    parent_org_id: Optional[int] = None


class OrgResponse(BaseModel):
    model_config = {"from_attributes": True}

    id: int
    name: str
    parent_org_id: Optional[int]
    created_at: datetime


# ─── UserAccountRole ──────────────────────────────────────────────────────────

RoleType = Literal["admin", "auditor", "dev", "viewer"]


class UserAccountRoleCreate(BaseModel):
    user_id: int
    cloud_account_id: int
    role: RoleType
    expires_at: Optional[datetime] = Field(
        None,
        description="Leave null for a permanent grant. Set to a future UTC datetime for time-limited access.",
    )


class UserAccountRoleResponse(BaseModel):
    model_config = {"from_attributes": True}

    id: int
    user_id: int
    cloud_account_id: int
    role: str
    is_active: bool
    expires_at: Optional[datetime]
    granted_by: Optional[int]
    granted_at: datetime

    # Computed — populated by the API layer
    is_expired: bool = False
    granted_by_email: Optional[str] = None


# ─── Account role summary (embedded in UserResponse) ─────────────────────────

class AccountRoleSchema(BaseModel):
    model_config = {"from_attributes": True}

    cloud_account_id: int
    role: str
    expires_at: Optional[datetime]
    is_expired: bool = False
