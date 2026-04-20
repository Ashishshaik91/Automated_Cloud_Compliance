"""
Invites API for admin-issued registration tokens.
"""
import uuid
from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from app.auth.dependencies import AdminUser
from app.models.database import get_db
from app.models.invite import InviteToken
from pydantic import BaseModel, EmailStr

router = APIRouter()

class InviteCreate(BaseModel):
    email: EmailStr
    expires_in_hours: int = 48

class InviteResponse(BaseModel):
    id: int
    token: str
    email: str
    expires_at: datetime
    used: bool

    class Config:
        from_attributes = True

@router.post("", response_model=InviteResponse, status_code=status.HTTP_201_CREATED)
async def create_invite(
    invite_in: InviteCreate,
    current_user: AdminUser,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Admin creates a one-time registration invite token."""
    token_str = str(uuid.uuid4())
    expires_at = datetime.now(timezone.utc) + timedelta(hours=invite_in.expires_in_hours)
    
    invite = InviteToken(
        token=token_str,
        email=invite_in.email,
        expires_at=expires_at,
        created_by_id=current_user.id
    )
    db.add(invite)
    await db.commit()
    await db.refresh(invite)
    
    return invite

@router.get("", response_model=list[InviteResponse])
async def list_invites(
    current_user: AdminUser,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """List all invite tokens."""
    result = await db.execute(select(InviteToken).order_by(InviteToken.created_at.desc()))
    return result.scalars().all()
