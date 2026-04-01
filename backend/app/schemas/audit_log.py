"""
Pydantic schema for AuditLog read responses.
"""

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel


class AuditLogResponse(BaseModel):
    model_config = {"from_attributes": True}

    id: int
    user_id: Optional[int]
    user_email: str
    action: str
    resource_type: Optional[str]
    resource_id: Optional[str]
    detail: Optional[Any]
    ip_address: Optional[str]
    timestamp: datetime
