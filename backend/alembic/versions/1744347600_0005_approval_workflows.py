"""
Alembic migration 0005 — Approval Workflow table.

Creates:
  approval_requests — change-management gating for high-risk platform actions

Revision ID: 0005
Revises: 0004
Create Date: 2026-04-08
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.create_table(
        "approval_requests",
        sa.Column("id",               sa.String(36),              primary_key=True),
        sa.Column("title",             sa.String(500),             nullable=False),
        sa.Column("description",       sa.Text(),                  nullable=True),
        sa.Column("action_type",       sa.String(100),             nullable=False),
        sa.Column("action_payload",    sa.JSON(),                  nullable=True),
        sa.Column("status",            sa.String(50),              nullable=False, server_default="pending"),
        sa.Column("risk_level",        sa.String(20),              nullable=False),
        sa.Column("org_id",            sa.Integer(),               sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("requester_id",      sa.Integer(),               sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=False),
        sa.Column("approver_id",       sa.Integer(),               sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("requested_at",      sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("expires_at",        sa.DateTime(timezone=True), nullable=True),
        sa.Column("reviewed_at",       sa.DateTime(timezone=True), nullable=True),
        sa.Column("notes",             sa.Text(),                  nullable=True),
        sa.Column("execution_result",  sa.JSON(),                  nullable=True),
    )
    op.create_index("ix_approval_requests_status", "approval_requests", ["status"])
    op.create_index("ix_approval_requests_org",    "approval_requests", ["org_id"])
    op.create_index("ix_approval_requests_expires", "approval_requests", ["expires_at"])


def downgrade() -> None:
    op.drop_index("ix_approval_requests_expires", "approval_requests")
    op.drop_index("ix_approval_requests_org",     "approval_requests")
    op.drop_index("ix_approval_requests_status",  "approval_requests")
    op.drop_table("approval_requests")
