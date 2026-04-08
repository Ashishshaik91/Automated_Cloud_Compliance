"""multi_account_scoping_gaps

Closes the org-hierarchy scoping gaps identified in the Feature 3 audit:

  1. users.last_login_at (TIMESTAMPTZ NULL)
       Tracks when each user last authenticated. Required for CIS AWS 1.3
       (disable IAM credentials unused for ≥90 days).

  2. auditor_org_assignments.is_active (BOOLEAN DEFAULT TRUE NOT NULL)
       Enables soft-revoke of auditor grants without deleting the audit trail.
       get_org_scope() filters WHERE is_active = TRUE.

  3. auditor_org_assignments.expires_at (TIMESTAMPTZ NULL)
       Time-limited auditor grants. NULL means permanent.
       get_org_scope() filters WHERE expires_at IS NULL OR expires_at > NOW().

Rollback:
  Removes all three columns in reverse order.

Revision ID: 0002
Revises: 0001
Create Date: 2026-04-08
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    # 1. users.last_login_at
    op.add_column(
        "users",
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
    )

    # 2. auditor_org_assignments.is_active
    op.add_column(
        "auditor_org_assignments",
        sa.Column(
            "is_active",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("TRUE"),
        ),
    )

    # 3. auditor_org_assignments.expires_at
    op.add_column(
        "auditor_org_assignments",
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
    )

    # Index on is_active so get_org_scope() filter is fast
    op.create_index(
        "ix_auditor_org_assignments_is_active",
        "auditor_org_assignments",
        ["is_active"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_auditor_org_assignments_is_active", table_name="auditor_org_assignments")
    op.drop_column("auditor_org_assignments", "expires_at")
    op.drop_column("auditor_org_assignments", "is_active")
    op.drop_column("users", "last_login_at")
