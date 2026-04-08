"""
Alembic migration 0003 — TOTP MFA columns.

Adds four columns to the `users` table:
  mfa_secret        TEXT NULL      -- base32 TOTP secret (application-level encrypted)
  mfa_enabled       BOOLEAN        -- True only after first successful TOTP verify
  mfa_backup_codes  JSONB NULL     -- list of argon2-hashed 8-char recovery codes
  mfa_enrolled_at   TIMESTAMPTZ NULL

Revision ID: 0003
Revises: 0002
Create Date: 2026-04-08
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.add_column("users", sa.Column("mfa_secret",       sa.Text(),                    nullable=True))
    op.add_column("users", sa.Column("mfa_enabled",      sa.Boolean(), server_default=sa.text("FALSE"), nullable=False))
    op.add_column("users", sa.Column("mfa_backup_codes", sa.JSON(),                    nullable=True))
    op.add_column("users", sa.Column("mfa_enrolled_at",  sa.DateTime(timezone=True),   nullable=True))

    # Index for fast "find users with MFA enabled" queries (e.g. admin audit)
    op.create_index("ix_users_mfa_enabled", "users", ["mfa_enabled"])


def downgrade() -> None:
    op.drop_index("ix_users_mfa_enabled", table_name="users")
    op.drop_column("users", "mfa_enrolled_at")
    op.drop_column("users", "mfa_backup_codes")
    op.drop_column("users", "mfa_enabled")
    op.drop_column("users", "mfa_secret")
