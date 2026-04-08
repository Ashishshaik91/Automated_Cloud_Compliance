"""
Alembic migration 0004 — Compliance Score Engine tables.

Creates:
  score_snapshots     — daily org-level score history
  account_score_cache — latest per-account per-framework score (fast read)

Revision ID: 0004
Revises: 0003
Create Date: 2026-04-08
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.create_table(
        "score_snapshots",
        sa.Column("id",            sa.Integer(),             primary_key=True),
        sa.Column("org_id",        sa.Integer(),             sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("snapshot_date", sa.Date(),                nullable=False),
        sa.Column("overall_score", sa.Float(),               nullable=False),
        sa.Column("grade",         sa.String(1),             nullable=False),
        sa.Column("by_framework",  sa.JSON(),                nullable=True),
        sa.Column("account_count", sa.Integer(),             server_default=sa.text("0")),
        sa.Column("critical_fails",sa.Integer(),             server_default=sa.text("0")),
        sa.Column("dspm_risk_avg", sa.Float(),               server_default=sa.text("0")),
        sa.Column("created_at",    sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.UniqueConstraint("org_id", "snapshot_date", name="uq_score_snapshot_org_date"),
    )
    op.create_index("ix_score_snapshots_org_date", "score_snapshots", ["org_id", "snapshot_date"])

    op.create_table(
        "account_score_cache",
        sa.Column("id",            sa.Integer(),             primary_key=True),
        sa.Column("account_id",    sa.Integer(),             sa.ForeignKey("cloud_accounts.id", ondelete="CASCADE"), nullable=False),
        sa.Column("framework",     sa.String(100),           nullable=False),
        sa.Column("score",         sa.Float(),               nullable=False),
        sa.Column("grade",         sa.String(1),             nullable=False),
        sa.Column("critical_fails",sa.Integer(),             server_default=sa.text("0")),
        sa.Column("high_fails",    sa.Integer(),             server_default=sa.text("0")),
        sa.Column("last_computed", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.UniqueConstraint("account_id", "framework", name="uq_account_score_cache_fw"),
    )
    op.create_index("ix_account_score_cache_account", "account_score_cache", ["account_id"])


def downgrade() -> None:
    op.drop_index("ix_account_score_cache_account", "account_score_cache")
    op.drop_table("account_score_cache")
    op.drop_index("ix_score_snapshots_org_date", "score_snapshots")
    op.drop_table("score_snapshots")
