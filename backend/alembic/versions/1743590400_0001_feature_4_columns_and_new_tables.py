"""feature_4_columns_and_new_tables

Adds all columns and tables introduced by the four feature completions:

Feature 1 — Terraform State Ingestion:
  (no new DB schema; state is parsed from file/remote at runtime)

Feature 2 — Remediation Runbooks:
  (no new DB schema; runbooks are YAML files read at runtime)

Feature 3 — Multi-Account Org Isolation:
  + organizations.remediation_dry_run   (BOOLEAN, default TRUE)
  + auditor_org_assignments             (new table)
  + cloud_accounts.organization_id      (INTEGER FK → organisations, nullable)
    — backfill: NULL for existing rows (no assumed org)

Feature 4 — Threat Intel Risk Enrichment:
  + dspm_findings.cloud_account_id       (INTEGER FK → cloud_accounts, nullable)
  + dspm_findings.cve_ids                (JSON)
  + dspm_findings.cvss_max               (FLOAT)
  + dspm_findings.vt_reputation          (FLOAT)
  + dspm_findings.threat_intel_boost     (FLOAT)
  + dspm_findings.threat_intel_enriched_at (TIMESTAMP WITH TIME ZONE)
  + violations.cve_ids                   (JSON)
  + violations.cvss_max                  (FLOAT)

Rollback:
  Removes all of the above additions in reverse order.

Revision ID: 0001
Revises: (initial)
Create Date: 2026-04-02
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic
revision: str = "0001"
down_revision: str | None = None
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    # ── Feature 3: organizations ──────────────────────────────────────────────

    # Add remediation_dry_run flag (safe default: True = dry-run only)
    op.add_column(
        "organizations",
        sa.Column(
            "remediation_dry_run",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("TRUE"),
        ),
    )

    # ── Feature 3: cloud_accounts — add organization_id FK ───────────────────
    # Nullable so existing rows are unaffected; constraint enforced by app layer.
    op.add_column(
        "cloud_accounts",
        sa.Column(
            "organization_id",
            sa.Integer(),
            sa.ForeignKey("organizations.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    op.create_index(
        "ix_cloud_accounts_organization_id",
        "cloud_accounts",
        ["organization_id"],
        unique=False,
    )

    # ── Feature 3: auditor_org_assignments (new table) ────────────────────────
    op.create_table(
        "auditor_org_assignments",
        sa.Column("id", sa.Integer(), primary_key=True, index=True),
        sa.Column(
            "auditor_user_id",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column(
            "organization_id",
            sa.Integer(),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column(
            "granted_by",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "granted_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("NOW()"),
            nullable=False,
        ),
        sa.UniqueConstraint(
            "auditor_user_id", "organization_id", name="uq_auditor_org"
        ),
    )

    # ── Feature 4: dspm_findings — org FK ────────────────────────────────────
    op.add_column(
        "dspm_findings",
        sa.Column(
            "cloud_account_id",
            sa.Integer(),
            sa.ForeignKey("cloud_accounts.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    op.create_index(
        "ix_dspm_findings_cloud_account_id",
        "dspm_findings",
        ["cloud_account_id"],
        unique=False,
    )

    # ── Feature 4: dspm_findings — threat intel columns ──────────────────────
    op.add_column("dspm_findings", sa.Column("cve_ids",    sa.JSON(),  nullable=True))
    op.add_column("dspm_findings", sa.Column("cvss_max",   sa.Float(), nullable=True))
    op.add_column("dspm_findings", sa.Column("vt_reputation",      sa.Float(), nullable=True))
    op.add_column("dspm_findings", sa.Column("threat_intel_boost",  sa.Float(), nullable=True))
    op.add_column(
        "dspm_findings",
        sa.Column(
            "threat_intel_enriched_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )

    # ── Feature 4: violations — threat intel columns ──────────────────────────
    op.add_column("violations", sa.Column("cve_ids",  sa.JSON(),  nullable=True))
    op.add_column("violations", sa.Column("cvss_max", sa.Float(), nullable=True))


def downgrade() -> None:
    # Reverse in strict reverse order of upgrade

    # Feature 4: violations
    op.drop_column("violations", "cvss_max")
    op.drop_column("violations", "cve_ids")

    # Feature 4: dspm_findings threat intel
    op.drop_column("dspm_findings", "threat_intel_enriched_at")
    op.drop_column("dspm_findings", "threat_intel_boost")
    op.drop_column("dspm_findings", "vt_reputation")
    op.drop_column("dspm_findings", "cvss_max")
    op.drop_column("dspm_findings", "cve_ids")

    # Feature 4: dspm_findings org FK
    op.drop_index("ix_dspm_findings_cloud_account_id", table_name="dspm_findings")
    op.drop_column("dspm_findings", "cloud_account_id")

    # Feature 3: auditor_org_assignments
    op.drop_table("auditor_org_assignments")

    # Feature 3: cloud_accounts.organization_id
    op.drop_index("ix_cloud_accounts_organization_id", table_name="cloud_accounts")
    op.drop_column("cloud_accounts", "organization_id")

    # Feature 3: organizations.remediation_dry_run
    op.drop_column("organizations", "remediation_dry_run")
