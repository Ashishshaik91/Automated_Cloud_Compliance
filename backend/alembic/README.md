# Alembic Migrations

This directory manages all database schema migrations for the Cloud Compliance Platform.

## Commands

All commands must be run from the `backend/` directory:

```bash
# Apply all pending migrations to the connected DB
alembic upgrade head

# Roll back the last migration
alembic downgrade -1

# Roll back to a specific revision
alembic downgrade 0001

# Generate a new migration from model changes (always review before applying)
alembic revision --autogenerate -m "describe your change here"

# Show current revision
alembic current

# Show full migration history
alembic history --verbose
```

## Environment

Alembic reads `DATABASE_URL` from the app's `Settings` (via environment variables or `.env`).
The Docker stack sets this automatically. For local runs, ensure you have exported:

```bash
export DATABASE_URL=postgresql+asyncpg://user:password@localhost:5432/compliance_db
```

## Migration 0001 — Feature Completion

File: `versions/1743590400_0001_feature_4_columns_and_new_tables.py`

Covers all schema changes from the four feature completions:

| Table | Change | Feature |
|---|---|---|
| `organizations` | + `remediation_dry_run` BOOLEAN | 3 |
| `cloud_accounts` | + `organization_id` FK (nullable) | 3 |
| `auditor_org_assignments` | New table | 3 |
| `dspm_findings` | + `cloud_account_id` FK (nullable) | 4 |
| `dspm_findings` | + `cve_ids`, `cvss_max`, `vt_reputation`, `threat_intel_boost`, `threat_intel_enriched_at` | 4 |
| `violations` | + `cve_ids`, `cvss_max` | 4 |

### Backfill Notes

- `cloud_accounts.organization_id` is **nullable** — existing rows will have `NULL`.
  Assign org IDs as needed via admin UI or direct SQL.
- `organizations.remediation_dry_run` defaults to `TRUE` — all existing orgs are
  placed in safe dry-run mode. Admins must explicitly set to `FALSE` to enable live remediation.
