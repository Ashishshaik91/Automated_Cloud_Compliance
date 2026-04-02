# Feature Completion Plan: Cloud Compliance Platform

Four partial features identified in code review. Plan covers gap analysis, proposed changes per feature, and a verification approach.

> **Revision note:** This version incorporates fixes from plan review. Changes from v1 are marked with `[REVISED]` or `[ADDED]` tags inline.

---

## Gap Analysis Summary

| Feature | Current State | Gap |
|---|---|---|
| **Terraform State Ingestion** | Connectors use boto3/azure-mgmt SDKs directly | No `.tfstate` JSON parsing pipeline; no drift detection |
| **Remediation Runbooks** | `RemediationEngine` class with handler stubs | No per-rule YAML runbooks; Azure/GCP handlers missing; no rollback endpoint |
| **Multi-Account Org Isolation** | Schema has `org_id` FK; roles exist | API queries unscoped; Celery tasks bypass org filter; Auditor tier not differentiated |
| **Threat Intel Risk Enrichment** | Isolation Forest + DSPM internal scoring | No CVE/VirusTotal/MISP lookups; keyword NVD search too broad; no audit trail for score mutations |

---

## Decisions Required Before Coding

> [!IMPORTANT]
> The following questions from the original plan must be answered before any feature branch is created. Coding proceeds only once all four are resolved.

**Q1 — Terraform backend mode:** Do you have a remote Terraform backend (S3, GCS, Azure Blob) configured, or should the connector support only local `.tfstate` file uploads via REST endpoint? This determines whether we wire remote backend credentials. **Default in this plan: local JSON parse only, remote backend opt-in.**

**Q2 — VirusTotal API tier:** The free VirusTotal public API is rate-limited to 4 req/min. Do you have a premium key, or should we use the free tier with strict per-minute throttling + Redis caching? **Default in this plan: free tier with throttle queue.**

**Q3 — MISP instance:** Do you have a running MISP instance, or should the MISP integration be scaffolded but disabled by default (opt-in via `MISP_URL` config)? **Default in this plan: scaffolded, disabled.**

**Q4 — Org isolation migration — orphaned rows:** Applying org-scoping requires an Alembic migration to backfill `cloud_accounts.organization_id` for any existing rows. Should orphaned accounts be auto-assigned to a default "root" org, or left nullable (accessible only to Admins)? **Default in this plan: auto-assign to root org, with a migration guard that fails loudly if root org doesn't exist.**

---

## Proposed Changes

---

### Feature 1 — Terraform State Ingestion

**Goal:** Parse `.tfstate` JSON and ingest resources into the existing compliance scan pipeline as a supplementary data source alongside SDK connectors. Surface configuration drift when TF-declared state diverges from live SDK state.

> [!NOTE]
> We are NOT replacing SDK connectors. Terraform state is a supplementary source. The primary scan path remains the live SDK connectors.

#### [REVISED] `backend/app/connectors/terraform_connector.py`

**Parse mode (default):** Reads `.tfstate` JSON directly via Python's `json` module — no Terraform binary required, no subprocess, no container image changes.

**Binary mode (opt-in):** If `TERRAFORM_MODE=binary` is set in config, falls back to `subprocess.run(["terraform", "show", "-json"], ...)` (no `shell=True`). Requires Terraform CLI installed in the container.

Additional behaviours:
- Accepts a local `.tfstate` file path (uploaded via REST endpoint) OR, if `TERRAFORM_MODE=remote` is set, downloads state from S3/GCS/Azure Blob using credentials already available via env vars.
- Acquires a Redis-backed advisory lock (`tf_state_lock:{account_id}`) before reading remote state. TTL = 60s. If lock is already held (concurrent scan), raises `TerraformStateLockError` and the scan retries after 10s (max 3 attempts). Prevents concurrent reads of partial state.
- Normalizes TF resources into the same `{resource_type, resource_id, config}` dict format existing connectors produce.
- Handles: `aws_s3_bucket`, `aws_iam_user`, `aws_rds_instance`, `azurerm_storage_account`, `google_storage_bucket`.

#### [MODIFY] `backend/app/core/scanner.py`
- Add `TerraformConnector` as an optional third data source in `run_scan()`.
- Enabled by a new `use_terraform_state: bool` field on the scan request payload.
- Merge TF resources with SDK resources, deduplicating on `resource_id`. SDK resource wins for `config` fields; TF record stored as `terraform_declared_config` for drift comparison.

#### [MODIFY] `backend/app/api/scans.py`
- Expose `terraform_state_path` (optional string) on the scan trigger endpoint.

#### [NEW] `backend/policies/terraform/drift_check.yaml`
- New policy: flag when a TF-declared resource has `status: PASS` in `.tfstate` but `status: FAIL` in the live SDK scan — i.e., configuration drift. Severity = `medium` by default.

#### [ADDED] `backend/app/config.py`
- New settings:
  - `TERRAFORM_MODE: Literal["json", "binary", "remote"] = "json"`
  - `TERRAFORM_STATE_KMS_KEY_ARN: str | None = None`

---

### Feature 2 — Remediation Runbooks

**Goal:** Back every entry in `RemediationEngine.REMEDIATION_MAP` with a real YAML runbook, add Azure/GCP remediation handlers, expose a rollback API endpoint, and extend runbook coverage to DSPM violations.

> [!IMPORTANT]
> All live remediation actions stay behind `dry_run=True` by default. `dry_run` is a per-org flag, not a global constant. Runbooks are surfaced in the UI as step-by-step instructions the user can approve and trigger.

#### [NEW] `backend/runbooks/` directory — per-rule YAML files

```yaml
rule_id: s3-encryption-required
title: Enable S3 Bucket Default Encryption
severity: high
automated: true
framework_version: "PCI-DSS v4.0"
last_verified: "2026-01"
manual_steps:
  - "Open S3 console → Select bucket → Properties → Default encryption → Edit"
  - "Choose SSE-S3 or SSE-KMS and Save"
aws_cli_command: |
  aws s3api put-bucket-encryption \
    --bucket {resource_id} \
    --server-side-encryption-configuration ...
rollback_command: |
  aws s3api delete-bucket-encryption --bucket {resource_id}
references:
  - "https://docs.aws.amazon.com/AmazonS3/latest/userguide/default-bucket-encryption.html"
```

**Infrastructure runbooks:** `s3_encryption.yaml`, `s3_public_access.yaml`, `s3_versioning.yaml`, `iam_mfa.yaml`, `cloudtrail_logging.yaml`, `rds_encryption.yaml`, `azure_storage_https.yaml`, `azure_sql_tde.yaml`, `gcp_gcs_public_access.yaml`, `gcp_sql_ssl.yaml`

**DSPM runbooks (new):** `dspm_s3_pii_exposed.yaml`, `dspm_s3_unencrypted_data.yaml`, `dspm_rds_pii_unencrypted.yaml`, `dspm_gcs_public_pii.yaml`

#### [MODIFY] `backend/app/core/remediation.py`
- Add `load_runbook(rule_id) -> dict` — reads matching YAML file.
- Add Azure handler `_enforce_storage_https` and GCP handler `_block_gcs_public_access`.
- Add `execute_rollback(rule_id, resource_id, org_id)` — executes `rollback_command` from runbook YAML. Respects org-level `dry_run` flag. Emits audit log event.

#### [MODIFY] `backend/app/api/violations.py`
- Add `GET /api/v1/remediations/{rule_id}/runbook`
- Add `POST /api/v1/remediations/{rule_id}/rollback` — requires `remediation:execute` permission, respects org-level `dry_run`, returns audit event ID.

---

### Feature 3 — Multi-Account Org Isolation

**Goal:** Enforce all API queries and Celery tasks are scoped to the requesting user's organisation. Three-tier hierarchy: Admin (all orgs), Auditor (assigned orgs, read-only), Customer (own org only).

> [!WARNING]
> Security-critical change. Every data-fetching query without `organization_id` filter must be patched. Celery tasks are equally in scope.

#### Current gaps:
- `User.organization_id` → FK to `organizations` ✅
- `CloudAccount.organization_id` → FK to `organizations` ✅
- `UserAccountRole` → per-account role mapping ✅
- **Missing:** API queries in `scans.py`, `violations.py`, `dspm.py`, `alerts.py` unscoped.
- **Missing:** Celery task signatures carry no `organization_id`.
- **Missing:** Auditor role not differentiated from Customer.

#### [NEW] Alembic migration
1. Ensure `root` org exists (id=1). Fail loudly if absent.
2. Backfill `cloud_accounts.organization_id = 1` for NULL rows.
3. Add NOT NULL constraint to `cloud_accounts.organization_id`.
4. Add `auditor_org_assignments` join table.
5. Add `remediation_dry_run: bool DEFAULT true` to `organizations`.

#### [REVISED] `backend/app/auth/scoping.py`
```python
def get_org_filter(user: User) -> OrgScope:
    # Admin:    OrgScope(mode="all")
    # Auditor:  OrgScope(mode="assigned", org_ids=[...])
    # Customer: OrgScope(mode="own", org_ids=[user.organization_id])
```

#### [ADDED] `backend/app/models/org.py`
- `auditor_org_assignments` join table (auditor_user_id, organization_id, granted_by, granted_at).
- `remediation_dry_run: bool = True` column on `Organization`.

#### [MODIFY] All API files
- `scans.py`, `violations.py`, `dspm.py`, `alerts.py` — apply `apply_org_scope` to all list/detail queries.

#### [ADDED] Celery task org scoping
Tasks updated with `organization_id` in signature:
- `scan_tasks.py`, `alert_tasks.py`, `dspm_tasks.py`, `remediation_tasks.py`
- Raise `MissingOrgContextError` if `organization_id` is None.

---

### Feature 4 — Threat Intel Risk Enrichment

**Goal:** Enrich DSPM risk scores and violation severity with NVD/CVE (CPE search), VirusTotal, and optional MISP. Async, cached, fail-open, fully auditable.

#### [NEW] `backend/app/integrations/`
- `nvd_client.py` — CPE-based NVD search (CVSS ≥ 7.0 only)
- `virustotal_client.py` — VT v3 API with Redis-backed 4 req/min throttle queue
- `misp_client.py` — scaffolded, disabled unless `MISP_URL` set
- `threat_intel_cache.py` — Redis TTL 24h; key = `ti:{source}:{query_hash}`

#### CPE mapping table
| Resource type | CPE string |
|---|---|
| `aws_rds_instance` | `cpe:2.3:a:amazon:relational_database_service:*` |
| `aws_s3_bucket` | `cpe:2.3:a:amazon:simple_storage_service:*` |
| `azurerm_storage_account` | `cpe:2.3:a:microsoft:azure_storage:*` |
| `google_storage_bucket` | `cpe:2.3:a:google:cloud_storage:*` |

#### Risk score formula
```
base_score        = internal DSPM scoring (range: 0–80)
threat_intel_boost = min(20, ...)
  +10 per critical CVE (CVSS ≥ 9.0), capped at +20 from CVEs
  +20 if VT reputation > 0.5 (takes whichever is higher)
final_score = min(100, max(0, base_score + threat_intel_boost))
```

#### [MODIFY] `backend/app/models/dspm.py`
- Add: `cve_ids: JSON`, `cvss_max: Float`, `vt_reputation: Float`, `threat_intel_enriched_at: DateTime`, `threat_intel_boost: Float`

#### [MODIFY] `backend/app/models/violations.py`
- Add: `cve_ids: JSON`, `cvss_max: Float`

#### [ADDED] Audit event on enrichment
```json
{
  "event": "risk_score_enriched",
  "finding_id": "...",
  "before_score": 40,
  "threat_intel_boost": 20,
  "boost_reason": { "cve_ids": ["CVE-2024-XXXX"], "cvss_max": 9.1, "vt_reputation": 0.0 },
  "after_score": 60,
  "enriched_at": "2026-04-02T10:00:00Z"
}
```
Signed by the existing HMAC audit chain.

#### [MODIFY] `backend/app/config.py`
- `NVD_API_KEY`, `VIRUSTOTAL_API_KEY`, `MISP_URL`, `MISP_API_KEY`, `TERRAFORM_MODE`, `TERRAFORM_STATE_KMS_KEY_ARN`

---

## Verification Plan

### Automated Tests
```bash
docker compose exec backend pytest tests/ -v --cov=app

# Security regression (required on every PR)
docker compose exec backend pytest tests/security/test_cross_org_isolation.py -v

# Per-feature
docker compose exec backend pytest tests/unit/test_org_scoping.py -v
docker compose exec backend pytest tests/unit/test_celery_org_context.py -v
docker compose exec backend pytest tests/unit/test_threat_intel.py -v
docker compose exec backend pytest tests/unit/test_nvd_cpe_mapping.py -v
docker compose exec backend pytest tests/unit/test_terraform_connector.py -v
docker compose exec backend pytest tests/unit/test_runbooks.py -v
```

### Manual Verification
1. **Terraform:** Upload `.tfstate` → resources appear in violations panel → modify live resource → drift violation raised.
2. **Runbooks:** `GET /remediations/{rule_id}/runbook` returns YAML. `POST /rollback` with `dry_run=True` returns audit ID with no cloud API call.
3. **Org Isolation:** User A cannot see User B's org data across `/scans/`, `/violations/`, `/dspm/findings/`, `/alerts/`.
4. **Auditor role:** Auditor reads assigned org, cannot create/trigger in any org.
5. **Threat Intel:** DSPM scan populates `cve_ids`, `cvss_max` in response; audit log shows `risk_score_enriched` event.
6. **Celery:** Worker logs show `organization_id` in task args on every scan dispatch.

---

## Resolved Decisions

| Question | Decision |
|---|---|
| Terraform backend mode | Local JSON parse; remote opt-in via `TERRAFORM_MODE=remote` |
| VirusTotal API tier | Free tier with Redis-backed 4 req/min throttle queue |
| MISP | Scaffolded, disabled unless `MISP_URL` is set |
| Orphaned cloud_account rows | Auto-assign to root org (id=1); migration fails loudly if root absent |
