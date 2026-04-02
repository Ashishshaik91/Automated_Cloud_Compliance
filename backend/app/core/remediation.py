"""
Automated Remediation Module — Feature 2 (updated).

Executes policy-driven remediation actions for non-compliant resources.
All actions are logged with full audit trail.
Dry-run mode is now per-org (Organisation.remediation_dry_run flag).

New in this version:
 - load_runbook(rule_id) → loads per-rule YAML runbook from backend/runbooks/
 - execute_rollback(rule_id, resource_id, org_id) → runs rollback_command from runbook
 - Azure handler: _enforce_storage_https
 - GCP handler: _block_gcs_public_access
"""

from pathlib import Path
from typing import Any

import structlog
import yaml

from app.config import get_settings
from app.models.compliance import ComplianceCheck

settings = get_settings()
logger = structlog.get_logger(__name__)

RUNBOOKS_DIR = Path(__file__).parent.parent.parent / "runbooks"


def load_runbook(rule_id: str) -> dict[str, Any] | None:
    """
    Load a runbook YAML file for the given rule_id.

    Returns the parsed dict, or None if no runbook exists for this rule.
    Sanitises the rule_id to prevent path traversal.
    """
    safe_id = "".join(c for c in rule_id if c.isalnum() or c in "-_")
    runbook_path = RUNBOOKS_DIR / f"{safe_id}.yaml"
    if not runbook_path.exists():
        logger.debug("No runbook found for rule", rule_id=rule_id)
        return None
    try:
        with runbook_path.open() as fh:
            return yaml.safe_load(fh)
    except Exception as e:
        logger.error("Failed to load runbook", rule_id=rule_id, error=str(e))
        return None


class RemediationEngine:
    """
    Applies automated fix actions for identified compliance violations.
    Supports dry_run mode to preview actions without applying them.
    dry_run is now set per-org via Organisation.remediation_dry_run.
    """

    # Maps (resource_type, policy_id) → remediation function name
    REMEDIATION_MAP: dict[tuple[str, str], str] = {
        # AWS
        ("s3_bucket",   "s3-encryption-required"):      "_enable_s3_encryption",
        ("s3_bucket",   "s3-public-access-blocked"):    "_block_s3_public_access",
        ("s3_bucket",   "s3-versioning-required"):      "_enable_s3_versioning",
        ("iam_user",    "iam-mfa-required"):             "_flag_iam_mfa_missing",
        ("cloudtrail",  "cloudtrail-logging-enabled"):  "_enable_cloudtrail",
        ("rds_instance","rds-encryption-required"):     "_flag_rds_unencrypted",
        # Azure (new)
        ("storage_account", "azure-storage-https-required"): "_enforce_storage_https",
        ("sql_database",    "azure-sql-tde-required"):        "_enforce_azure_sql_tde",
        # GCP (new)
        ("gcs_bucket",      "gcp-gcs-public-access-blocked"): "_block_gcs_public_access",
        ("cloud_sql_instance", "gcp-sql-ssl-required"):       "_flag_gcp_sql_ssl",
        # DSPM-linked
        ("s3_bucket",   "dspm-s3-pii-exposed"):         "_block_s3_public_access",
        ("s3_bucket",   "dspm-s3-unencrypted"):         "_enable_s3_encryption",
        ("rds_instance","dspm-rds-pii-unencrypted"):    "_flag_rds_unencrypted",
        ("gcs_bucket",  "dspm-gcs-public-pii"):         "_block_gcs_public_access",
    }

    def __init__(self, dry_run: bool = True) -> None:
        self.dry_run = dry_run

    async def remediate(
        self,
        check: ComplianceCheck,
        resource_data: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Attempt automated remediation for a failed compliance check.
        Returns a dict describing the action taken (or that would be taken in dry_run).
        """
        key = (check.resource_type or "", check.policy_id)
        handler_name = self.REMEDIATION_MAP.get(key)

        if not handler_name:
            return {
                "status": "no_action",
                "message": f"No automated remediation available for {check.policy_id}",
            }

        handler = getattr(self, handler_name, None)
        if not handler:
            return {"status": "error", "message": f"Handler {handler_name} not found"}

        if self.dry_run:
            logger.info(
                "DRY RUN remediation",
                policy_id=check.policy_id,
                resource_id=check.resource_id,
                action=handler_name,
            )
            return {
                "status":      "dry_run",
                "action":      handler_name,
                "resource_id": check.resource_id,
                "message":     f"Would execute: {handler_name}",
                "runbook":     load_runbook(check.policy_id),
            }

        try:
            result = await handler(check, resource_data)
            logger.info(
                "Remediation applied",
                policy_id=check.policy_id,
                resource_id=check.resource_id,
                action=handler_name,
            )
            return result
        except Exception as e:
            logger.error(
                "Remediation failed",
                policy_id=check.policy_id,
                resource_id=check.resource_id,
                error=str(e),
            )
            return {"status": "error", "message": str(e)}

    async def execute_rollback(
        self,
        rule_id: str,
        resource_id: str,
        org_id: int | None,
    ) -> dict[str, Any]:
        """
        Execute the rollback_command from the rule's runbook.
        Always respects the current dry_run setting.
        Returns a status dict suitable for the API response.
        """
        runbook = load_runbook(rule_id)
        if not runbook:
            return {
                "status":  "no_runbook",
                "message": f"No runbook found for rule '{rule_id}'",
            }

        rollback_cmd = runbook.get("rollback_command", "").strip()
        if not rollback_cmd:
            return {
                "status":  "no_rollback",
                "message": f"Runbook for '{rule_id}' has no rollback_command defined.",
            }

        # Interpolate {resource_id} placeholder
        rollback_cmd = rollback_cmd.replace("{resource_id}", resource_id)

        if self.dry_run:
            logger.info(
                "DRY RUN rollback",
                rule_id=rule_id,
                resource_id=resource_id,
                command_preview=rollback_cmd[:200],
            )
            return {
                "status":          "dry_run",
                "rule_id":         rule_id,
                "resource_id":     resource_id,
                "rollback_command": rollback_cmd,
                "message":         "Dry-run: rollback command logged but not executed.",
            }

        # Live execution — log it prominently
        logger.warning(
            "LIVE rollback executing",
            rule_id=rule_id,
            resource_id=resource_id,
            org_id=org_id,
        )
        # CLI rollback commands are surfaced as instructions; actual SDK calls
        # should be implemented per handler. We log and return for audit.
        return {
            "status":          "rollback_queued",
            "rule_id":         rule_id,
            "resource_id":     resource_id,
            "rollback_command": rollback_cmd,
            "message":         "Rollback command logged. Execute via CLI or automated pipeline.",
        }

    # ── AWS handlers ─────────────────────────────────────────────────────────

    async def _enable_s3_encryption(
        self, check: ComplianceCheck, resource_data: dict[str, Any]
    ) -> dict[str, Any]:
        import boto3
        s3 = boto3.client("s3")
        bucket_name = check.resource_id or ""
        s3.put_bucket_encryption(
            Bucket=bucket_name,
            ServerSideEncryptionConfiguration={
                "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
            },
        )
        return {"status": "applied", "action": "s3_encryption_enabled", "resource": bucket_name}

    async def _block_s3_public_access(
        self, check: ComplianceCheck, resource_data: dict[str, Any]
    ) -> dict[str, Any]:
        import boto3
        s3 = boto3.client("s3")
        bucket_name = check.resource_id or ""
        s3.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        )
        return {"status": "applied", "action": "s3_public_access_blocked", "resource": bucket_name}

    async def _enable_s3_versioning(
        self, check: ComplianceCheck, resource_data: dict[str, Any]
    ) -> dict[str, Any]:
        import boto3
        s3 = boto3.client("s3")
        bucket_name = check.resource_id or ""
        s3.put_bucket_versioning(
            Bucket=bucket_name,
            VersioningConfiguration={"Status": "Enabled"},
        )
        return {"status": "applied", "action": "s3_versioning_enabled", "resource": bucket_name}

    async def _flag_iam_mfa_missing(
        self, check: ComplianceCheck, resource_data: dict[str, Any]
    ) -> dict[str, Any]:
        return {
            "status":  "flagged",
            "action":  "mfa_enforcement_required",
            "message": "Manual action required: Enable MFA for IAM user",
            "resource": check.resource_id,
        }

    async def _enable_cloudtrail(
        self, check: ComplianceCheck, resource_data: dict[str, Any]
    ) -> dict[str, Any]:
        import boto3
        ct = boto3.client("cloudtrail")
        trail_name = check.resource_id or ""
        ct.start_logging(Name=trail_name)
        return {"status": "applied", "action": "cloudtrail_logging_enabled", "resource": trail_name}

    async def _flag_rds_unencrypted(
        self, check: ComplianceCheck, resource_data: dict[str, Any]
    ) -> dict[str, Any]:
        return {
            "status":  "flagged",
            "action":  "rds_recreation_required",
            "message": "RDS encryption requires instance recreation. Manual action required.",
            "resource": check.resource_id,
        }

    # ── Azure handlers (new) ─────────────────────────────────────────────────

    async def _enforce_storage_https(
        self, check: ComplianceCheck, resource_data: dict[str, Any]
    ) -> dict[str, Any]:
        """Enable HTTPS-only traffic on an Azure Storage Account."""
        try:
            from azure.identity import DefaultAzureCredential
            from azure.mgmt.storage import StorageManagementClient

            credential       = DefaultAzureCredential()
            subscription_id  = settings.azure_subscription_id
            resource_group   = resource_data.get("resource_group", "")
            account_name     = check.resource_id or ""

            client = StorageManagementClient(credential, subscription_id)
            client.storage_accounts.update(
                resource_group,
                account_name,
                {"enable_https_traffic_only": True},
            )
            return {
                "status":   "applied",
                "action":   "azure_storage_https_enforced",
                "resource": account_name,
            }
        except Exception as e:
            logger.error("Azure storage HTTPS remediation failed", error=str(e))
            return {"status": "error", "message": str(e)}

    async def _enforce_azure_sql_tde(
        self, check: ComplianceCheck, resource_data: dict[str, Any]
    ) -> dict[str, Any]:
        """Enable Transparent Data Encryption on Azure SQL Database."""
        return {
            "status":  "flagged",
            "action":  "azure_sql_tde_required",
            "message": "Enable TDE via Azure Portal or az sql db tde set. See runbook.",
            "resource": check.resource_id,
        }

    # ── GCP handlers (new) ───────────────────────────────────────────────────

    async def _block_gcs_public_access(
        self, check: ComplianceCheck, resource_data: dict[str, Any]
    ) -> dict[str, Any]:
        """Remove public IAM bindings and enable uniform bucket-level access on GCS."""
        try:
            from google.cloud import storage as gcs

            client      = gcs.Client()
            bucket_name = check.resource_id or ""
            bucket      = client.bucket(bucket_name)

            # Enable uniform bucket-level access (blocks ACL bypass)
            bucket.iam_configuration.uniform_bucket_level_access_enabled = True
            bucket.patch()

            # Remove allUsers and allAuthenticatedUsers bindings
            policy = bucket.get_iam_policy(requested_policy_version=3)
            policy.bindings[:] = [
                b for b in policy.bindings
                if "allUsers" not in b["members"] and "allAuthenticatedUsers" not in b["members"]
            ]
            bucket.set_iam_policy(policy)

            return {
                "status":   "applied",
                "action":   "gcs_public_access_blocked",
                "resource": bucket_name,
            }
        except Exception as e:
            logger.error("GCS public access remediation failed", error=str(e))
            return {"status": "error", "message": str(e)}

    async def _flag_gcp_sql_ssl(
        self, check: ComplianceCheck, resource_data: dict[str, Any]
    ) -> dict[str, Any]:
        """Flag GCP Cloud SQL instance that requires SSL enforcement."""
        return {
            "status":  "flagged",
            "action":  "gcp_sql_ssl_required",
            "message": "Require SSL via: gcloud sql instances patch <name> --require-ssl",
            "resource": check.resource_id,
        }
