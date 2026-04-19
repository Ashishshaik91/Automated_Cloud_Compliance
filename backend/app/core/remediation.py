"""
Automated Remediation Module — Feature 2 (complete).

Executes policy-driven remediation actions for non-compliant resources.
All actions are logged with full audit trail.
Dry-run mode is per-org (Organisation.remediation_dry_run flag).

Key design decisions:
 - load_runbook(rule_id): resolves policy_id ? runbook filename via RULE_ID_TO_RUNBOOK
   mapping. This decouples the policy IDs emitted by the violations engine (kebab-case)
   from the runbook filenames (snake_case).
 - execute_rollback(rule_id, resource_id, org_id): for automated=true rules, calls
   the SDK handler directly (live path). For manual-only rules, surfaces the CLI
   command as an instruction.
 - All handlers use lazy cloud SDK imports so the module loads cleanly in test/dry-run.
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

# -- rule_id ? runbook filename mapping ----------------------------------------
# Maps the policy_id strings used in ComplianceCheck / REMEDIATION_MAP to the
# actual YAML runbook filenames in backend/runbooks/.
# This avoids renaming the physical files: the YAML rule_id field is human-facing,
# the policy_id is the machine-facing key used in the compliance engine.
RULE_ID_TO_RUNBOOK: dict[str, str] = {
    # AWS — infrastructure (policy_id format from compliance scanner)
    "s3-encryption-required":     "s3_encryption",
    "s3-public-access-blocked":   "s3_public_access",
    "s3-versioning-required":     "s3_versioning",
    "iam-mfa-required":           "iam_mfa",
    "cloudtrail-logging-enabled": "cloudtrail_logging",
    "rds-encryption-required":    "rds_encryption",
    "ec2-sg-open-ssh":            "ec2_security_group",
    "ec2-sg-open-rdp":            "ec2_security_group",
    "ec2-sg-unrestricted-ingress":"ec2_security_group",
    "iam-access-key-active":      "aws_iam_access_key_active",
    # Azure
    "azure-storage-https-required": "azure_storage_https",
    "azure-sql-tde-required":       "azure_sql_tde",
    # GCP
    "gcp-gcs-public-access-blocked": "gcp_gcs_public_access",
    "gcp-sql-ssl-required":          "gcp_sql_ssl",
    # DSPM-linked
    "dspm-s3-pii-exposed":       "dspm_s3_pii_exposed",
    "dspm-s3-unencrypted":       "dspm_s3_unencrypted_data",
    "dspm-rds-pii-unencrypted":  "dspm_rds_pii_unencrypted",
    "dspm-gcs-public-pii":       "dspm_gcs_public_pii",
    # -- violations_engine.py rule IDs (uppercase, provider-prefixed format) --
    # These are the rule_id values actually stored in the Violation table.
    "AWS-S3-001":  "s3_public_access",
    "AWS-SG-001":  "ec2_security_group",
    "AWS-EBS-001": "rds_encryption",        # closest available — EBS runbook TBD
    "AWS-IAM-001": "iam_mfa",               # root MFA = IAM MFA runbook
    "AWS-IAM-002": "iam_mfa",               # wildcard policy = MFA / IAM runbook
    "AWS-IAM-003": "aws_iam_access_key_active",
    "AWS-CT-001":  "cloudtrail_logging",
    "AWS-RDS-001": "rds_encryption",
    "AZ-ST-001":   "azure_storage_https",
    "AZ-NSG-001":  "ec2_security_group",    # NSG open-any = same class as SG open
    "GCP-GCS-001": "gcp_gcs_public_access",
}

# Automated rules: execute_rollback calls the matching SDK handler (not just logs CLI).
# Manual-only rules surface the CLI rollback_command as an instruction string.
AUTOMATED_RULE_IDS: frozenset[str] = frozenset({
    # compliance scanner policy_ids
    "s3-encryption-required",
    "s3-public-access-blocked",
    "s3-versioning-required",
    "cloudtrail-logging-enabled",
    "azure-storage-https-required",
    "gcp-gcs-public-access-blocked",
    "dspm-s3-pii-exposed",
    "dspm-s3-unencrypted",
    "dspm-gcs-public-pii",
    "ec2-sg-open-ssh",
    "ec2-sg-unrestricted-ingress",
    # violations engine rule_ids
    "AWS-S3-001",
    "AWS-SG-001",
    "AWS-CT-001",
    "AZ-ST-001",
    "GCP-GCS-001",
})


def load_runbook(rule_id: str) -> dict[str, Any] | None:
    """
    Load a runbook YAML file for the given rule_id.

    Resolves via RULE_ID_TO_RUNBOOK first (policy_id ? filename), then falls
    back to a direct filename match (for custom/unknown rule IDs).
    Sanitises the rule_id to prevent path traversal.
    Returns the parsed dict, or None if no runbook exists for this rule.
    """
    # Resolve via mapping, fall back to direct (sanitised) name
    filename = RULE_ID_TO_RUNBOOK.get(rule_id)
    if filename is None:
        # Direct fallback: sanitise and try as-is
        filename = "".join(c for c in rule_id if c.isalnum() or c in "-_")

    runbook_path = RUNBOOKS_DIR / f"{filename}.yaml"
    if not runbook_path.exists():
        logger.debug("No runbook found for rule", rule_id=rule_id, tried=str(runbook_path))
        return None
    try:
        with runbook_path.open() as fh:
            return yaml.safe_load(fh)
    except Exception as e:
        logger.error("Failed to load runbook", rule_id=rule_id, error=str(e))
        return None


def list_runbooks() -> list[dict[str, Any]]:
    """Return a summary list of all available runbooks (title, severity, automated flag)."""
    runbooks = []
    for path in sorted(RUNBOOKS_DIR.glob("*.yaml")):
        try:
            with path.open() as fh:
                data = yaml.safe_load(fh) or {}
            runbooks.append({
                "rule_id":   data.get("rule_id", path.stem),
                "filename":  path.stem,
                "title":     data.get("title", ""),
                "severity":  data.get("severity", ""),
                "automated": data.get("automated", False),
                "framework": data.get("framework_version", ""),
            })
        except Exception:
            pass
    return runbooks


class RemediationEngine:
    """
    Applies automated fix actions for identified compliance violations.
    Supports dry_run mode to preview actions without applying them.
    dry_run is set per-org via Organisation.remediation_dry_run.
    """

    # Maps (resource_type, policy_id) ? remediation function name
    REMEDIATION_MAP: dict[tuple[str, str], str] = {
        # AWS
        ("s3_bucket",    "s3-encryption-required"):       "_enable_s3_encryption",
        ("s3_bucket",    "s3-public-access-blocked"):     "_block_s3_public_access",
        ("s3_bucket",    "s3-versioning-required"):       "_enable_s3_versioning",
        ("iam_user",     "iam-mfa-required"):              "_flag_iam_mfa_missing",
        ("iam_user",     "iam-access-key-active"):         "_flag_iam_access_key",
        ("cloudtrail",   "cloudtrail-logging-enabled"):   "_enable_cloudtrail",
        ("rds_instance", "rds-encryption-required"):      "_flag_rds_unencrypted",
        ("ec2_instance", "ec2-sg-open-ssh"):               "_revoke_sg_open_ssh",
        ("ec2_instance", "ec2-sg-unrestricted-ingress"):  "_revoke_sg_open_ssh",
        # Azure
        ("storage_account",  "azure-storage-https-required"): "_enforce_storage_https",
        ("sql_database",     "azure-sql-tde-required"):        "_enforce_azure_sql_tde",
        # GCP
        ("gcs_bucket",       "gcp-gcs-public-access-blocked"): "_block_gcs_public_access",
        ("cloud_sql_instance","gcp-sql-ssl-required"):          "_flag_gcp_sql_ssl",
        # DSPM-linked
        ("s3_bucket",    "dspm-s3-pii-exposed"):    "_block_s3_public_access",
        ("s3_bucket",    "dspm-s3-unencrypted"):    "_enable_s3_encryption",
        ("rds_instance", "dspm-rds-pii-unencrypted"): "_flag_rds_unencrypted",
        ("gcs_bucket",   "dspm-gcs-public-pii"):    "_block_gcs_public_access",
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
        Returns a dict describing the action taken (or previewed in dry_run).
        """
        key = (check.resource_type or "", check.policy_id)
        handler_name = self.REMEDIATION_MAP.get(key)

        if not handler_name:
            return {
                "status": "no_action",
                "message": f"No automated remediation available for {check.policy_id}",
                "runbook": load_runbook(check.policy_id),
            }

        handler = getattr(self, handler_name, None)
        if not handler:
            return {"status": "error", "message": f"Handler {handler_name} not found"}

        runbook = load_runbook(check.policy_id)

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
                "runbook":     runbook,
            }

        try:
            result = await handler(check, resource_data)
            logger.info(
                "Remediation applied",
                policy_id=check.policy_id,
                resource_id=check.resource_id,
                action=handler_name,
            )
            if runbook:
                result["runbook_title"] = runbook.get("title", "")
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
        Execute the rollback for a given rule and resource.

        For AUTOMATED_RULE_IDS: calls the SDK handler directly (live path).
        For manual-only rules: surfaces the CLI rollback_command as an instruction.
        Always respects the current dry_run setting and returns an audit-ready dict.
        """
        runbook = load_runbook(rule_id)
        if not runbook:
            return {
                "status":  "no_runbook",
                "message": f"No runbook found for rule '{rule_id}'. "
                           f"Available: {[r['rule_id'] for r in list_runbooks()]}",
            }

        rollback_cmd = runbook.get("rollback_command", "").strip()
        if not rollback_cmd:
            return {
                "status":  "no_rollback",
                "message": f"Runbook for '{rule_id}' has no rollback_command defined.",
            }

        # Interpolate {resource_id} placeholder
        rollback_cmd_interpolated = rollback_cmd.replace("{resource_id}", resource_id)

        if self.dry_run:
            logger.info(
                "DRY RUN rollback",
                rule_id=rule_id,
                resource_id=resource_id,
                command_preview=rollback_cmd_interpolated[:200],
            )
            return {
                "status":           "dry_run",
                "rule_id":          rule_id,
                "resource_id":      resource_id,
                "rollback_command": rollback_cmd_interpolated,
                "automated":        rule_id in AUTOMATED_RULE_IDS,
                "message":          "Dry-run: rollback command previewed but not executed.",
                "runbook_title":    runbook.get("title", ""),
            }

        # Live path
        logger.warning(
            "LIVE rollback executing",
            rule_id=rule_id,
            resource_id=resource_id,
            org_id=org_id,
            automated=rule_id in AUTOMATED_RULE_IDS,
        )

        if rule_id in AUTOMATED_RULE_IDS:
            # Dispatch to SDK handler via a synthetic ComplianceCheck
            return await self._execute_sdk_rollback(rule_id, resource_id, org_id)

        # Manual-only: return the CLI command as an instruction string
        return {
            "status":           "rollback_queued",
            "rule_id":          rule_id,
            "resource_id":      resource_id,
            "rollback_command": rollback_cmd_interpolated,
            "automated":        False,
            "message":          "Manual rollback required. Execute the CLI command above.",
            "runbook_title":    runbook.get("title", ""),
        }

    async def _execute_sdk_rollback(
        self,
        rule_id: str,
        resource_id: str,
        org_id: int | None,
    ) -> dict[str, Any]:
        """
        Dispatch SDK rollback for automated rules by calling the inverse handler.
        Each SDK rollback handler is the logical inverse of the corresponding remediation.
        """
        # Use SimpleNamespace to avoid SQLAlchemy ORM initialisation errors
        import types
        check = types.SimpleNamespace(
            policy_id=rule_id,
            resource_id=resource_id,
            resource_type="",
        )

        rollback_dispatch: dict[str, str] = {
            # ── Compliance scanner short IDs ─────────────────────────────────
            "s3-encryption-required":        "_rollback_s3_encryption",
            "s3-public-access-blocked":      "_rollback_s3_public_access",
            "s3-versioning-required":        "_rollback_s3_versioning",
            "cloudtrail-logging-enabled":    "_rollback_cloudtrail",
            "azure-storage-https-required":  "_rollback_storage_https",
            "gcp-gcs-public-access-blocked": "_rollback_gcs_public_access",
            "dspm-s3-pii-exposed":           "_rollback_s3_public_access",
            "dspm-s3-unencrypted":           "_rollback_s3_encryption",
            "dspm-gcs-public-pii":           "_rollback_gcs_public_access",
            "ec2-sg-open-ssh":               "_rollback_sg_open_ssh",
            "ec2-sg-unrestricted-ingress":   "_rollback_sg_open_ssh",
            # ── Violations engine format ──────────────────────────────────────
            "AWS-S3-001":  "_rollback_s3_public_access",
            "AWS-SG-001":  "_rollback_sg_open_ssh",
            "AWS-CT-001":  "_rollback_cloudtrail",
            "AZ-ST-001":   "_rollback_storage_https",
            "GCP-GCS-001": "_rollback_gcs_public_access",
            # ── Framework-prefixed policy IDs from compliance checks ──────────
            # S3 public access
            "pci-s3-no-public-access":   "_rollback_s3_public_access",
            "hipaa-s3-no-public":        "_rollback_s3_public_access",
            "gdpr-s3-no-public":         "_rollback_s3_public_access",
            "cis-s3-public-access":      "_rollback_s3_public_access",
            "nist-s3-public-access":     "_rollback_s3_public_access",
            "soc2-s3-public-access":     "_rollback_s3_public_access",
            "owasp-s3-public-exposure":  "_rollback_s3_public_access",
            # S3 encryption
            "pci-s3-encryption-required": "_rollback_s3_encryption",
            "hipaa-s3-encryption":        "_rollback_s3_encryption",
            "gdpr-s3-encryption":         "_rollback_s3_encryption",
            "cis-s3-encryption":          "_rollback_s3_encryption",
            "nist-s3-encryption":         "_rollback_s3_encryption",
            "soc2-s3-encryption":         "_rollback_s3_encryption",
            "owasp-s3-encryption":        "_rollback_s3_encryption",
            # S3 versioning
            "hipaa-s3-versioning":        "_rollback_s3_versioning",
            "gdpr-s3-versioning":         "_rollback_s3_versioning",
            # CloudTrail
            "pci-cloudtrail-enabled":          "_rollback_cloudtrail",
            "pci-cloudtrail-validation":       "_rollback_cloudtrail",
            "hipaa-cloudtrail-enabled":        "_rollback_cloudtrail",
            "gdpr-cloudtrail-audit":           "_rollback_cloudtrail",
            "cis-cloudtrail-log-validation":   "_rollback_cloudtrail",
            "nist-audit-logging":              "_rollback_cloudtrail",
            "nist-cloudtrail-multiregion":     "_rollback_cloudtrail",
            "soc2-cloudtrail-monitoring":      "_rollback_cloudtrail",
            "owasp-cloudtrail-logging":        "_rollback_cloudtrail",
            # IAM MFA — manual only (no automated SDK action safe enough)
            "pci-iam-mfa-required":   "_flag_iam_mfa_missing",
            "hipaa-iam-mfa":          "_flag_iam_mfa_missing",
            "nist-iam-mfa":           "_flag_iam_mfa_missing",
            "soc2-iam-mfa":           "_flag_iam_mfa_missing",
            "owasp-iam-no-mfa":       "_flag_iam_mfa_missing",
            "cis-root-mfa":           "_flag_iam_mfa_missing",
            "cis-iam-no-active-keys": "_flag_iam_mfa_missing",
        }

        handler_name = rollback_dispatch.get(rule_id)
        if not handler_name:
            return {
                "status":  "manual_required",
                "message": f"No SDK rollback handler for '{rule_id}'. Run CLI command manually.",
            }

        handler = getattr(self, handler_name, None)
        if not handler:
            return {"status": "error", "message": f"Rollback handler {handler_name} not found"}

        try:
            result = await handler(check, {})
            result["rule_id"] = rule_id
            return result
        except Exception as e:
            logger.error("SDK rollback failed", rule_id=rule_id, resource_id=resource_id, error=str(e))
            return {"status": "error", "message": str(e)}

    # -- AWS remediation handlers -----------------------------------------------

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
            "status":   "flagged",
            "action":   "mfa_enforcement_required",
            "message":  "Manual action required: Enable MFA for IAM user. See runbook.",
            "resource": check.resource_id,
            "runbook":  load_runbook("iam-mfa-required"),
        }

    async def _flag_iam_access_key(
        self, check: ComplianceCheck, resource_data: dict[str, Any]
    ) -> dict[str, Any]:
        return {
            "status":   "flagged",
            "action":   "access_key_rotation_required",
            "message":  "Rotate or deactivate the IAM access key. See runbook.",
            "resource": check.resource_id,
            "runbook":  load_runbook("iam-access-key-active"),
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
            "status":   "flagged",
            "action":   "rds_recreation_required",
            "message":  "RDS encryption at rest requires instance recreation. See runbook for the snapshot-based migration path.",
            "resource": check.resource_id,
            "runbook":  load_runbook("rds-encryption-required"),
        }

    async def _revoke_sg_open_ssh(
        self, check: ComplianceCheck, resource_data: dict[str, Any]
    ) -> dict[str, Any]:
        """Revoke world-open SSH inbound rule from an EC2 Security Group."""
        import boto3
        ec2 = boto3.client("ec2")
        sg_id = check.resource_id or resource_data.get("group_id", "")
        if not sg_id:
            return {"status": "error", "message": "No security group ID found on check"}

        revoked = []
        # Revoke IPv4 0.0.0.0/0 on port 22
        try:
            ec2.revoke_security_group_ingress(
                GroupId=sg_id,
                IpPermissions=[{
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }],
            )
            revoked.append("tcp/22 from 0.0.0.0/0")
        except ec2.exceptions.InvalidPermission_NotFound:
            pass  # Rule may not have existed — that's fine

        # Revoke IPv6 ::/0 on port 22
        try:
            ec2.revoke_security_group_ingress(
                GroupId=sg_id,
                IpPermissions=[{
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
                }],
            )
            revoked.append("tcp/22 from ::/0")
        except Exception:
            pass

        return {
            "status":        "applied",
            "action":        "sg_open_ssh_revoked",
            "resource":      sg_id,
            "rules_revoked": revoked,
        }

    # -- AWS rollback handlers --------------------------------------------------

    async def _rollback_s3_encryption(
        self, check: ComplianceCheck, resource_data: dict[str, Any]
    ) -> dict[str, Any]:
        import boto3
        s3 = boto3.client("s3")
        bucket_name = check.resource_id or ""
        s3.delete_bucket_encryption(Bucket=bucket_name)
        return {"status": "rolled_back", "action": "s3_encryption_removed", "resource": bucket_name}

    async def _rollback_s3_public_access(
        self, check: ComplianceCheck, resource_data: dict[str, Any]
    ) -> dict[str, Any]:
        import boto3
        s3 = boto3.client("s3")
        bucket_name = check.resource_id or ""
        s3.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": False,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": False,
            },
        )
        return {"status": "rolled_back", "action": "s3_public_access_reopened",
                "resource": bucket_name, "warning": "Public access re-enabled"}

    async def _rollback_s3_versioning(
        self, check: ComplianceCheck, resource_data: dict[str, Any]
    ) -> dict[str, Any]:
        import boto3
        s3 = boto3.client("s3")
        bucket_name = check.resource_id or ""
        s3.put_bucket_versioning(
            Bucket=bucket_name,
            VersioningConfiguration={"Status": "Suspended"},
        )
        return {"status": "rolled_back", "action": "s3_versioning_suspended", "resource": bucket_name}

    async def _rollback_cloudtrail(
        self, check: ComplianceCheck, resource_data: dict[str, Any]
    ) -> dict[str, Any]:
        import boto3
        ct = boto3.client("cloudtrail")
        trail_name = check.resource_id or ""
        ct.stop_logging(Name=trail_name)
        return {"status": "rolled_back", "action": "cloudtrail_logging_stopped",
                "resource": trail_name, "warning": "CloudTrail logging disabled"}

    async def _rollback_sg_open_ssh(
        self, check: ComplianceCheck, resource_data: dict[str, Any]
    ) -> dict[str, Any]:
        """WARNING: re-opens world-accessible SSH — only for rollback edge cases."""
        import boto3
        ec2 = boto3.client("ec2")
        sg_id = check.resource_id or resource_data.get("group_id", "")
        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[{
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }],
        )
        return {
            "status":   "rolled_back",
            "action":   "sg_open_ssh_restored",
            "resource": sg_id,
            "warning":  "SECURITY RISK: world-open SSH has been re-authorised",
        }

    # -- Azure handlers --------------------------------------------------------

    async def _enforce_storage_https(
        self, check: ComplianceCheck, resource_data: dict[str, Any]
    ) -> dict[str, Any]:
        """Enable HTTPS-only traffic on an Azure Storage Account."""
        try:
            from azure.identity import DefaultAzureCredential
            from azure.mgmt.storage import StorageManagementClient

            credential      = DefaultAzureCredential()
            subscription_id = settings.azure_subscription_id
            resource_group  = resource_data.get("resource_group", "")
            account_name    = check.resource_id or ""

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

    async def _rollback_storage_https(
        self, check: ComplianceCheck, resource_data: dict[str, Any]
    ) -> dict[str, Any]:
        try:
            from azure.identity import DefaultAzureCredential
            from azure.mgmt.storage import StorageManagementClient

            credential      = DefaultAzureCredential()
            subscription_id = settings.azure_subscription_id
            resource_group  = resource_data.get("resource_group", "")
            account_name    = check.resource_id or ""

            client = StorageManagementClient(credential, subscription_id)
            client.storage_accounts.update(
                resource_group,
                account_name,
                {"enable_https_traffic_only": False},
            )
            return {
                "status":   "rolled_back",
                "action":   "azure_storage_https_disabled",
                "resource": account_name,
                "warning":  "HTTP traffic is now allowed on the storage account",
            }
        except Exception as e:
            return {"status": "error", "message": str(e)}

    async def _enforce_azure_sql_tde(
        self, check: ComplianceCheck, resource_data: dict[str, Any]
    ) -> dict[str, Any]:
        return {
            "status":   "flagged",
            "action":   "azure_sql_tde_required",
            "message":  "Enable TDE via: az sql db tde set --status Enabled. See runbook.",
            "resource": check.resource_id,
            "runbook":  load_runbook("azure-sql-tde-required"),
        }

    # -- GCP handlers ----------------------------------------------------------

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

    async def _rollback_gcs_public_access(
        self, check: ComplianceCheck, resource_data: dict[str, Any]
    ) -> dict[str, Any]:
        try:
            from google.cloud import storage as gcs

            client      = gcs.Client()
            bucket_name = check.resource_id or ""
            bucket      = client.bucket(bucket_name)

            # Disable uniform bucket-level access
            bucket.iam_configuration.uniform_bucket_level_access_enabled = False
            bucket.patch()

            return {
                "status":   "rolled_back",
                "action":   "gcs_uniform_access_disabled",
                "resource": bucket_name,
                "warning":  "ACL-based public access is now possible",
            }
        except Exception as e:
            return {"status": "error", "message": str(e)}

    async def _flag_gcp_sql_ssl(
        self, check: ComplianceCheck, resource_data: dict[str, Any]
    ) -> dict[str, Any]:
        return {
            "status":   "flagged",
            "action":   "gcp_sql_ssl_required",
            "message":  "Require SSL: gcloud sql instances patch <name> --require-ssl. See runbook.",
            "resource": check.resource_id,
            "runbook":  load_runbook("gcp-sql-ssl-required"),
        }


# -- Standalone helper called by workflow_engine.py ----------------------------

async def execute_remediation_action(
    action_type: str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    """
    Entry point called by the approval workflow engine when a request is executed.

    Dispatches based on action_type:
      - "remediation"    -> run RemediationEngine via rule_id + resource_id in payload
      - "policy_change"  -> acknowledged; no automated action
      - "account_delete" -> acknowledged; no automated action
      - "mfa_bypass"     -> acknowledged; no automated action
      - anything else    -> returns a summary of the payload for audit purposes
    """
    logger.info("Workflow execute_remediation_action called", action_type=action_type)

    if action_type == "remediation":
        rule_id     = payload.get("rule_id", "")
        resource_id = payload.get("resource_id", "")
        org_id      = payload.get("org_id")
        dry_run     = payload.get("dry_run", True)  # default safe

        if not rule_id:
            return {
                "status":  "skipped",
                "message": "No rule_id in payload - nothing to remediate.",
                "payload": payload,
            }

        engine = RemediationEngine(dry_run=dry_run)
        return await engine.execute_rollback(
            rule_id=rule_id,
            resource_id=resource_id,
            org_id=org_id,
        )

    acknowledged_types = {"policy_change", "account_delete", "mfa_bypass"}
    if action_type in acknowledged_types:
        return {
            "status":      "acknowledged",
            "action_type": action_type,
            "message":     f"Action '{action_type}' recorded. Manual follow-up required.",
            "payload":     payload,
        }

    return {
        "status":      "completed",
        "action_type": action_type,
        "message":     f"Workflow action '{action_type}' executed.",
        "payload":     payload,
    }
