"""
Automated Remediation Module.

Executes policy-driven remediation actions for non-compliant resources.
All actions are logged with full audit trail. Dry-run mode available.
"""

from typing import Any

import structlog

from app.config import get_settings
from app.models.compliance import ComplianceCheck

settings = get_settings()
logger = structlog.get_logger(__name__)


class RemediationEngine:
    """
    Applies automated fix actions for identified compliance violations.
    Supports dry_run mode to preview actions without applying them.
    """

    # Maps (resource_type, policy_id) → remediation function name
    REMEDIATION_MAP: dict[tuple[str, str], str] = {
        ("s3_bucket", "s3-encryption-required"): "_enable_s3_encryption",
        ("s3_bucket", "s3-public-access-blocked"): "_block_s3_public_access",
        ("s3_bucket", "s3-versioning-required"): "_enable_s3_versioning",
        ("iam_user", "iam-mfa-required"): "_flag_iam_mfa_missing",
        ("cloudtrail", "cloudtrail-logging-enabled"): "_enable_cloudtrail",
        ("rds_instance", "rds-encryption-required"): "_flag_rds_unencrypted",
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
                "status": "dry_run",
                "action": handler_name,
                "resource_id": check.resource_id,
                "message": f"Would execute: {handler_name}",
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
        # Cannot auto-enable MFA for users — flag for human review
        return {
            "status": "flagged",
            "action": "mfa_enforcement_required",
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
        # RDS encryption cannot be enabled on existing instances — flag for recreation
        return {
            "status": "flagged",
            "action": "rds_recreation_required",
            "message": "RDS encryption requires instance recreation. Manual action required.",
            "resource": check.resource_id,
        }
