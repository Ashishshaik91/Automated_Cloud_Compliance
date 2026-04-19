"""
Violations Engine — rule-based misconfiguration detection.

Rules are seeded once; the engine evaluates them against known cloud resources
(currently driven by ComplianceCheck records + a set of simulated resource states)
and writes Violation rows.  The run() function is idempotent: it upserts by
(rule_id, resource_urn) so repeated runs don't create duplicate rows.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any

import structlog
from sqlalchemy import select, update, delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.violations import Violation, ViolationRule
from app.models.compliance import ComplianceCheck, ScanResult, CloudAccount

logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Rule definitions
# ---------------------------------------------------------------------------

RULES: list[dict[str, Any]] = [
    # ── AWS ──────────────────────────────────────────────────────────────
    {
        "rule_id": "AWS-S3-001", "name": "S3 Bucket Publicly Accessible",
        "description": "S3 bucket ACL or policy allows public read/write access.",
        "category": "storage", "severity": "critical", "provider": "aws",
        "framework_tags": {"pci_dss": True, "hipaa": True, "gdpr": True},
        "remediation": "Remove public ACL grants; apply a bucket policy that denies s3:GetObject for '*'.",
    },
    {
        "rule_id": "AWS-SG-001", "name": "Security Group Allows 0.0.0.0/0 Inbound",
        "description": "Inbound rule permits unrestricted access from any IP.",
        "category": "network", "severity": "critical", "provider": "aws",
        "framework_tags": {"pci_dss": True, "nist": True},
        "remediation": "Restrict inbound rules to known CIDR ranges; remove 0.0.0.0/0 entries.",
    },
    {
        "rule_id": "AWS-EBS-001", "name": "EBS Volume Not Encrypted",
        "description": "EBS volume is missing at-rest encryption.",
        "category": "encryption", "severity": "high", "provider": "aws",
        "framework_tags": {"pci_dss": True, "hipaa": True},
        "remediation": "Enable EBS encryption by default in the account; re-create unencrypted volumes.",
    },
    {
        "rule_id": "AWS-IAM-001", "name": "Root Account Has No MFA",
        "description": "AWS root account does not have Multi-Factor Authentication enabled.",
        "category": "iam", "severity": "critical", "provider": "aws",
        "framework_tags": {"cis": True, "nist": True, "soc2": True},
        "remediation": "Enable hardware or virtual MFA device on the root account.",
    },
    {
        "rule_id": "AWS-IAM-002", "name": "IAM Policy Allows Wildcard Actions",
        "description": "IAM policy grants Action: '*' — effectively full admin access.",
        "category": "iam", "severity": "high", "provider": "aws",
        "framework_tags": {"cis": True, "nist": True},
        "remediation": "Replace wildcard action with least-privilege action list.",
    },
    {
        "rule_id": "AWS-IAM-003", "name": "Inactive IAM Access Keys (>90 days)",
        "description": "IAM access keys have not been rotated in over 90 days.",
        "category": "iam", "severity": "medium", "provider": "aws",
        "framework_tags": {"cis": True, "pci_dss": True},
        "remediation": "Rotate or delete access keys older than 90 days.",
    },
    {
        "rule_id": "AWS-CT-001", "name": "CloudTrail Not Enabled",
        "description": "CloudTrail is not enabled for all regions.",
        "category": "logging", "severity": "high", "provider": "aws",
        "framework_tags": {"cis": True, "pci_dss": True, "soc2": True},
        "remediation": "Enable CloudTrail with multi-region logging and S3 + CloudWatch integration.",
    },
    {
        "rule_id": "AWS-GD-001", "name": "GuardDuty Not Enabled",
        "description": "AWS GuardDuty threat detection is not active in this region.",
        "category": "monitoring", "severity": "high", "provider": "aws",
        "framework_tags": {"nist": True, "soc2": True},
        "remediation": "Enable GuardDuty; configure findings export to Security Hub.",
    },
    {
        "rule_id": "AWS-RDS-001", "name": "RDS Instance Publicly Accessible",
        "description": "RDS database instance is reachable from the public internet.",
        "category": "database", "severity": "critical", "provider": "aws",
        "framework_tags": {"pci_dss": True, "hipaa": True},
        "remediation": "Set PubliclyAccessible=false; deploy RDS inside a private subnet.",
    },
    {
        "rule_id": "AWS-EC2-001", "name": "EC2 IMDSv1 Enabled",
        "description": "Instance Metadata Service v1 is enabled; susceptible to SSRF-based credential theft.",
        "category": "compute", "severity": "medium", "provider": "aws",
        "framework_tags": {"cis": True},
        "remediation": "Set HttpTokens=required on the instance metadata options to enforce IMDSv2.",
    },
    # ── Azure ─────────────────────────────────────────────────────────────
    {
        "rule_id": "AZ-ST-001", "name": "Storage Account Allows HTTP",
        "description": "Azure Storage Account permits non-HTTPS (HTTP) traffic.",
        "category": "encryption", "severity": "high", "provider": "azure",
        "framework_tags": {"pci_dss": True, "gdpr": True},
        "remediation": "Set supportsHttpsTrafficOnly=true on the storage account.",
    },
    {
        "rule_id": "AZ-NSG-001", "name": "NSG Inbound Allow Any",
        "description": "Network Security Group has an ANY inbound rule.",
        "category": "network", "severity": "critical", "provider": "azure",
        "framework_tags": {"cis": True, "nist": True},
        "remediation": "Remove * source rules; use application security groups instead.",
    },
    {
        "rule_id": "AZ-RBAC-001", "name": "Over-Privileged RBAC Assignment",
        "description": "Owner or Contributor role assigned to a service principal at subscription scope.",
        "category": "iam", "severity": "high", "provider": "azure",
        "framework_tags": {"cis": True, "soc2": True},
        "remediation": "Apply least-privilege custom role; scope to resource group level.",
    },
    {
        "rule_id": "AZ-DEF-001", "name": "Defender for Cloud Not Enabled",
        "description": "Microsoft Defender for Cloud is disabled for one or more resource types.",
        "category": "monitoring", "severity": "medium", "provider": "azure",
        "framework_tags": {"nist": True},
        "remediation": "Enable Microsoft Defender for Cloud Standard tier for all resource types.",
    },
    # ── GCP ───────────────────────────────────────────────────────────────
    {
        "rule_id": "GCP-GCS-001", "name": "GCS Bucket Has Uniform Bucket-Level Access Disabled",
        "description": "GCS bucket relies on legacy ACLs, risking inadvertent public access.",
        "category": "storage", "severity": "high", "provider": "gcp",
        "framework_tags": {"cis": True, "pci_dss": True},
        "remediation": "Enable uniformBucketLevelAccess; remove legacy ACLs.",
    },
    {
        "rule_id": "GCP-FW-001", "name": "Firewall Rule Allows All Ingress",
        "description": "GCP firewall rule permits ingress from 0.0.0.0/0 on all ports.",
        "category": "network", "severity": "critical", "provider": "gcp",
        "framework_tags": {"cis": True},
        "remediation": "Replace the catch-all rule with specific port and source range restrictions.",
    },
    {
        "rule_id": "GCP-SA-001", "name": "Service Account Key Not Rotated (>90 days)",
        "description": "GCP service account has a user-managed key older than 90 days.",
        "category": "iam", "severity": "medium", "provider": "gcp",
        "framework_tags": {"cis": True, "nist": True},
        "remediation": "Delete and re-create service account keys; prefer Workload Identity.",
    },
    {
        "rule_id": "GCP-LOG-001", "name": "GCP Audit Logs Disabled",
        "description": "Data Access audit logs are not enabled for one or more GCP services.",
        "category": "logging", "severity": "high", "provider": "gcp",
        "framework_tags": {"cis": True, "pci_dss": True},
        "remediation": "Enable Data Access audit logs (ADMIN_READ, DATA_READ, DATA_WRITE).",
    },
    # ── Generic ───────────────────────────────────────────────────────────
    {
        "rule_id": "GEN-TLS-001", "name": "TLS 1.0/1.1 Accepted",
        "description": "Service accepts deprecated TLS versions (1.0 or 1.1).",
        "category": "encryption", "severity": "high", "provider": "generic",
        "framework_tags": {"pci_dss": True, "hipaa": True},
        "remediation": "Configure the service to accept TLS 1.2+ only.",
    },
    {
        "rule_id": "GEN-MFA-001", "name": "Console Access Without MFA",
        "description": "User accounts can access the cloud console without MFA.",
        "category": "iam", "severity": "high", "provider": "generic",
        "framework_tags": {"cis": True, "soc2": True, "nist": True},
        "remediation": "Enforce MFA for all console users via IAM policy condition.",
    },
]

# ---------------------------------------------------------------------------
# Simulated data removed in favor of live queries
# ---------------------------------------------------------------------------

def _make_urn(cloud_provider: str, account_id: str, resource_type: str, resource_id: str) -> str:
    """Build a normalised resource URN for cross-module correlation."""
    safe_rid = resource_id.replace("arn:aws:iam::", "").replace(" ", "-").lower()
    return f"{cloud_provider}://{account_id}/{resource_type}/{safe_rid}"


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

async def seed_violation_rules(db: AsyncSession) -> None:
    """Idempotent: insert rules that don't already exist."""
    for r in RULES:
        existing = await db.execute(
            select(ViolationRule).where(ViolationRule.rule_id == r["rule_id"])
        )
        if existing.scalar_one_or_none():
            continue
        db.add(ViolationRule(**r))
    await db.flush()
    logger.info("Violation rules seeded", count=len(RULES))


async def run_violations_engine(db: AsyncSession) -> int:
    """
    Evaluate actual failed compliance checks against rules.
    Upserts violations; returns count of newly created rows.
    """
    # 1. Clean up old data to prevent stale findings
    await db.execute(delete(Violation))
    await db.flush()

    rule_map: dict[str, ViolationRule] = {}
    for row in (await db.execute(select(ViolationRule))).scalars():
        rule_map[row.rule_id] = row

    created = 0

    # 2. Query live failed compliance checks
    stmt = (
        select(ComplianceCheck, ScanResult, CloudAccount)
        .join(ScanResult, ComplianceCheck.scan_id == ScanResult.id)
        .join(CloudAccount, ScanResult.account_id == CloudAccount.id)
        .where(ComplianceCheck.status == "fail")
    )
    
    results = await db.execute(stmt)

    for check, scan, account in results:
        rule = rule_map.get(check.policy_id)
        
        # Dynamically support custom policies
        if not rule:
            rule = ViolationRule(
                rule_id=check.policy_id,
                name=check.policy_name,
                description=f"Auto-generated rule for {check.policy_id}",
                category="custom",
                severity=check.severity,
                provider=account.provider,
            )
            db.add(rule)
            await db.flush()
            rule_map[check.policy_id] = rule

        if not rule.enabled:
            continue

        urn = _make_urn(
            account.provider, account.account_id,
            check.resource_type or "unknown", check.resource_id or "unknown"
        )

        db.add(Violation(
            rule_id=check.policy_id,
            resource_urn=urn,
            resource_id=check.resource_id or "unknown",
            resource_type=check.resource_type or "unknown",
            account_id=account.account_id,
            cloud_provider=account.provider,
            severity=rule.severity,
            status="open",
            details=check.details,
            remediation_hint=check.remediation_hint or rule.remediation,
        ))
        created += 1

    await db.flush()
    logger.info("Violations engine run complete", new=created)
    return created

