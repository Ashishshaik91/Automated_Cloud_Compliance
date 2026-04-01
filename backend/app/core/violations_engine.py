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
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.violations import Violation, ViolationRule

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
# Simulated resource states — drives which violations fire
# ---------------------------------------------------------------------------

_SIMULATED_VIOLATIONS: list[dict[str, Any]] = [
    # S3 public bucket
    {"rule_id": "AWS-S3-001",  "resource_id": "pii-production-lake",  "resource_type": "s3",
     "account_id": "123456789012", "cloud_provider": "aws",
     "details": {"acl": "public-read", "region": "us-east-1"}},
    {"rule_id": "AWS-S3-001",  "resource_id": "analytics-public-exports", "resource_type": "s3",
     "account_id": "123456789012", "cloud_provider": "aws",
     "details": {"policy": "PublicRead", "region": "us-west-2"}},
    # Open security group
    {"rule_id": "AWS-SG-001",  "resource_id": "sg-0a1b2c3d4e5f6a7b8", "resource_type": "security_group",
     "account_id": "123456789012", "cloud_provider": "aws",
     "details": {"port": "0-65535", "cidr": "0.0.0.0/0"}},
    # Unencrypted EBS
    {"rule_id": "AWS-EBS-001", "resource_id": "vol-0123456789abcdef0", "resource_type": "ebs_volume",
     "account_id": "123456789012", "cloud_provider": "aws",
     "details": {"size_gb": 500, "region": "eu-west-1"}},
    # Root no MFA
    {"rule_id": "AWS-IAM-001", "resource_id": "root",                  "resource_type": "iam_root",
     "account_id": "123456789012", "cloud_provider": "aws",
     "details": {"mfa_enabled": False}},
    # Wildcard IAM
    {"rule_id": "AWS-IAM-002", "resource_id": "arn:aws:iam::123456789012:policy/DevFullAccess",
     "resource_type": "iam_policy", "account_id": "123456789012", "cloud_provider": "aws",
     "details": {"action": "*", "resource": "*"}},
    # Stale IAM key
    {"rule_id": "AWS-IAM-003", "resource_id": "AKIAIOSFODNN7EXAMPLE", "resource_type": "iam_access_key",
     "account_id": "123456789012", "cloud_provider": "aws",
     "details": {"days_since_rotation": 127, "username": "deploy-bot"}},
    # CloudTrail off
    {"rule_id": "AWS-CT-001",  "resource_id": "cloudtrail-eu-west-1",  "resource_type": "cloudtrail",
     "account_id": "123456789012", "cloud_provider": "aws",
     "details": {"region": "eu-west-1", "enabled": False}},
    # GuardDuty off
    {"rule_id": "AWS-GD-001",  "resource_id": "guardduty-ap-southeast-1", "resource_type": "guardduty",
     "account_id": "123456789012", "cloud_provider": "aws",
     "details": {"region": "ap-southeast-1", "status": "disabled"}},
    # Public RDS
    {"rule_id": "AWS-RDS-001", "resource_id": "prod-db-mysql",         "resource_type": "rds_instance",
     "account_id": "123456789012", "cloud_provider": "aws",
     "details": {"engine": "mysql", "publicly_accessible": True}},
    # IMDSv1
    {"rule_id": "AWS-EC2-001", "resource_id": "i-0abcdef1234567890",   "resource_type": "ec2_instance",
     "account_id": "123456789012", "cloud_provider": "aws",
     "details": {"imds_version": "v1", "instance_type": "t3.large"}},
    # Azure HTTP storage
    {"rule_id": "AZ-ST-001",   "resource_id": "stgaccountprodeurwest",  "resource_type": "az_storage",
     "account_id": "sub-0001-prod", "cloud_provider": "azure",
     "details": {"https_only": False}},
    # Azure NSG
    {"rule_id": "AZ-NSG-001",  "resource_id": "nsg-prod-frontend",     "resource_type": "az_nsg",
     "account_id": "sub-0001-prod", "cloud_provider": "azure",
     "details": {"rule": "AllowAnyInbound", "priority": 100}},
    # GCP public GCS
    {"rule_id": "GCP-GCS-001", "resource_id": "gcs-ml-training-data",  "resource_type": "gcs_bucket",
     "account_id": "proj-frontend-prod", "cloud_provider": "gcp",
     "details": {"iam_public": True, "uniform_access": False}},
    # GCP firewall open
    {"rule_id": "GCP-FW-001",  "resource_id": "fw-allow-all-ingress",  "resource_type": "gcp_firewall",
     "account_id": "proj-frontend-prod", "cloud_provider": "gcp",
     "details": {"source_ranges": ["0.0.0.0/0"], "ports": ["all"]}},
    # Generic TLS
    {"rule_id": "GEN-TLS-001", "resource_id": "api.internal.corp",     "resource_type": "service_endpoint",
     "account_id": "corp-infra", "cloud_provider": "generic",
     "details": {"tls_versions": ["1.0", "1.1", "1.2"]}},
    # Generic MFA
    {"rule_id": "GEN-MFA-001", "resource_id": "console-access-policy",  "resource_type": "iam_policy",
     "account_id": "corp-infra", "cloud_provider": "generic",
     "details": {"mfa_required": False, "affected_users": 14}},
]


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
    Evaluate simulated resource states against rules.
    Upserts violations; returns count of newly created rows.
    """
    rule_map: dict[str, ViolationRule] = {}
    for r in RULES:
        row = (await db.execute(
            select(ViolationRule).where(ViolationRule.rule_id == r["rule_id"])
        )).scalar_one_or_none()
        if row:
            rule_map[r["rule_id"]] = row

    created = 0
    for v in _SIMULATED_VIOLATIONS:
        rule = rule_map.get(v["rule_id"])
        if not rule or not rule.enabled:
            continue

        urn = _make_urn(
            v["cloud_provider"], v.get("account_id", "unknown"),
            v["resource_type"], v["resource_id"]
        )

        existing = (await db.execute(
            select(Violation).where(Violation.resource_urn == urn)
        )).scalar_one_or_none()

        if existing:
            # Refresh detection timestamp so periodic runs update the record
            await db.execute(
                update(Violation)
                .where(Violation.resource_urn == urn)
                .values(detected_at=datetime.now(timezone.utc))
            )
            continue

        db.add(Violation(
            rule_id=v["rule_id"],
            resource_urn=urn,
            resource_id=v["resource_id"],
            resource_type=v["resource_type"],
            account_id=v.get("account_id"),
            cloud_provider=v["cloud_provider"],
            severity=rule.severity,
            status="open",
            details=v.get("details"),
            remediation_hint=rule.remediation,
        ))
        created += 1

    await db.flush()
    logger.info("Violations engine run complete", new=created, total=len(_SIMULATED_VIOLATIONS))
    return created
