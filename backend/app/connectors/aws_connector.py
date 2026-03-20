"""
AWS Cloud Connector.
Uses boto3 to enumerate AWS resources for compliance checking.
Credentials are read from environment variables (never hardcoded).
Supports: S3, IAM, EC2, RDS, CloudTrail, GuardDuty, SecurityHub.
"""

import asyncio
from functools import cached_property
from typing import Any

import boto3
import structlog
from botocore.exceptions import BotoCoreError, ClientError

from app.config import get_settings
from app.connectors.base import CloudConnectorBase
from app.models.compliance import CloudAccount

settings = get_settings()
logger = structlog.get_logger(__name__)


class AWSConnector(CloudConnectorBase):
    """Enumerates AWS resources and checks them for compliance."""

    def __init__(self, account: CloudAccount) -> None:
        super().__init__(account)

    @cached_property
    def session(self) -> boto3.Session:
        """Create a boto3 session using environment credentials or assumed role."""
        if settings.aws_role_arn:
            sts = boto3.client(
                "sts",
                aws_access_key_id=settings.aws_access_key_id or None,
                aws_secret_access_key=settings.aws_secret_access_key.get_secret_value() or None,
                region_name=self.region,
            )
            creds = sts.assume_role(
                RoleArn=settings.aws_role_arn,
                RoleSessionName="CompliancePlatformSession",
            )["Credentials"]
            return boto3.Session(
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"],
                region_name=self.region,
            )
        return boto3.Session(
            aws_access_key_id=settings.aws_access_key_id or None,
            aws_secret_access_key=settings.aws_secret_access_key.get_secret_value() or None,
            region_name=self.region,
        )

    def _client(self, service: str):
        return self.session.client(service, region_name=self.region)

    async def enumerate_resources(self, framework: str) -> list[dict[str, Any]]:
        """Enumerate relevant AWS resources for the given framework."""
        loop = asyncio.get_event_loop()

        tasks = [
            loop.run_in_executor(None, self._get_s3_buckets),
            loop.run_in_executor(None, self._get_iam_users),
            loop.run_in_executor(None, self._get_ec2_instances),
            loop.run_in_executor(None, self._get_rds_instances),
            loop.run_in_executor(None, self._get_cloudtrail_status),
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        resources: list[dict[str, Any]] = []
        for r in results:
            if isinstance(r, Exception):
                logger.error("AWS resource enumeration error", error=str(r))
            else:
                resources.extend(r)  # type: ignore[arg-type]
        return resources

    async def get_resource_config(self, resource_id: str, resource_type: str) -> dict[str, Any]:
        """Fetch config for a single resource."""
        if resource_type == "s3_bucket":
            return self._get_s3_bucket_config(resource_id)
        return {}

    def _get_s3_buckets(self) -> list[dict[str, Any]]:
        """List S3 buckets and their security configuration."""
        try:
            s3 = self._client("s3")
            buckets = s3.list_buckets().get("Buckets", [])
            resources = []
            for bucket in buckets:
                name = bucket["Name"]
                config = self._get_s3_bucket_config(name)
                resources.append(
                    self._normalize_resource(config, "s3_bucket", name)
                )
            return resources
        except (BotoCoreError, ClientError) as e:
            logger.error("S3 enumeration failed", error=str(e))
            return []

    def _get_s3_bucket_config(self, bucket_name: str) -> dict[str, Any]:
        s3 = self._client("s3")
        config: dict[str, Any] = {"bucket_name": bucket_name}
        # Encryption
        try:
            enc = s3.get_bucket_encryption(Bucket=bucket_name)
            config["encryption_enabled"] = True
            config["encryption_rules"] = enc.get("ServerSideEncryptionConfiguration", {})
        except ClientError:
            config["encryption_enabled"] = False
        # Public access block
        try:
            pub = s3.get_public_access_block(Bucket=bucket_name)
            pub_cfg = pub.get("PublicAccessBlockConfiguration", {})
            config["public_access_blocked"] = all([
                pub_cfg.get("BlockPublicAcls", False),
                pub_cfg.get("BlockPublicPolicy", False),
                pub_cfg.get("IgnorePublicAcls", False),
                pub_cfg.get("RestrictPublicBuckets", False),
            ])
        except ClientError:
            config["public_access_blocked"] = False
        # Versioning
        try:
            ver = s3.get_bucket_versioning(Bucket=bucket_name)
            config["versioning_enabled"] = ver.get("Status") == "Enabled"
        except ClientError:
            config["versioning_enabled"] = False
        return config

    def _get_iam_users(self) -> list[dict[str, Any]]:
        """List IAM users and their security properties."""
        try:
            iam = self._client("iam")
            paginator = iam.get_paginator("list_users")
            resources = []
            for page in paginator.paginate():
                for user in page.get("Users", []):
                    # Check MFA
                    mfa_devices = iam.list_mfa_devices(UserName=user["UserName"])
                    has_mfa = len(mfa_devices.get("MFADevices", [])) > 0
                    # Check access keys age
                    keys = iam.list_access_keys(UserName=user["UserName"])
                    active_keys = [
                        k for k in keys.get("AccessKeyMetadata", [])
                        if k["Status"] == "Active"
                    ]
                    config = {
                        "username": user["UserName"],
                        "mfa_enabled": has_mfa,
                        "active_key_count": len(active_keys),
                        "created_at": str(user.get("CreateDate", "")),
                    }
                    resources.append(
                        self._normalize_resource(config, "iam_user", user["UserName"])
                    )
            return resources
        except (BotoCoreError, ClientError) as e:
            logger.error("IAM enumeration failed", error=str(e))
            return []

    def _get_ec2_instances(self) -> list[dict[str, Any]]:
        """List EC2 instances and their security configuration."""
        try:
            ec2 = self._client("ec2")
            reservations = ec2.describe_instances().get("Reservations", [])
            resources = []
            for res in reservations:
                for inst in res.get("Instances", []):
                    config = {
                        "instance_id": inst["InstanceId"],
                        "state": inst["State"]["Name"],
                        "public_ip": inst.get("PublicIpAddress"),
                        "is_public": bool(inst.get("PublicIpAddress")),
                        "ebs_optimized": inst.get("EbsOptimized", False),
                        "monitoring_enabled": inst.get("Monitoring", {}).get("State") == "enabled",
                    }
                    resources.append(
                        self._normalize_resource(config, "ec2_instance", inst["InstanceId"])
                    )
            return resources
        except (BotoCoreError, ClientError) as e:
            logger.error("EC2 enumeration failed", error=str(e))
            return []

    def _get_rds_instances(self) -> list[dict[str, Any]]:
        """List RDS instances and security settings."""
        try:
            rds = self._client("rds")
            dbs = rds.describe_db_instances().get("DBInstances", [])
            resources = []
            for db in dbs:
                config = {
                    "db_id": db["DBInstanceIdentifier"],
                    "engine": db["Engine"],
                    "publicly_accessible": db.get("PubliclyAccessible", True),
                    "storage_encrypted": db.get("StorageEncrypted", False),
                    "deletion_protection": db.get("DeletionProtection", False),
                    "multi_az": db.get("MultiAZ", False),
                    "auto_minor_version_upgrade": db.get("AutoMinorVersionUpgrade", True),
                }
                resources.append(
                    self._normalize_resource(config, "rds_instance", db["DBInstanceIdentifier"])
                )
            return resources
        except (BotoCoreError, ClientError) as e:
            logger.error("RDS enumeration failed", error=str(e))
            return []

    def _get_cloudtrail_status(self) -> list[dict[str, Any]]:
        """Check CloudTrail configuration for auditing compliance."""
        try:
            ct = self._client("cloudtrail")
            trails = ct.describe_trails().get("trailList", [])
            resources = []
            for trail in trails:
                status = ct.get_trail_status(Name=trail["TrailARN"])
                config = {
                    "trail_name": trail["Name"],
                    "is_logging": status.get("IsLogging", False),
                    "multi_region": trail.get("IsMultiRegionTrail", False),
                    "log_file_validation": trail.get("LogFileValidationEnabled", False),
                    "s3_bucket": trail.get("S3BucketName", ""),
                    "include_global_service_events": trail.get("IncludeGlobalServiceEvents", False),
                }
                resources.append(
                    self._normalize_resource(config, "cloudtrail", trail["Name"])
                )
            return resources
        except (BotoCoreError, ClientError) as e:
            logger.error("CloudTrail enumeration failed", error=str(e))
            return []
