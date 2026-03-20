"""
Targeted AWS Connector internal method tests.
These test the private _get_* methods directly using mocked boto3 clients.
"""
import pytest
from unittest.mock import MagicMock, patch, AsyncMock


def make_account(provider="aws", region="us-east-1"):
    account = MagicMock()
    account.provider = provider
    account.region = region
    account.name = "test-account"
    account.id = 1
    return account


class TestAWSConnectorInternals:

    def _make_connector(self):
        from app.connectors.aws_connector import AWSConnector
        account = make_account()
        with patch("app.connectors.aws_connector.boto3.Session"):
            connector = AWSConnector(account)
        return connector

    def test_get_s3_buckets_success(self):
        connector = self._make_connector()
        mock_s3 = MagicMock()
        mock_s3.list_buckets.return_value = {"Buckets": [{"Name": "test-bucket"}]}
        mock_s3.get_bucket_encryption.return_value = {
            "ServerSideEncryptionConfiguration": {"Rules": []}
        }
        mock_s3.get_public_access_block.return_value = {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "BlockPublicPolicy": True,
                "IgnorePublicAcls": True,
                "RestrictPublicBuckets": True,
            }
        }
        mock_s3.get_bucket_versioning.return_value = {"Status": "Enabled"}

        with patch.object(connector, "_client", return_value=mock_s3):
            result = connector._get_s3_buckets()

        assert len(result) == 1
        assert result[0]["encryption_enabled"] is True
        assert result[0]["versioning_enabled"] is True

    def test_get_s3_buckets_client_error(self):
        from botocore.exceptions import ClientError
        connector = self._make_connector()
        mock_s3 = MagicMock()
        mock_s3.list_buckets.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Denied"}}, "ListBuckets"
        )
        with patch.object(connector, "_client", return_value=mock_s3):
            result = connector._get_s3_buckets()
        assert result == []

    def test_get_s3_bucket_config_encryption_error(self):
        from botocore.exceptions import ClientError
        connector = self._make_connector()
        mock_s3 = MagicMock()
        mock_s3.get_bucket_encryption.side_effect = ClientError(
            {"Error": {"Code": "ServerSideEncryptionConfigurationNotFoundError", "Message": ""}}, "GetBucketEncryption"
        )
        mock_s3.get_public_access_block.side_effect = ClientError(
            {"Error": {"Code": "NoSuchPublicAccessBlockConfiguration", "Message": ""}}, "GetPublicAccessBlock"
        )
        mock_s3.get_bucket_versioning.side_effect = ClientError(
            {"Error": {"Code": "NoSuchBucketPolicy", "Message": ""}}, "GetBucketVersioning"
        )
        with patch.object(connector, "_client", return_value=mock_s3):
            config = connector._get_s3_bucket_config("test-bucket")
        assert config["encryption_enabled"] is False
        assert config["public_access_blocked"] is False
        assert config["versioning_enabled"] is False

    def test_get_iam_users_success(self):
        connector = self._make_connector()
        mock_iam = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [
            {"Users": [{"UserName": "alice", "CreateDate": "2023-01-01"}]}
        ]
        mock_iam.get_paginator.return_value = paginator
        mock_iam.list_mfa_devices.return_value = {"MFADevices": [{"SerialNumber": "arn:aws:iam::123:mfa/alice"}]}
        mock_iam.list_access_keys.return_value = {
            "AccessKeyMetadata": [{"AccessKeyId": "AKID1", "Status": "Active"}]
        }
        with patch.object(connector, "_client", return_value=mock_iam):
            result = connector._get_iam_users()
        assert len(result) == 1
        assert result[0]["mfa_enabled"] is True

    def test_get_iam_users_client_error(self):
        from botocore.exceptions import ClientError
        connector = self._make_connector()
        mock_iam = MagicMock()
        mock_iam.get_paginator.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Denied"}}, "GetPaginator"
        )
        with patch.object(connector, "_client", return_value=mock_iam):
            result = connector._get_iam_users()
        assert result == []

    def test_get_ec2_instances_success(self):
        connector = self._make_connector()
        mock_ec2 = MagicMock()
        mock_ec2.describe_instances.return_value = {
            "Reservations": [{
                "Instances": [{
                    "InstanceId": "i-123",
                    "State": {"Name": "running"},
                    "EbsOptimized": True,
                    "Monitoring": {"State": "enabled"},
                }]
            }]
        }
        with patch.object(connector, "_client", return_value=mock_ec2):
            result = connector._get_ec2_instances()
        assert len(result) == 1
        assert result[0]["monitoring_enabled"] is True

    def test_get_ec2_instances_client_error(self):
        from botocore.exceptions import ClientError
        connector = self._make_connector()
        mock_ec2 = MagicMock()
        mock_ec2.describe_instances.side_effect = ClientError(
            {"Error": {"Code": "UnauthorizedOperation", "Message": "Denied"}}, "DescribeInstances"
        )
        with patch.object(connector, "_client", return_value=mock_ec2):
            result = connector._get_ec2_instances()
        assert result == []

    def test_get_rds_instances_success(self):
        connector = self._make_connector()
        mock_rds = MagicMock()
        mock_rds.describe_db_instances.return_value = {
            "DBInstances": [{
                "DBInstanceIdentifier": "mydb",
                "Engine": "mysql",
                "PubliclyAccessible": False,
                "StorageEncrypted": True,
                "DeletionProtection": True,
                "MultiAZ": True,
                "AutoMinorVersionUpgrade": True,
            }]
        }
        with patch.object(connector, "_client", return_value=mock_rds):
            result = connector._get_rds_instances()
        assert len(result) == 1
        assert result[0]["storage_encrypted"] is True

    def test_get_rds_instances_client_error(self):
        from botocore.exceptions import ClientError
        connector = self._make_connector()
        mock_rds = MagicMock()
        mock_rds.describe_db_instances.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Denied"}}, "DescribeDBInstances"
        )
        with patch.object(connector, "_client", return_value=mock_rds):
            result = connector._get_rds_instances()
        assert result == []

    def test_get_cloudtrail_status_success(self):
        connector = self._make_connector()
        mock_ct = MagicMock()
        mock_ct.describe_trails.return_value = {
            "trailList": [{
                "Name": "my-trail",
                "TrailARN": "arn:aws:cloudtrail:us-east-1:123:trail/my-trail",
                "IsMultiRegionTrail": True,
                "LogFileValidationEnabled": True,
                "S3BucketName": "my-bucket",
                "IncludeGlobalServiceEvents": True,
            }]
        }
        mock_ct.get_trail_status.return_value = {"IsLogging": True}
        with patch.object(connector, "_client", return_value=mock_ct):
            result = connector._get_cloudtrail_status()
        assert len(result) == 1
        assert result[0]["is_logging"] is True

    def test_get_cloudtrail_client_error(self):
        from botocore.exceptions import ClientError
        connector = self._make_connector()
        mock_ct = MagicMock()
        mock_ct.describe_trails.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Denied"}}, "DescribeTrails"
        )
        with patch.object(connector, "_client", return_value=mock_ct):
            result = connector._get_cloudtrail_status()
        assert result == []

    @pytest.mark.asyncio
    async def test_enumerate_resources(self):
        connector = self._make_connector()
        with patch.object(connector, "_get_s3_buckets", return_value=[{"type": "s3_bucket"}]):
            with patch.object(connector, "_get_iam_users", return_value=[]):
                with patch.object(connector, "_get_ec2_instances", return_value=[]):
                    with patch.object(connector, "_get_rds_instances", return_value=[]):
                        with patch.object(connector, "_get_cloudtrail_status", return_value=[]):
                            result = await connector.enumerate_resources("pci_dss")
        assert len(result) == 1

    @pytest.mark.asyncio
    async def test_get_resource_config_s3(self):
        connector = self._make_connector()
        mock_s3 = MagicMock()
        mock_s3.get_bucket_encryption.return_value = {"ServerSideEncryptionConfiguration": {}}
        mock_s3.get_public_access_block.return_value = {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True, "BlockPublicPolicy": True,
                "IgnorePublicAcls": True, "RestrictPublicBuckets": True,
            }
        }
        mock_s3.get_bucket_versioning.return_value = {"Status": "Enabled"}
        with patch.object(connector, "_client", return_value=mock_s3):
            result = await connector.get_resource_config("my-bucket", "s3_bucket")
        assert result["encryption_enabled"] is True

    @pytest.mark.asyncio
    async def test_get_resource_config_unknown(self):
        connector = self._make_connector()
        result = await connector.get_resource_config("something", "unknown_type")
        assert result == {}
