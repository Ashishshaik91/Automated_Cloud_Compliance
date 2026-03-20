import pytest
from unittest.mock import AsyncMock, patch, MagicMock

from app.connectors.aws_connector import AWSConnector
from app.connectors.azure_connector import AzureConnector
from app.connectors.gcp_connector import GCPConnector

# Test AWS Connector
@patch("app.connectors.aws_connector.boto3.Session")
async def test_aws_connector_collect_evidence(mock_session):
    mock_client = MagicMock()
    mock_session_instance = mock_session.return_value
    mock_session_instance.client.return_value = mock_client
    
    connector = AWSConnector(credentials={"aws_access_key_id": "test", "aws_secret_access_key": "test"}, region="us-east-1")
    
    # Needs to be tested but collect_evidence uses async gathering
    # Since AWS connector collect_evidence calls multiple methods, we just mock the inner ones or await it
    with patch.object(connector, "_check_s3_encryption", return_value=[]) as mock_s3:
        with patch.object(connector, "_check_iam_mfa", return_value=[]) as mock_iam:
            with patch.object(connector, "_check_vpc_flow_logs", return_value=[]) as mock_vpc:
                results = await connector.collect_evidence()
                assert isinstance(results, list)
                mock_s3.assert_awaited()

# Test Azure Connector
@patch("app.connectors.azure_connector.InteractiveBrowserCredential")
async def test_azure_connector_collect_evidence(mock_cred):
    mock_cred_instance = mock_cred.return_value
    
    connector = AzureConnector(credentials={"tenant_id": "test", "client_id": "test", "client_secret": "test"})
    
    with patch.object(connector, "_check_storage_encryption", return_value=[]) as mock_storage:
        with patch.object(connector, "_check_key_vault_logging", return_value=[]) as mock_vault:
            with patch.object(connector, "_check_network_security_groups", return_value=[]) as mock_nsg:
                results = await connector.collect_evidence()
                assert isinstance(results, list)

# Test GCP Connector
@patch("app.connectors.gcp_connector.compute_v1.InstancesClient")
@patch("app.connectors.gcp_connector.storage.Client")
async def test_gcp_connector_collect_evidence(mock_storage_client, mock_compute_client):
    connector = GCPConnector(credentials={"project_id": "test", "service_account_path": "/dev/null"})
    
    with patch.object(connector, "_check_storage_buckets", return_value=[]) as mock_storage:
        with patch.object(connector, "_check_compute_instances", return_value=[]) as mock_compute:
            with patch.object(connector, "_check_iam_policies", return_value=[]) as mock_iam:
                results = await connector.collect_evidence()
                assert isinstance(results, list)
