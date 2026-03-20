import pytest
import json
from unittest.mock import AsyncMock, MagicMock, patch

from app.core.scanner import ScanOrchestrator, run_scheduled_scan
from app.models.compliance import CloudAccount, ScanResult, CloudProvider
from app.core.ingestion import IngestionPipeline

@pytest.mark.asyncio
async def test_scan_orchestrator_run_scan():
    mock_db = AsyncMock()
    mock_loader = MagicMock()
    mock_evidence = AsyncMock()
    
    orchestrator = ScanOrchestrator(mock_db, mock_loader, mock_evidence)
    
    account = CloudAccount(id=1, provider="aws", name="Test", account_id="123")
    
    # Mock connector
    mock_connector_cls = MagicMock()
    mock_connector_instance = AsyncMock()
    mock_connector_instance.enumerate_resources.return_value = [{"resource_type": "s3_bucket", "id": "bucket1"}]
    mock_connector_cls.return_value = mock_connector_instance
    
    # Mock engine
    orchestrator.engine.evaluate = AsyncMock(return_value=[{
        "status": "pass",
        "policy_id": "test_policy",
        "policy_name": "Test Policy",
        "resource_id": "bucket1",
        "resource_type": "s3_bucket",
        "severity": "high",
        "details": {},
        "remediation_hint": "Fix it"
    }])
    orchestrator.engine.close = AsyncMock()
    
    with patch("app.core.scanner.CONNECTOR_MAP", {"aws": mock_connector_cls}):
        result = await orchestrator.run_scan(account, "pci_dss")
        
    assert result.framework == "pci_dss"
    assert result.total_checks == 1
    assert result.passed_checks == 1
    assert result.failed_checks == 0
    assert result.compliance_score == 100.0

@pytest.mark.asyncio
async def test_scan_orchestrator_dry_run():
    mock_db = AsyncMock()
    mock_loader = MagicMock()
    mock_evidence = AsyncMock()
    
    orchestrator = ScanOrchestrator(mock_db, mock_loader, mock_evidence)
    account = CloudAccount(id=1, provider="aws", name="Test", account_id="123")
    
    # Use dry_run, check DB is not written
    mock_connector_cls = MagicMock()
    mock_connector_instance = AsyncMock()
    mock_connector_instance.enumerate_resources.return_value = []
    mock_connector_cls.return_value = mock_connector_instance
    
    orchestrator.engine.evaluate = AsyncMock(return_value=[])
    orchestrator.engine.close = AsyncMock()
    
    with patch("app.core.scanner.CONNECTOR_MAP", {"aws": mock_connector_cls}):
        result = await orchestrator.run_scan(account, "pci_dss", dry_run=True)
        
    assert result.total_checks == 0

@pytest.mark.asyncio
async def test_ingestion_pipeline_ingest_event():
    pipeline = IngestionPipeline()
    mock_client = AsyncMock()
    mock_client.xadd.return_value = "12345-0"
    
    pipeline._redis = mock_client
    
    entry_id = await pipeline.ingest_event({"source": "cloudtrail", "event_type": "ConsoleLogin"})
    assert entry_id == "12345-0"
    mock_client.xadd.assert_called_once()

@pytest.mark.asyncio
async def test_ingestion_pipeline_process_entry():
    pipeline = IngestionPipeline()
    payload = {"eventName": "DeleteBucket", "userIdentity": {"arn": "test"}}
    
    data = {
        "payload": json.dumps(payload),
        "source": "cloudtrail",
        "event_type": "DeleteBucket"
    }
    
    with patch.object(pipeline, "_process_cloudtrail_event") as mock_process:
        await pipeline._process_entry("123", data)
        mock_process.assert_called_once_with(payload)

def test_run_scheduled_scan_celery():
    with patch("app.core.scanner.asyncio.run") as mock_run:
        mock_run.return_value = {"scan_id": 1, "compliance_score": 100.0, "total_checks": 1}
        
        result = run_scheduled_scan(1, "pci_dss")
        assert result["scan_id"] == 1

def test_celery_app():
    from app.core.celery_app import celery_app
    assert celery_app is not None
    assert celery_app.conf.timezone == "UTC"

@pytest.mark.asyncio
@patch("boto3.client")
async def test_remediation_engine(mock_boto):
    from app.core.remediation import RemediationEngine
    engine = RemediationEngine(dry_run=True)
    
    check_mock = MagicMock()
    check_mock.policy_id = "s3-encryption-required"
    check_mock.resource_type = "s3_bucket"
    check_mock.resource_id = "test_bucket"
    
    result = await engine.remediate(check_mock, {})
    assert result["status"] == "dry_run"
    
    engine.dry_run = False
    result = await engine.remediate(check_mock, {})
    assert result["status"] == "applied"
    
    check_mock.policy_id = "unknown-policy"
    result = await engine.remediate(check_mock, {})
    assert result["status"] == "no_action"
    
    check_mock.policy_id = "s3-public-access-blocked"
    result = await engine.remediate(check_mock, {})
    assert result["status"] == "applied"

    check_mock.policy_id = "s3-versioning-required"
    result = await engine.remediate(check_mock, {})
    assert result["status"] == "applied"

    check_mock.policy_id = "iam-mfa-required"
    check_mock.resource_type = "iam_user"
    result = await engine.remediate(check_mock, {})
    assert result["status"] == "flagged"

    check_mock.policy_id = "cloudtrail-logging-enabled"
    check_mock.resource_type = "cloudtrail"
    result = await engine.remediate(check_mock, {})
    assert result["status"] == "applied"

    check_mock.policy_id = "rds-encryption-required"
    check_mock.resource_type = "rds_instance"
    result = await engine.remediate(check_mock, {})
    assert result["status"] == "flagged"
    
    check_mock.policy_id = "cloudtrail-logging-enabled"
    check_mock.resource_type = "cloudtrail"
    mock_boto.side_effect = Exception("AWS Error")
    result = await engine.remediate(check_mock, {})
    assert result["status"] == "error"

@pytest.mark.asyncio
@patch("app.core.scanner.AsyncSessionLocal")
async def test_async_scheduled_scan(mock_session_local):
    from app.core.scanner import _async_scheduled_scan
    mock_db = AsyncMock()
    mock_session_local.return_value.__aenter__.return_value = mock_db
    
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    mock_db.execute.return_value = mock_result
    
    res = await _async_scheduled_scan(1, "all")
    assert "error" in res
    
    mock_result.scalar_one_or_none.return_value = MagicMock()
    with patch("app.core.scanner.ScanOrchestrator") as orchestrator_mock:
        orchestrator_instance = AsyncMock()
        orchestrator_mock.return_value = orchestrator_instance
        orchestrator_instance.run_scan.return_value = MagicMock(id=1, compliance_score=100.0, total_checks=1)
        res = await _async_scheduled_scan(1, "all")
        assert res["scan_id"] == 1

@pytest.mark.asyncio
@patch("boto3.client")
async def test_evidence_manager(mock_boto):
    from app.core.evidence import EvidenceManager
    from app.models.compliance import ComplianceCheck
    
    manager = EvidenceManager()
    check = ComplianceCheck(id=1, scan_id=1, policy_id="test", status="failed")
    
    url = await manager.store(check, {"reason": "bad"})
    assert url is not None

@pytest.mark.asyncio
@patch("app.core.ingestion.aioredis.from_url", new_callable=AsyncMock)
async def test_ingestion_redis_property(mock_from_url):
    from app.core.ingestion import IngestionPipeline
    pipeline = IngestionPipeline()
    client1 = await pipeline.redis
    client2 = await pipeline.redis
    assert client1 == client2
    mock_from_url.assert_called_once()
    
    await pipeline.close()
    pipeline._redis.aclose.assert_called_once()

@pytest.mark.asyncio
async def test_ingestion_pipeline_batch():
    from app.core.ingestion import IngestionPipeline
    pipeline = IngestionPipeline()
    pipeline.ingest_event = AsyncMock(return_value="1-0")
    res = await pipeline.ingest_batch([{}, {}])
    assert len(res) == 2

@pytest.mark.asyncio
async def test_ingestion_process_events():
    from app.core.ingestion import IngestionPipeline
    pipeline = IngestionPipeline()
    
    mock_client = AsyncMock()
    mock_client.xreadgroup.side_effect = [
        [("stream", [("1-0", {"payload": "{}", "source": "cloudtrail", "event_type": "ConsoleLogin"})])],
        Exception("break loop")
    ]
    pipeline._redis = mock_client
    
    try:
        await pipeline.process_events()
    except Exception as e:
        assert str(e) == "break loop"
        
    mock_client.xgroup_create.assert_called_once()
    mock_client.xack.assert_called_once()

@pytest.mark.asyncio
async def test_ingestion_process_specific_events():
    from app.core.ingestion import IngestionPipeline
    import json
    pipeline = IngestionPipeline()
    
    await pipeline._process_entry("1", {"source": "cloudtrail", "payload": json.dumps({"eventName": "DeleteBucket"})})
    await pipeline._process_entry("2", {"source": "azure_monitor", "payload": json.dumps({"operationName": "test"})})
    await pipeline._process_entry("3", {"source": "gcp_audit", "payload": json.dumps({"methodName": "test"})})
    await pipeline._process_entry("4", {"source": "unknown"})
