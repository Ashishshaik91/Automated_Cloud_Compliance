import pytest
import asyncio
from unittest.mock import patch, AsyncMock, MagicMock
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession
from unittest.mock import AsyncMock, MagicMock

from app.main import app
from app.models.database import get_db
from app.auth.dependencies import get_current_user, require_admin
from app.models.user import User

client = TestClient(app, raise_server_exceptions=False)

# Mocked dependencies
import datetime

async def override_get_db():
    mock_db = AsyncMock(spec=AsyncSession)
    mock_result = MagicMock()
    
    generic = MagicMock()
    generic.id = 1
    generic.name = "Test"
    generic.framework = "pci_dss"
    generic.compliance_score = 90
    generic.account_id = 1
    generic.total_checks = 10
    generic.passed_checks = 9
    generic.failed_checks = 1
    generic.started_at = datetime.datetime.now(datetime.timezone.utc)
    generic.region = "us-east-1"
    generic.triggered_by = "test"
    generic.checks = []
    
    mock_result.scalars.return_value.all.return_value = []
    mock_result.scalar_one_or_none.return_value = generic
    mock_result.scalar.return_value = 0
    mock_db.execute.return_value = mock_result
    
    mock_db.new_records = []
    def fake_add(obj):
        mock_db.new_records.append(obj)
    mock_db.add.side_effect = fake_add
    
    async def fake_flush(*args, **kwargs):
        for obj in mock_db.new_records:
            if not getattr(obj, "id", None):
                obj.id = 1
            if not getattr(obj, "created_at", None):
                obj.created_at = datetime.datetime.now(datetime.timezone.utc)
            if not getattr(obj, "updated_at", None):
                obj.updated_at = datetime.datetime.now(datetime.timezone.utc)
            if not getattr(obj, "is_active", None):
                obj.is_active = True
    mock_db.flush.side_effect = fake_flush
    
    yield mock_db

async def override_get_current_user():
    return User(id=1, email="user@example.com", is_active=True, role="user")

async def override_require_admin():
    return User(id=2, email="admin@example.com", is_active=True, role="admin")

app.dependency_overrides[get_db] = override_get_db
app.dependency_overrides[get_current_user] = override_get_current_user
app.dependency_overrides[require_admin] = override_require_admin

def test_list_alerts():
    response = client.get("/api/v1/alerts/")
    assert response.status_code == 200

def test_acknowledge_alert():
    response = client.post("/api/v1/alerts/123/acknowledge")
    assert response.status_code == 200

def test_create_cloud_account():
    response = client.post("/api/v1/cloud-accounts/", json={
        "name": "Prod", "provider": "aws", "account_id": "123", "region": "us-east-1"
    })
    assert response.status_code == 201

def test_list_cloud_accounts():
    response = client.get("/api/v1/cloud-accounts/")
    assert response.status_code == 200

def test_disable_cloud_account_not_found():
    async def override_get_db_none():
        mock_db = AsyncMock(spec=AsyncSession)
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_db.execute.return_value = mock_result
        yield mock_db
    app.dependency_overrides[get_db] = override_get_db_none
    try:
        response = client.delete("/api/v1/cloud-accounts/999")
        assert response.status_code == 404
    finally:
        app.dependency_overrides[get_db] = override_get_db

def test_compliance_summary():
    response = client.get("/api/v1/compliance/summary")
    assert response.status_code == 200

def test_compliance_checks():
    response = client.get("/api/v1/compliance/checks")
    assert response.status_code == 200

def test_generate_report():
    response = client.post("/api/v1/reports/generate", json={"scan_id": 1, "format": "html"})
    assert response.status_code == 200

def test_download_report():
    response = client.get("/api/v1/reports/123/download?scan_id=1")
    assert response.status_code == 200

def test_list_scans():
    response = client.get("/api/v1/scans/")
    assert response.status_code == 200

def test_trigger_scan():
    response = client.post("/api/v1/scans/trigger", json={"account_id": 1, "framework": "pci_dss"})
    assert response.status_code == 202

def test_get_scan_detail():
    response = client.get("/api/v1/scans/1")
    assert response.status_code == 200

def test_get_scan_detail_not_found():
    async def override_get_db_none():
        mock_db = AsyncMock(spec=AsyncSession)
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_db.execute.return_value = mock_result
        yield mock_db
    app.dependency_overrides[get_db] = override_get_db_none
    try:
        response = client.get("/api/v1/scans/999")
        assert response.status_code == 404
    finally:
        app.dependency_overrides[get_db] = override_get_db

from app.api.alerts import send_slack_alert, send_email_alert

@pytest.mark.asyncio
async def test_send_slack_alert():
    with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value.status_code = 200
        result = await send_slack_alert("http://webhook", "Test", "critical")
        assert result is True

@pytest.mark.asyncio
async def test_send_slack_alert_failure():
    with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
        mock_post.side_effect = Exception("Network error")
        result = await send_slack_alert("http://webhook", "Test", "critical")
        assert result is False

@pytest.mark.asyncio
async def test_send_email_alert():
    with patch("smtplib.SMTP") as mock_smtp:
        mock_instance = mock_smtp.return_value.__enter__.return_value
        result = await send_email_alert("to@x.com", "Subj", "Body", "localhost", 25, "u", "p", "from@x.com")
        assert result is True

@pytest.mark.asyncio
async def test_send_email_alert_failure():
    with patch("smtplib.SMTP") as mock_smtp:
        mock_smtp.side_effect = Exception("SMTP error")
        result = await send_email_alert("to@x.com", "Subj", "Body", "localhost", 25, "u", "p", "from@x.com")
        assert result is False


