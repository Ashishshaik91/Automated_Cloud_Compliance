import pytest
from pydantic import ValidationError
from datetime import datetime, timezone

from app.schemas.auth import UserCreate, UserResponse, TokenResponse, RefreshRequest
from app.schemas.compliance import CloudAccountCreate, CloudAccountResponse, ScanTriggerRequest, ReportRequest

def test_user_create_valid():
    user = UserCreate(email="test@example.com", full_name="Test User", password="Password123!")
    assert user.email == "test@example.com"
    assert user.full_name == "Test User"
    
def test_user_create_invalid_email():
    with pytest.raises(ValidationError):
        UserCreate(email="invalid_email", full_name="Test", password="Password123!")

def test_user_create_password_no_upper():
    with pytest.raises(ValidationError):
        UserCreate(email="test@test.com", full_name="Test", password="password123!")

def test_user_create_password_no_lower():
    with pytest.raises(ValidationError):
        UserCreate(email="test@test.com", full_name="Test", password="PASSWORD123!")

def test_user_create_password_no_digit():
    with pytest.raises(ValidationError):
        UserCreate(email="test@test.com", full_name="Test", password="Password!!!")

def test_user_create_password_no_special():
    with pytest.raises(ValidationError):
        UserCreate(email="test@test.com", full_name="Test", password="Password1234")

def test_user_create_name_too_short():
    with pytest.raises(ValidationError):
        UserCreate(email="test@test.com", full_name="T", password="Password123!")

def test_cloud_account_create_valid():
    account = CloudAccountCreate(name="Prod AWS", provider="aws", account_id="123456789012")
    assert account.provider == "aws"
    assert account.account_id == "123456789012"

def test_cloud_account_create_invalid_provider():
    with pytest.raises(ValidationError):
        CloudAccountCreate(name="Prod", provider="digitalocean", account_id="123")

def test_scan_trigger_request_valid():
    scan = ScanTriggerRequest(account_id=1, framework="pci_dss")
    assert scan.framework == "pci_dss"
    assert scan.dry_run is False

def test_scan_trigger_request_invalid_framework():
    with pytest.raises(ValidationError):
        ScanTriggerRequest(account_id=1, framework="iso27001")

def test_report_request_valid():
    report = ReportRequest(scan_id=1, format="pdf")
    assert report.format == "pdf"
    
def test_report_request_invalid_format():
    with pytest.raises(ValidationError):
        ReportRequest(scan_id=1, format="docx")
