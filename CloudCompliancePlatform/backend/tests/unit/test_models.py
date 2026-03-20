import pytest
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

from app.models.user import User
from app.models.compliance import CloudAccount, ScanResult, ComplianceCheck, EvidenceRecord, CloudProvider, Severity, CheckStatus
from app.schemas.auth import UserCreate


@pytest.mark.asyncio
class TestUserModel:
    async def test_user_creation(self):
        user = User(
            email="test@example.com",
            full_name="Test User",
            hashed_password="hashed_pwd",
            role="admin",
            is_active=True
        )
        assert user.email == "test@example.com"
        assert user.full_name == "Test User"
        assert user.role == "admin"
        assert user.is_active is True

    async def test_get_by_id(self):
        mock_session = AsyncMock()
        mock_result = MagicMock()  # Synchronous result object
        mock_user = User(id=1, email="test@example.com")
        mock_result.scalar_one_or_none.return_value = mock_user
        mock_session.execute.return_value = mock_result

        result = await User.get_by_id(mock_session, 1)
        assert result.id == 1
        assert result.email == "test@example.com"
        mock_session.execute.assert_called_once()

    async def test_get_by_email(self):
        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_user = User(id=1, email="test@example.com")
        mock_result.scalar_one_or_none.return_value = mock_user
        mock_session.execute.return_value = mock_result

        result = await User.get_by_email(mock_session, "TEST@example.com   ")
        assert result.id == 1
        mock_session.execute.assert_called_once()

    async def test_create(self):
        mock_session = AsyncMock()
        user_in = UserCreate(email="NEW@example.com", full_name="New", password="Password12345!")
        
        with patch("app.models.user.hash_password", return_value="hashed"):
            user = await User.create(mock_session, user_in)
            
        assert user.email == "new@example.com"
        assert user.hashed_password == "hashed"
        assert user.full_name == "New"
        mock_session.add.assert_called_once_with(user)
        mock_session.flush.assert_called_once()


def test_compliance_models():
    # Test CloudAccount
    account = CloudAccount(
        name="Prod AWS", provider=CloudProvider.AWS, account_id="123", region="us-east-1", is_active=True
    )
    assert account.name == "Prod AWS"
    assert account.provider == "aws"
    assert account.is_active is True
    
    # Test ScanResult
    scan = ScanResult(
        account_id=1, framework="pci_dss", started_at=datetime.now(timezone.utc),
        total_checks=0, compliance_score=0.0
    )
    assert scan.framework == "pci_dss"
    assert scan.total_checks == 0
    assert scan.compliance_score == 0.0
    
    # Test ComplianceCheck
    check = ComplianceCheck(
        scan_id=1, policy_id="test", policy_name="Test", framework="pci_dss",
        status=CheckStatus.FAIL, severity=Severity.HIGH
    )
    assert check.status == "fail"
    assert check.severity == "high"
    
    # Test EvidenceRecord
    evidence = EvidenceRecord(
        check_id=1, hash_value="abc", previous_hash="genesis"
    )
    assert evidence.hash_value == "abc"
    assert evidence.previous_hash == "genesis"
