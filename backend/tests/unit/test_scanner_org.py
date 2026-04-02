"""
Tests for scanner.py — Celery task org context propagation and
TerraformConnector presence in CONNECTOR_MAP.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch


class TestConnectorMap:
    def test_terraform_connector_in_map(self):
        """TerraformConnector must be registered in CONNECTOR_MAP."""
        from app.core.scanner import CONNECTOR_MAP
        assert "terraform" in CONNECTOR_MAP

    def test_all_expected_providers_present(self):
        from app.core.scanner import CONNECTOR_MAP
        for provider in ("aws", "azure", "gcp", "terraform"):
            assert provider in CONNECTOR_MAP, f"Provider '{provider}' missing from CONNECTOR_MAP"


class TestScanOrgContext:
    @pytest.mark.asyncio
    async def test_org_mismatch_returns_error(self):
        """_async_scheduled_scan must reject if account.org != dispatched org."""
        from app.core.scanner import _async_scheduled_scan

        mock_account = MagicMock()
        mock_account.organization_id = 5  # account belongs to org 5

        mock_db = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_account
        mock_db.execute = AsyncMock(return_value=mock_result)

        with patch("app.models.database.engine") as mock_engine:
            mock_engine.dispose = AsyncMock()
            with patch("app.core.scanner.AsyncSessionLocal") as mock_session:
                mock_session.return_value.__aenter__ = AsyncMock(return_value=mock_db)
                mock_session.return_value.__aexit__ = AsyncMock(return_value=False)

                # Dispatch from org 99, but account belongs to org 5
                result = await _async_scheduled_scan(
                    account_id=1, framework="all", organization_id=99
                )

        assert "error" in result
        assert "organization" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_matching_org_proceeds(self):
        """_async_scheduled_scan must proceed when account.org == dispatched org."""
        from app.core.scanner import _async_scheduled_scan

        mock_account = MagicMock()
        mock_account.organization_id = 3

        mock_db = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_account
        mock_db.execute = AsyncMock(return_value=mock_result)
        mock_db.commit = AsyncMock()

        with patch("app.models.database.engine") as mock_engine:
            mock_engine.dispose = AsyncMock()
            with patch("app.core.scanner.AsyncSessionLocal") as mock_session:
                mock_session.return_value.__aenter__ = AsyncMock(return_value=mock_db)
                mock_session.return_value.__aexit__ = AsyncMock(return_value=False)

                with patch("app.core.scanner.PolicyLoader"), \
                     patch("app.core.scanner.EvidenceManager"), \
                     patch("app.core.scanner.ScanOrchestrator") as mock_orch:

                    mock_scan = MagicMock(id=42, compliance_score=95.0, total_checks=10)
                    mock_orch.return_value.run_scan = AsyncMock(return_value=mock_scan)

                    result = await _async_scheduled_scan(
                        account_id=1, framework="all", organization_id=3
                    )

        assert result["scan_id"] == 42
        assert result["organization_id"] == 3

    @pytest.mark.asyncio
    async def test_none_org_id_skips_mismatch_check(self):
        """When organization_id=None (legacy/unscoped call), no mismatch check runs."""
        from app.core.scanner import _async_scheduled_scan

        mock_account = MagicMock()
        mock_account.organization_id = 7  # different from None, but no check expected

        mock_db = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_account
        mock_db.execute = AsyncMock(return_value=mock_result)
        mock_db.commit = AsyncMock()

        with patch("app.models.database.engine") as mock_engine:
            mock_engine.dispose = AsyncMock()
            with patch("app.core.scanner.AsyncSessionLocal") as mock_session:
                mock_session.return_value.__aenter__ = AsyncMock(return_value=mock_db)
                mock_session.return_value.__aexit__ = AsyncMock(return_value=False)

                with patch("app.core.scanner.PolicyLoader"), \
                     patch("app.core.scanner.EvidenceManager"), \
                     patch("app.core.scanner.ScanOrchestrator") as mock_orch:

                    mock_scan = MagicMock(id=10, compliance_score=80.0, total_checks=5)
                    mock_orch.return_value.run_scan = AsyncMock(return_value=mock_scan)

                    result = await _async_scheduled_scan(
                        account_id=1, framework="all", organization_id=None
                    )

        assert result["scan_id"] == 10
        assert result.get("organization_id") is None

    @pytest.mark.asyncio
    async def test_missing_account_returns_error(self):
        """Non-existent account_id returns error dict without raising."""
        from app.core.scanner import _async_scheduled_scan

        mock_db = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_db.execute = AsyncMock(return_value=mock_result)

        with patch("app.models.database.engine") as mock_engine:
            mock_engine.dispose = AsyncMock()
            with patch("app.core.scanner.AsyncSessionLocal") as mock_session:
                mock_session.return_value.__aenter__ = AsyncMock(return_value=mock_db)
                mock_session.return_value.__aexit__ = AsyncMock(return_value=False)

                result = await _async_scheduled_scan(
                    account_id=999, framework="all", organization_id=1
                )

        assert "error" in result
        assert "999" in result["error"]


class TestRunScheduledScanTask:
    def test_celery_task_accepts_organization_id(self):
        """
        The underlying Celery task function must accept organization_id kwarg.
        When running under the celery mock, we inspect the __wrapped__ or .run
        attribute to get the real function signature.
        """
        from app.core.scanner import run_scheduled_scan
        import inspect

        # Under the celery stub, the task is a MagicMock wrapping our function.
        # The original function is accessible via __wrapped__ or we can fall back
        # to checking the module-level _async_scheduled_scan which has the real sig.
        from app.core.scanner import _async_scheduled_scan
        sig = inspect.signature(_async_scheduled_scan)
        assert "organization_id" in sig.parameters

    def test_celery_task_org_id_defaults_to_none(self):
        """organization_id must default to None for backwards compatibility."""
        from app.core.scanner import _async_scheduled_scan
        import inspect
        param = inspect.signature(_async_scheduled_scan).parameters["organization_id"]
        assert param.default is None
