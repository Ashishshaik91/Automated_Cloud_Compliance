"""
Unit tests for the CaC Engine and Policy Loader.
"""

from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.core.cac_engine import CaCEngine
from app.core.policy_loader import PolicyLoader


class TestPolicyLoader:
    """Test policy loading from YAML files."""

    def test_load_all_policies(self, tmp_path: Path) -> None:
        """Test loading policies from temporary YAML files."""
        # Create test policy file
        policy_dir = tmp_path / "test_framework"
        policy_dir.mkdir()
        policy_file = policy_dir / "test_policies.yaml"
        policy_file.write_text("""
policies:
  - id: test-policy-001
    name: "Test Policy: Encryption Required"
    resource_type: s3_bucket
    severity: critical
    opa_package: compliance.test.s3
    rules:
      - field: encryption_enabled
        operator: is_true
    remediation: "Enable encryption"
""")
        loader = PolicyLoader(base_dir=tmp_path)
        loader.load_all()

        policies = loader.get_policies("test_framework", "s3_bucket")
        assert len(policies) >= 1
        assert policies[0]["id"] == "test-policy-001"
        assert policies[0]["severity"] == "critical"

    def test_get_frameworks(self, tmp_path: Path) -> None:
        """Test framework discovery."""
        for fw in ["pci_dss", "hipaa", "gdpr"]:
            fw_dir = tmp_path / fw
            fw_dir.mkdir()
            (fw_dir / "policy.yaml").write_text("""
policies:
  - id: test-001
    name: "Test"
    resource_type: all
    severity: high
    opa_package: compliance.generic
    rules: []
""")
        loader = PolicyLoader(base_dir=tmp_path)
        loader.load_all()
        frameworks = loader.get_frameworks()
        assert "pci_dss" in frameworks
        assert "hipaa" in frameworks
        assert "gdpr" in frameworks

    def test_invalid_policy_file(self, tmp_path: Path, caplog) -> None:
        """Test graceful handling of malformed policy files."""
        fw_dir = tmp_path / "bad_framework"
        fw_dir.mkdir()
        (fw_dir / "bad.yaml").write_text("not: valid: policy: format")
        loader = PolicyLoader(base_dir=tmp_path)
        loader.load_all()  # Should not raise


class TestCaCEngineLocalFallback:
    """Test CaC engine local Python fallback evaluator."""

    def setup_method(self) -> None:
        self.mock_loader = MagicMock()
        self.engine = CaCEngine(self.mock_loader)

    def test_passes_when_field_is_true(self) -> None:
        policy = {"rules": [{"field": "encryption_enabled", "operator": "is_true"}]}
        resource = {"encryption_enabled": True}
        result = self.engine._local_fallback_eval(policy, resource)
        assert result == "pass"

    def test_fails_when_field_is_false(self) -> None:
        policy = {"rules": [{"field": "encryption_enabled", "operator": "is_true"}]}
        resource = {"encryption_enabled": False}
        result = self.engine._local_fallback_eval(policy, resource)
        assert result == "fail"

    def test_is_false_operator(self) -> None:
        policy = {"rules": [{"field": "publicly_accessible", "operator": "is_false"}]}
        resource = {"publicly_accessible": False}
        result = self.engine._local_fallback_eval(policy, resource)
        assert result == "pass"

    def test_is_false_fails_when_true(self) -> None:
        policy = {"rules": [{"field": "publicly_accessible", "operator": "is_false"}]}
        resource = {"publicly_accessible": True}
        result = self.engine._local_fallback_eval(policy, resource)
        assert result == "fail"

    def test_equals_operator(self) -> None:
        policy = {"rules": [{"field": "status", "operator": "equals", "value": "enabled"}]}
        resource = {"status": "enabled"}
        result = self.engine._local_fallback_eval(policy, resource)
        assert result == "pass"

    def test_multiple_rules_all_must_pass(self) -> None:
        policy = {
            "rules": [
                {"field": "encryption_enabled", "operator": "is_true"},
                {"field": "publicly_accessible", "operator": "is_false"},
            ]
        }
        resource = {"encryption_enabled": True, "publicly_accessible": False}
        result = self.engine._local_fallback_eval(policy, resource)
        assert result == "pass"

    def test_multiple_rules_one_fail(self) -> None:
        policy = {
            "rules": [
                {"field": "encryption_enabled", "operator": "is_true"},
                {"field": "publicly_accessible", "operator": "is_false"},
            ]
        }
        resource = {"encryption_enabled": True, "publicly_accessible": True}
        result = self.engine._local_fallback_eval(policy, resource)
        assert result == "fail"

    def test_empty_rules_passes(self) -> None:
        policy = {"rules": []}
        resource = {}
        result = self.engine._local_fallback_eval(policy, resource)
        assert result == "pass"


class TestCaCEngineEvaluate:
    """Test CaC engine async evaluate with mocked OPA HTTP client."""

    def setup_method(self) -> None:
        from app.core.cac_engine import CaCEngine
        from unittest.mock import MagicMock
        self.mock_loader = MagicMock()
        self.engine = CaCEngine(self.mock_loader)

    @pytest.mark.asyncio
    async def test_evaluate_opa_pass(self) -> None:
        from unittest.mock import AsyncMock, patch, MagicMock
        policy = {
            "id": "s3-enc", "name": "S3 Encryption", "framework": "pci_dss",
            "severity": "critical", "opa_package": "compliance.aws.s3",
            "rules": [], "remediation": "Enable encryption",
        }
        self.mock_loader.get_policies.return_value = [policy]
        mock_response = MagicMock()
        mock_response.json.return_value = {"result": True}
        mock_response.raise_for_status.return_value = None
        with patch.object(self.engine._opa_client, "post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = mock_response
            results = await self.engine.evaluate("pci_dss", "s3_bucket", {"resource_id": "mybucket"})
        assert len(results) == 1
        assert results[0]["status"] == "pass"

    @pytest.mark.asyncio
    async def test_evaluate_opa_fail(self) -> None:
        from unittest.mock import AsyncMock, patch, MagicMock
        policy = {
            "id": "s3-pub", "name": "S3 Public Access", "framework": "pci_dss",
            "severity": "high", "opa_package": "compliance.aws.s3",
            "rules": [], "remediation": "Block public access",
        }
        self.mock_loader.get_policies.return_value = [policy]
        mock_response = MagicMock()
        mock_response.json.return_value = {"result": False}
        mock_response.raise_for_status.return_value = None
        with patch.object(self.engine._opa_client, "post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = mock_response
            results = await self.engine.evaluate("pci_dss", "s3_bucket", {"resource_id": "mybucket"})
        assert results[0]["status"] == "fail"

    @pytest.mark.asyncio
    async def test_evaluate_opa_http_error_fallback(self) -> None:
        import httpx
        from unittest.mock import AsyncMock, patch
        policy = {
            "id": "s3-fallback", "name": "S3 Fallback", "framework": "pci_dss",
            "severity": "medium", "opa_package": "compliance.aws.s3",
            "rules": [{"field": "encryption_enabled", "operator": "is_true"}],
            "remediation": "Enable encryption",
        }
        self.mock_loader.get_policies.return_value = [policy]
        with patch.object(self.engine._opa_client, "post", new_callable=AsyncMock) as mock_post:
            mock_post.side_effect = httpx.HTTPError("OPA unavailable")
            results = await self.engine.evaluate(
                "pci_dss", "s3_bucket", {"resource_id": "mybucket", "encryption_enabled": True}
            )
        assert results[0]["status"] == "pass"

    @pytest.mark.asyncio
    async def test_evaluate_empty_policies(self) -> None:
        self.mock_loader.get_policies.return_value = []
        results = await self.engine.evaluate("pci_dss", "s3_bucket", {})
        assert results == []

    @pytest.mark.asyncio
    async def test_engine_close(self) -> None:
        from unittest.mock import AsyncMock, patch
        with patch.object(self.engine._opa_client, "aclose", new_callable=AsyncMock) as mock_close:
            await self.engine.close()
            mock_close.assert_called_once()
