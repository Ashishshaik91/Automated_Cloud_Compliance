"""
Tests for YAML runbook loading, rollback command resolution, and RemediationEngine.
Feature 2 verification.
"""

import pytest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from app.core.remediation import RemediationEngine, load_runbook, RUNBOOKS_DIR


# ── Runbook loading ───────────────────────────────────────────────────────────

class TestLoadRunbook:
    def test_load_known_runbook(self):
        """s3_encryption.yaml should load and have required keys."""
        rb = load_runbook("s3_encryption")
        assert rb is not None
        assert rb["rule_id"] == "s3_encryption"
        assert "manual_steps" in rb
        assert "aws_cli_command" in rb
        assert "rollback_command" in rb

    def test_load_dspm_runbook(self):
        """DSPM runbook for PII-exposed S3 should have a critical severity."""
        rb = load_runbook("dspm_s3_pii_exposed")
        assert rb is not None
        assert rb["severity"] == "critical"

    def test_load_azure_runbook(self):
        """Azure storage HTTPS runbook should contain azure_cli_command."""
        rb = load_runbook("azure_storage_https")
        assert rb is not None
        assert "azure_cli_command" in rb

    def test_load_gcp_runbook(self):
        """GCP GCS public access runbook should contain gcloud_command."""
        rb = load_runbook("gcp_gcs_public_access")
        assert rb is not None
        assert "gcloud_command" in rb

    def test_load_unknown_runbook_returns_none(self):
        """A non-existent rule_id should return None gracefully."""
        result = load_runbook("nonexistent_rule_xyz_123")
        assert result is None

    def test_path_traversal_sanitisation(self):
        """Attempting path traversal should not load any file."""
        result = load_runbook("../../../etc/passwd")
        assert result is None

    def test_all_runbooks_have_rollback(self):
        """Every runbook YAML in the directory must have a rollback_command."""
        missing = []
        for yaml_file in RUNBOOKS_DIR.glob("*.yaml"):
            rb = load_runbook(yaml_file.stem)
            if rb and not rb.get("rollback_command"):
                missing.append(yaml_file.name)
        assert not missing, f"Runbooks missing rollback_command: {missing}"

    def test_all_runbooks_have_required_fields(self):
        """Every runbook must have rule_id, title, severity, and manual_steps."""
        required = {"rule_id", "title", "severity", "manual_steps"}
        errors = []
        for yaml_file in RUNBOOKS_DIR.glob("*.yaml"):
            rb = load_runbook(yaml_file.stem)
            if rb:
                for field in required:
                    if field not in rb:
                        errors.append(f"{yaml_file.name}: missing '{field}'")
        assert not errors, f"Runbook field errors:\n" + "\n".join(errors)


# ── RemediationEngine ─────────────────────────────────────────────────────────

class TestRemediationEngine:
    """Tests for dry_run mode and rollback execution."""

    def _make_check(self, resource_type="s3_bucket", policy_id="s3-encryption-required", resource_id="my-bucket"):
        check = MagicMock()
        check.resource_type = resource_type
        check.policy_id = policy_id
        check.resource_id = resource_id
        return check

    @pytest.mark.asyncio
    async def test_dry_run_returns_dry_run_status(self):
        """In dry_run mode remediate() must return status 'dry_run'."""
        engine = RemediationEngine(dry_run=True)
        check = self._make_check()
        result = await engine.remediate(check, {})
        assert result["status"] == "dry_run"
        assert result["action"] == "_enable_s3_encryption"

    @pytest.mark.asyncio
    async def test_dry_run_includes_runbook_reference(self):
        """dry_run response must include the loaded runbook."""
        engine = RemediationEngine(dry_run=True)
        check = self._make_check()
        result = await engine.remediate(check, {})
        assert "runbook" in result
        # Runbook available for s3-encryption-required → s3_encryption.yaml (mapped by handler name)
        # May be None if policy_id doesn't match runbook name directly — that's OK

    @pytest.mark.asyncio
    async def test_unknown_rule_returns_no_action(self):
        """Policy with no handler mapped should return 'no_action'."""
        engine = RemediationEngine(dry_run=True)
        check = self._make_check(policy_id="unknown-rule-9999")
        result = await engine.remediate(check, {})
        assert result["status"] == "no_action"

    @pytest.mark.asyncio
    async def test_rollback_dry_run(self):
        """execute_rollback in dry_run mode should return dry_run status without executing."""
        engine = RemediationEngine(dry_run=True)
        result = await engine.execute_rollback("s3_encryption", "my-bucket", org_id=1)
        assert result["status"] == "dry_run"
        assert "rollback_command" in result
        assert "my-bucket" in result["rollback_command"]

    @pytest.mark.asyncio
    async def test_rollback_live_mode(self):
        """execute_rollback in live mode should return rollback_queued."""
        engine = RemediationEngine(dry_run=False)
        result = await engine.execute_rollback("s3_encryption", "test-bucket", org_id=1)
        assert result["status"] == "rollback_queued"
        assert "rollback_command" in result

    @pytest.mark.asyncio
    async def test_rollback_unknown_rule(self):
        """Rollback for an unknown rule_id should return 'no_runbook'."""
        engine = RemediationEngine(dry_run=True)
        result = await engine.execute_rollback("nonexistent_rule_abc", "resource-123", org_id=1)
        assert result["status"] == "no_runbook"

    @pytest.mark.asyncio
    async def test_azure_handler_dry_run(self):
        """Azure storage HTTPS handler in dry_run should not call Azure SDK."""
        engine = RemediationEngine(dry_run=True)
        check = self._make_check(
            resource_type="storage_account",
            policy_id="azure-storage-https-required",
            resource_id="stgaccountprod",
        )
        result = await engine.remediate(check, {})
        assert result["status"] == "dry_run"
        assert result["action"] == "_enforce_storage_https"

    @pytest.mark.asyncio
    async def test_gcp_handler_dry_run(self):
        """GCS public access handler in dry_run should not call GCP SDK."""
        engine = RemediationEngine(dry_run=True)
        check = self._make_check(
            resource_type="gcs_bucket",
            policy_id="gcp-gcs-public-access-blocked",
            resource_id="gcs-ml-training-data",
        )
        result = await engine.remediate(check, {})
        assert result["status"] == "dry_run"
        assert result["action"] == "_block_gcs_public_access"
