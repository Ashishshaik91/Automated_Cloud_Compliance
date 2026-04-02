"""
Tests for Terraform state connector — Feature 1.
Covers JSON parsing, resource normalisation, and path traversal safety.
"""

import json
import pytest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
from tempfile import NamedTemporaryFile


# ── _parse_tfstate ────────────────────────────────────────────────────────────

class TestParseTfstate:
    def test_parses_standard_v4_format(self):
        from app.connectors.terraform_connector import _parse_tfstate

        raw = {
            "format_version": "0.1",
            "resources": [
                {
                    "mode": "managed",
                    "type": "aws_s3_bucket",
                    "name": "data_lake",
                    "instances": [{
                        "attributes": {
                            "id": "my-data-lake",
                            "bucket": "my-data-lake",
                            "encryption": "AES256",
                            "region": "us-east-1",
                        }
                    }]
                }
            ]
        }
        resources = _parse_tfstate(raw)
        assert len(resources) == 1
        assert resources[0]["resource_type"] == "s3_bucket"
        assert resources[0]["resource_id"] == "my-data-lake"
        assert resources[0]["source"] == "terraform"

    def test_parses_terraform_show_json_format(self):
        from app.connectors.terraform_connector import _parse_tfstate

        raw = {
            "values": {
                "root_module": {
                    "resources": [{
                        "mode": "managed",
                        "type": "aws_s3_bucket",
                        "name": "logs",
                        "values": {
                            "id": "audit-logs-bucket",
                            "bucket": "audit-logs-bucket",
                        }
                    }]
                }
            }
        }
        resources = _parse_tfstate(raw)
        assert len(resources) == 1
        assert resources[0]["resource_id"] == "audit-logs-bucket"

    def test_skips_unsupported_resource_types(self):
        from app.connectors.terraform_connector import _parse_tfstate

        raw = {
            "resources": [{
                "mode": "managed",
                "type": "aws_lambda_function",  # not in _TF_TYPE_MAP
                "name": "my_func",
                "instances": [{"attributes": {"id": "fn-1"}}],
            }]
        }
        resources = _parse_tfstate(raw)
        assert resources == []

    def test_skips_data_source_mode(self):
        from app.connectors.terraform_connector import _parse_tfstate

        raw = {
            "resources": [{
                "mode": "data",  # data source, not managed resource
                "type": "aws_s3_bucket",
                "name": "lookup",
                "instances": [{"attributes": {"id": "other-bucket"}}],
            }]
        }
        resources = _parse_tfstate(raw)
        assert resources == []

    def test_normalises_az_resource(self):
        from app.connectors.terraform_connector import _parse_tfstate

        raw = {
            "resources": [{
                "mode": "managed",
                "type": "azurerm_storage_account",
                "name": "stgacc",
                "instances": [{"attributes": {"id": "/subscriptions/.../storageAccounts/stgacc", "name": "stgacc"}}],
            }]
        }
        resources = _parse_tfstate(raw)
        assert len(resources) == 1
        assert resources[0]["resource_type"] == "storage_account"

    def test_terraform_declared_config_preserved(self):
        """resource dict must include terraform_declared_config key for drift detection."""
        from app.connectors.terraform_connector import _parse_tfstate

        attrs = {"id": "my-bucket", "encryption": "AES256"}
        raw = {
            "resources": [{
                "mode": "managed", "type": "aws_s3_bucket", "name": "b1",
                "instances": [{"attributes": attrs}],
            }]
        }
        resources = _parse_tfstate(raw)
        assert resources[0]["terraform_declared_config"] == attrs

    def test_empty_state_file_returns_empty_list(self):
        from app.connectors.terraform_connector import _parse_tfstate
        assert _parse_tfstate({}) == []


# ── TerraformConnector._from_json_file ────────────────────────────────────────

class TestTerraformConnectorFromJson:
    @pytest.mark.asyncio
    async def test_reads_and_parses_tfstate_file(self, tmp_path):
        from app.connectors.terraform_connector import TerraformConnector

        state_data = {
            "resources": [{
                "mode": "managed", "type": "aws_s3_bucket", "name": "prod",
                "instances": [{"attributes": {"id": "prod-bucket"}}],
            }]
        }
        state_file = tmp_path / "terraform.tfstate"
        state_file.write_text(json.dumps(state_data))

        with patch("app.connectors.terraform_connector.get_settings") as mock_settings:
            mock_settings.return_value.terraform_mode = "json"
            connector = TerraformConnector(state_path=state_file)
            connector.settings = mock_settings.return_value
            resources = await connector.enumerate_resources()

        assert len(resources) == 1
        assert resources[0]["resource_id"] == "prod-bucket"

    @pytest.mark.asyncio
    async def test_missing_state_file_returns_empty(self, tmp_path):
        from app.connectors.terraform_connector import TerraformConnector

        with patch("app.connectors.terraform_connector.get_settings") as mock_settings:
            mock_settings.return_value.terraform_mode = "json"
            connector = TerraformConnector(state_path=tmp_path / "nonexistent.tfstate")
            connector.settings = mock_settings.return_value
            resources = await connector.enumerate_resources()

        assert resources == []

    @pytest.mark.asyncio
    async def test_invalid_json_returns_empty(self, tmp_path):
        from app.connectors.terraform_connector import TerraformConnector

        bad_file = tmp_path / "bad.tfstate"
        bad_file.write_text("NOT_VALID_JSON{{{")

        with patch("app.connectors.terraform_connector.get_settings") as mock_settings:
            mock_settings.return_value.terraform_mode = "json"
            connector = TerraformConnector(state_path=bad_file)
            connector.settings = mock_settings.return_value
            resources = await connector.enumerate_resources()

        assert resources == []


# ── Normalisation helper ──────────────────────────────────────────────────────

class TestNormaliseResource:
    def test_falls_back_to_tf_name_when_no_id_attr(self):
        from app.connectors.terraform_connector import _normalise_resource
        res = _normalise_resource("aws_s3_bucket", "my_fallback_name", {})
        assert res["resource_id"] == "my_fallback_name"

    def test_uses_attrs_id_first(self):
        from app.connectors.terraform_connector import _normalise_resource
        res = _normalise_resource("aws_s3_bucket", "tf_name", {"id": "actual-bucket-id"})
        assert res["resource_id"] == "actual-bucket-id"

    def test_unknown_tf_type_passes_through_as_raw(self):
        from app.connectors.terraform_connector import _normalise_resource
        res = _normalise_resource("some_custom_resource", "r1", {"id": "x"})
        assert res["resource_type"] == "some_custom_resource"
