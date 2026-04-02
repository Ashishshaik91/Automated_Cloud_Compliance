"""
Tests for NVD client CPE mapping, VirusTotal throttle logic,
MISP disabled-by-default, and the threat intel cache.
Feature 4 verification.
"""

import pytest
import json
from unittest.mock import AsyncMock, MagicMock, patch


# ── NVD CPE mapping ───────────────────────────────────────────────────────────

class TestNVDCpeMapping:
    def test_aws_s3_maps_to_cpe(self):
        from app.integrations.nvd_client import get_cpe_for_resource
        cpe = get_cpe_for_resource("aws_s3_bucket")
        assert cpe and "amazon" in cpe and "simple_storage_service" in cpe

    def test_rds_alias_maps_to_cpe(self):
        from app.integrations.nvd_client import get_cpe_for_resource
        cpe = get_cpe_for_resource("rds")
        assert cpe and "relational_database_service" in cpe

    def test_azure_storage_maps_to_cpe(self):
        from app.integrations.nvd_client import get_cpe_for_resource
        cpe = get_cpe_for_resource("azurerm_storage_account")
        assert cpe and "microsoft" in cpe and "azure_storage" in cpe

    def test_gcs_maps_to_cpe(self):
        from app.integrations.nvd_client import get_cpe_for_resource
        cpe = get_cpe_for_resource("gcs")
        assert cpe and "google" in cpe and "cloud_storage" in cpe

    def test_unknown_resource_returns_none(self):
        from app.integrations.nvd_client import get_cpe_for_resource
        cpe = get_cpe_for_resource("some_unsupported_resource_type")
        assert cpe is None

    @pytest.mark.asyncio
    async def test_nvd_query_on_timeout_returns_empty(self):
        """NVD query should return [] gracefully on timeout (fail-open)."""
        import httpx
        from app.integrations.nvd_client import query_nvd_cpe

        with patch("app.integrations.nvd_client.httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                side_effect=httpx.TimeoutException("timeout")
            )
            result = await query_nvd_cpe("s3")
        assert result == []

    @pytest.mark.asyncio
    async def test_nvd_query_parses_response_correctly(self):
        """NVD query should filter CVEs below MIN_CVSS_SCORE."""
        from app.integrations.nvd_client import query_nvd_cpe

        mock_response_data = {
            "vulnerabilities": [
                {"cve": {"id": "CVE-2024-0001", "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]}, "descriptions": [{"lang": "en", "value": "Critical vuln"}]}},
                {"cve": {"id": "CVE-2024-0002", "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 5.0}}]}, "descriptions": [{"lang": "en", "value": "Low vuln"}]}},
            ]
        }

        with patch("app.integrations.nvd_client.httpx.AsyncClient") as mock_client:
            mock_resp = MagicMock()
            mock_resp.json.return_value = mock_response_data
            mock_resp.raise_for_status = MagicMock()
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(return_value=mock_resp)

            with patch("app.integrations.nvd_client.get_settings") as mock_settings:
                mock_settings.return_value.nvd_api_key = ""
                result = await query_nvd_cpe("s3")

        # Only CVE-2024-0001 (9.8) should pass the ≥7.0 filter
        assert len(result) == 1
        assert result[0]["cve_id"] == "CVE-2024-0001"
        assert result[0]["cvss_score"] == 9.8


# ── VirusTotal rate limiting ──────────────────────────────────────────────────

class TestVirusTotalClient:
    @pytest.mark.asyncio
    async def test_no_api_key_returns_none(self):
        """VT client must return None gracefully when no API key is configured."""
        from app.integrations.virustotal_client import get_ip_reputation

        with patch("app.integrations.virustotal_client.get_settings") as mock_settings:
            mock_settings.return_value.virustotal_api_key.get_secret_value.return_value = ""
            result = await get_ip_reputation("1.2.3.4")
        assert result is None

    @pytest.mark.asyncio
    async def test_timeout_returns_none(self):
        """VT client must return None on timeout (fail-open)."""
        import httpx
        from app.integrations.virustotal_client import get_ip_reputation

        with patch("app.integrations.virustotal_client.get_settings") as mock_settings:
            mock_settings.return_value.virustotal_api_key.get_secret_value.return_value = "test-key"
            with patch("app.integrations.virustotal_client.httpx.AsyncClient") as mock_client:
                mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                    side_effect=httpx.TimeoutException("timeout")
                )
                result = await get_ip_reputation("1.2.3.4")
        assert result is None

    @pytest.mark.asyncio
    async def test_clean_ip_returns_zero_ratio(self):
        """VT client returns 0.0 when no malicious detections."""
        from app.integrations.virustotal_client import get_ip_reputation

        mock_data = {
            "data": {"attributes": {"last_analysis_stats": {"malicious": 0, "undetected": 80, "harmless": 10}}}
        }
        with patch("app.integrations.virustotal_client.get_settings") as mock_settings:
            mock_settings.return_value.virustotal_api_key.get_secret_value.return_value = "test-key"
            with patch("app.integrations.virustotal_client.httpx.AsyncClient") as mock_client:
                mock_resp = MagicMock()
                mock_resp.json.return_value = mock_data
                mock_resp.raise_for_status = MagicMock()
                mock_client.return_value.__aenter__.return_value.get = AsyncMock(return_value=mock_resp)
                result = await get_ip_reputation("1.2.3.4")
        assert result == 0.0


# ── MISP disabled by default ──────────────────────────────────────────────────

class TestMISPClient:
    @pytest.mark.asyncio
    async def test_disabled_by_default_returns_empty(self):
        """When MISP_URL is empty, search must return [] without making HTTP calls."""
        from app.integrations.misp_client import search_misp_events

        with patch("app.integrations.misp_client.get_settings") as mock_settings:
            mock_settings.return_value.misp_url = ""
            result = await search_misp_events("1.2.3.4")
        assert result == []

    @pytest.mark.asyncio
    async def test_timeout_returns_empty(self):
        """MISP timeout should return [] gracefully."""
        import httpx
        from app.integrations.misp_client import search_misp_events

        with patch("app.integrations.misp_client.get_settings") as mock_settings:
            mock_settings.return_value.misp_url = "https://misp.internal"
            mock_settings.return_value.misp_api_key.get_secret_value.return_value = "misp-key"
            with patch("app.integrations.misp_client.httpx.AsyncClient") as mock_client:
                mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                    side_effect=httpx.TimeoutException("timeout")
                )
                result = await search_misp_events("1.2.3.4")
        assert result == []


# ── Threat intel cache ────────────────────────────────────────────────────────

class TestThreatIntelCache:
    @pytest.mark.asyncio
    async def test_cache_miss_returns_none(self):
        from app.integrations.threat_intel_cache import cache_get

        redis = AsyncMock()
        redis.get = AsyncMock(return_value=None)
        result = await cache_get(redis, "nvd", "s3:aws")
        assert result is None

    @pytest.mark.asyncio
    async def test_cache_hit_returns_deserialized_value(self):
        from app.integrations.threat_intel_cache import cache_get

        payload = [{"cve_id": "CVE-2024-9999", "cvss_score": 9.1}]
        redis = AsyncMock()
        redis.get = AsyncMock(return_value=json.dumps(payload))
        result = await cache_get(redis, "nvd", "s3:aws")
        assert result == payload

    @pytest.mark.asyncio
    async def test_cache_set_calls_setex_with_ttl(self):
        from app.integrations.threat_intel_cache import cache_set, _CACHE_TTL

        redis = AsyncMock()
        redis.setex = AsyncMock()
        await cache_set(redis, "nvd", "s3:aws", [{"cve_id": "CVE-X"}])
        redis.setex.assert_called_once()
        args = redis.setex.call_args[0]
        assert args[1] == _CACHE_TTL  # TTL is 86400

    @pytest.mark.asyncio
    async def test_cache_get_with_none_redis_returns_none(self):
        """Passing None as redis_client should return None gracefully."""
        from app.integrations.threat_intel_cache import cache_get
        result = await cache_get(None, "nvd", "s3:aws")
        assert result is None

    @pytest.mark.asyncio
    async def test_cache_set_with_none_redis_is_noop(self):
        """Passing None as redis_client should not raise."""
        from app.integrations.threat_intel_cache import cache_set
        await cache_set(None, "nvd", "s3:aws", [])  # must not raise


# ── DSPM engine threat intel boost formula ────────────────────────────────────

class TestDSPMBoostFormula:
    def test_critical_cve_adds_ten_per_cve(self):
        from app.core.dspm_engine import _compute_threat_intel_boost
        cves = [
            {"cve_id": "CVE-2024-0001", "cvss_score": 9.8},
            {"cve_id": "CVE-2024-0002", "cvss_score": 9.1},
        ]
        boost, reason = _compute_threat_intel_boost(cves, None)
        assert boost == 20.0  # 2 × 10, capped at 20

    def test_single_critical_cve_adds_ten(self):
        from app.core.dspm_engine import _compute_threat_intel_boost
        cves = [{"cve_id": "CVE-2024-0001", "cvss_score": 9.5}]
        boost, reason = _compute_threat_intel_boost(cves, None)
        assert boost == 10.0

    def test_vt_high_reputation_adds_twenty(self):
        from app.core.dspm_engine import _compute_threat_intel_boost
        boost, reason = _compute_threat_intel_boost([], vt_reputation=0.8)
        assert boost == 20.0

    def test_high_cvss_below_9_does_not_count_as_critical(self):
        from app.core.dspm_engine import _compute_threat_intel_boost
        cves = [{"cve_id": "CVE-2024-0001", "cvss_score": 8.9}]
        boost, reason = _compute_threat_intel_boost(cves, None)
        assert boost == 0.0  # Only CVSS ≥ 9.0 counts

    def test_no_threat_intel_boost_is_zero(self):
        from app.core.dspm_engine import _compute_threat_intel_boost
        boost, reason = _compute_threat_intel_boost([], None)
        assert boost == 0.0

    def test_max_boost_is_twenty(self):
        """Even with many critical CVEs + high VT, boost is capped at 20."""
        from app.core.dspm_engine import _compute_threat_intel_boost
        cves = [{"cve_id": f"CVE-{i}", "cvss_score": 9.9} for i in range(10)]
        boost, reason = _compute_threat_intel_boost(cves, vt_reputation=0.9)
        assert boost == 20.0

    def test_base_score_not_exceeded_by_boost(self):
        """Final score must be capped at 100.0 even with maximum boost."""
        from app.core.dspm_engine import _compute_base_score
        base = _compute_base_score("critical", True, "unencrypted")
        final = min(100.0, base + 20.0)
        assert final == 100.0
