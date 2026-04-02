"""
NVD (National Vulnerability Database) REST API v2 client.
Uses CPE (Common Platform Enumeration) search for precision — not keyword search.

Queries only CVEs with CVSS base score >= 7.0 (High or Critical).
Returns a list of {cve_id, cvss_score, description} dicts.

CPE mapping for cloud resource types:
  aws_s3_bucket           → cpe:2.3:a:amazon:simple_storage_service:*
  aws_rds_instance        → cpe:2.3:a:amazon:relational_database_service:*
  aws_iam_user            → cpe:2.3:a:amazon:identity_and_access_management:*
  azurerm_storage_account → cpe:2.3:a:microsoft:azure_storage:*
  google_storage_bucket   → cpe:2.3:a:google:cloud_storage:*
"""

from __future__ import annotations

import asyncio
from typing import Any

import httpx
import structlog

from app.config import get_settings

logger = structlog.get_logger(__name__)

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MIN_CVSS_SCORE = 7.0

# Resource type → CPE string mapping
_CPE_MAP: dict[str, str] = {
    "aws_s3_bucket":            "cpe:2.3:a:amazon:simple_storage_service:*",
    "s3":                       "cpe:2.3:a:amazon:simple_storage_service:*",
    "aws_rds_instance":         "cpe:2.3:a:amazon:relational_database_service:*",
    "rds":                      "cpe:2.3:a:amazon:relational_database_service:*",
    "aws_iam_user":             "cpe:2.3:a:amazon:identity_and_access_management:*",
    "iam_user":                 "cpe:2.3:a:amazon:identity_and_access_management:*",
    "aws_ec2_instance":         "cpe:2.3:a:amazon:ec2:*",
    "ec2_instance":             "cpe:2.3:a:amazon:ec2:*",
    "azurerm_storage_account":  "cpe:2.3:a:microsoft:azure_storage:*",
    "blob":                     "cpe:2.3:a:microsoft:azure_storage:*",
    "google_storage_bucket":    "cpe:2.3:a:google:cloud_storage:*",
    "gcs":                      "cpe:2.3:a:google:cloud_storage:*",
    "bigquery":                 "cpe:2.3:a:google:bigquery:*",
}


def get_cpe_for_resource(resource_type: str) -> str | None:
    """Map a resource type string to its NVD CPE identifier."""
    return _CPE_MAP.get(resource_type.lower())


async def query_nvd_cpe(
    resource_type: str,
    max_results: int = 20,
) -> list[dict[str, Any]]:
    """
    Query NVD v2 API for CVEs matching the given resource type via CPE search.

    Returns a list of CVEs with CVSS score >= MIN_CVSS_SCORE, sorted by score descending.
    Returns [] on any failure (fail-open — callers must handle empty list).
    """
    cpe = get_cpe_for_resource(resource_type)
    if not cpe:
        logger.debug("No CPE mapping for resource type", resource_type=resource_type)
        return []

    settings = get_settings()
    headers = {}
    if settings.nvd_api_key:
        headers["apiKey"] = settings.nvd_api_key

    params = {
        "cpeName":       cpe,
        "cvssV3Severity": "HIGH",     # fetches HIGH + CRITICAL (CVSS >= 7.0)
        "resultsPerPage": min(max_results, 100),
        "startIndex":    0,
    }

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.get(NVD_BASE_URL, params=params, headers=headers)
            response.raise_for_status()
            data = response.json()
    except httpx.TimeoutException:
        logger.warning("NVD API timeout", resource_type=resource_type, cpe=cpe)
        return []
    except httpx.HTTPStatusError as e:
        logger.warning("NVD API HTTP error", status=e.response.status_code, resource_type=resource_type)
        return []
    except Exception as e:
        logger.error("NVD API unexpected error", error=str(e), resource_type=resource_type)
        return []

    results: list[dict[str, Any]] = []
    for item in data.get("vulnerabilities", []):
        cve_data = item.get("cve", {})
        cve_id = cve_data.get("id", "")

        # Extract CVSS v3 base score
        cvss_score = 0.0
        metrics = cve_data.get("metrics", {})
        for metric_key in ("cvssMetricV31", "cvssMetricV30"):
            entries = metrics.get(metric_key, [])
            if entries:
                cvss_score = entries[0].get("cvssData", {}).get("baseScore", 0.0)
                break

        if cvss_score < MIN_CVSS_SCORE:
            continue

        # Extract English description
        description = ""
        for desc in cve_data.get("descriptions", []):
            if desc.get("lang") == "en":
                description = desc.get("value", "")[:500]
                break

        results.append({
            "cve_id":      cve_id,
            "cvss_score":  cvss_score,
            "description": description,
        })

    # Sort by score descending
    results.sort(key=lambda x: x["cvss_score"], reverse=True)
    logger.info(
        "NVD CPE query complete",
        resource_type=resource_type,
        cpe=cpe,
        cve_count=len(results),
    )
    return results
