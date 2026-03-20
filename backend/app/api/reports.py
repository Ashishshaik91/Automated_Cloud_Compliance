"""
Report generation API routes.
Generates audit-ready PDF and HTML compliance reports.
"""

import io
import json
from datetime import datetime, timezone
from typing import Annotated

import structlog
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response, StreamingResponse
from jinja2 import Environment, PackageLoader, select_autoescape
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.auth.dependencies import CurrentUser
from app.models.compliance import ScanResult
from app.models.database import get_db
from app.schemas.compliance import ReportRequest, ReportResponse
from app.utils.crypto import generate_secure_token

router = APIRouter()
logger = structlog.get_logger(__name__)

REPORT_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Compliance Report - {{ scan.framework | upper }} - {{ report_date }}</title>
<style>
  body { font-family: Arial, sans-serif; margin: 40px; color: #333; }
  h1 { color: #1a3a5c; border-bottom: 2px solid #1a3a5c; padding-bottom: 10px; }
  h2 { color: #2563eb; margin-top: 30px; }
  table { border-collapse: collapse; width: 100%; margin-top: 15px; }
  th { background: #1a3a5c; color: white; padding: 10px; text-align: left; }
  td { border: 1px solid #ddd; padding: 8px; }
  tr:nth-child(even) { background: #f5f5f5; }
  .pass { color: #16a34a; font-weight: bold; }
  .fail { color: #dc2626; font-weight: bold; }
  .score { font-size: 2em; font-weight: bold; color: {{ "16a34a" if scan.compliance_score >= 80 else ("f59e0b" if scan.compliance_score >= 60 else "dc2626") }}; }
  .critical { background: #fef2f2; }
  .high { background: #fffbeb; }
  footer { margin-top: 40px; font-size: 0.8em; color: #666; border-top: 1px solid #ddd; padding-top: 10px; }
</style>
</head>
<body>
<h1>Cloud Compliance Audit Report</h1>
<p><strong>Framework:</strong> {{ scan.framework | upper }}</p>
<p><strong>Account ID:</strong> {{ scan.account_id }}</p>
<p><strong>Scan Date:</strong> {{ scan.started_at }}</p>
<p><strong>Report Generated:</strong> {{ report_date }}</p>

<h2>Compliance Score</h2>
<p class="score">{{ scan.compliance_score }}%</p>
<p>Total Checks: {{ scan.total_checks }} | 
   Passed: <span class="pass">{{ scan.passed_checks }}</span> | 
   Failed: <span class="fail">{{ scan.failed_checks }}</span></p>

<h2>Compliance Check Results</h2>
<table>
  <tr>
    <th>Policy ID</th><th>Policy Name</th><th>Resource</th>
    <th>Severity</th><th>Status</th><th>Remediation</th>
  </tr>
  {% for check in checks %}
  <tr class="{{ check.severity if check.status == 'fail' else '' }}">
    <td>{{ check.policy_id }}</td>
    <td>{{ check.policy_name }}</td>
    <td>{{ check.resource_id or 'N/A' }}</td>
    <td>{{ check.severity | upper }}</td>
    <td class="{{ check.status }}">{{ check.status | upper }}</td>
    <td>{{ check.remediation_hint or '-' }}</td>
  </tr>
  {% endfor %}
</table>

<footer>
  <p>Report ID: {{ report_id }} | Cloud Compliance Platform v1.0.0</p>
  <p>This report is confidential and intended for internal compliance purposes only.</p>
</footer>
</body>
</html>"""


@router.post("/generate", response_model=ReportResponse)
async def generate_report(
    body: ReportRequest,
    current_user: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> ReportResponse:
    """Generate a compliance audit report for a scan."""
    scan_result = await db.execute(
        select(ScanResult)
        .options(selectinload(ScanResult.checks))
        .where(ScanResult.id == body.scan_id)
    )
    scan = scan_result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    report_id = generate_secure_token(16)
    report_date = datetime.now(timezone.utc).isoformat()

    logger.info("Report generated", scan_id=body.scan_id, format=body.format, user_id=current_user.id)

    return ReportResponse(
        report_id=report_id,
        scan_id=body.scan_id,
        format=body.format,
        download_url=f"/api/v1/reports/{report_id}/download",
        generated_at=datetime.now(timezone.utc),
    )


@router.get("/{report_id}/download")
async def download_report(
    report_id: str,
    scan_id: int,
    current_user: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
    fmt: str = "html",
) -> StreamingResponse:
    """Download a generated compliance report as HTML."""
    scan_result = await db.execute(
        select(ScanResult)
        .options(selectinload(ScanResult.checks))
        .where(ScanResult.id == scan_id)
    )
    scan = scan_result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    from jinja2 import Template
    template = Template(REPORT_TEMPLATE)
    html_content = template.render(
        scan=scan,
        checks=scan.checks,
        report_id=report_id,
        report_date=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    )

    return StreamingResponse(
        io.BytesIO(html_content.encode("utf-8")),
        media_type="text/html",
        headers={"Content-Disposition": f'attachment; filename="compliance_report_{scan_id}.html"'},
    )
