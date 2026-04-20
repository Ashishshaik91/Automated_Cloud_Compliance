"""
Pydantic schemas for Compliance, Scanning, Reports, and Cloud Accounts.
"""

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field


# ---- Cloud Account ----

class CloudAccountCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    provider: str = Field(..., pattern="^(aws|azure|gcp|terraform|on_prem)$")
    account_id: str = Field(..., min_length=1, max_length=255)
    region: Optional[str] = None


class CloudAccountResponse(BaseModel):
    model_config = {"from_attributes": True}
    id: int
    name: str
    provider: str
    account_id: str
    region: Optional[str]
    is_active: bool
    created_at: datetime


# ---- Compliance Check ----

class ComplianceCheckResponse(BaseModel):
    model_config = {"from_attributes": True}
    id: int
    policy_id: str
    policy_name: str
    framework: str
    resource_id: Optional[str]
    resource_type: Optional[str]
    status: str
    severity: str
    details: Optional[dict[str, Any]]
    remediation_hint: Optional[str]
    checked_at: datetime


# ---- Scan ----

class ScanTriggerRequest(BaseModel):
    account_id: int
    framework: str = Field(..., pattern="^(pci_dss|hipaa|gdpr|soc2|nist|cis|owasp|custom|all)$")
    dry_run: bool = False
    # Terraform real-time fetch options
    # If set, overrides the connector's auto-detected state source
    terraform_state_path: Optional[str] = Field(
        default=None,
        description=(
            "Local .tfstate file path, or remote URI (s3://, gs://, https://...blob...). "
            "When provided, triggers a Terraform state scan in addition to the cloud SDK scan. "
            "Use 'binary' to run terraform show -json in the current working directory."
        ),
    )
    terraform_working_dir: Optional[str] = Field(
        default=None,
        description=(
            "Absolute path to the Terraform project directory. "
            "Used when terraform_state_path='binary' to run `terraform show -json` in that dir."
        ),
    )


class ScanResultResponse(BaseModel):
    model_config = {"from_attributes": True}
    id: int
    account_id: int
    framework: str
    started_at: datetime
    completed_at: Optional[datetime]
    total_checks: int
    passed_checks: int
    failed_checks: int
    compliance_score: float
    triggered_by: str


class ScanWithChecksResponse(ScanResultResponse):
    checks: list[ComplianceCheckResponse] = []


# ---- Report ----

class ReportRequest(BaseModel):
    scan_id: int
    format: str = Field("pdf", pattern="^(pdf|csv|html|json)$")
    include_evidence: bool = True


class ReportResponse(BaseModel):
    report_id: str
    scan_id: int
    format: str
    download_url: str
    generated_at: datetime


# ---- Alert ----

class AlertResponse(BaseModel):
    id: int
    severity: str
    message: str
    resource_id: Optional[str]
    framework: str
    acknowledged: bool
    status: Optional[str] = "open"
    created_at: datetime

    model_config = {"from_attributes": True}


# ---- Compliance Summary ----

class ComplianceSummary(BaseModel):
    total_accounts: int
    frameworks_monitored: list[str]
    overall_score: float
    critical_failures: int
    high_failures: int
    last_scan_at: Optional[datetime]
    trend: str  # improving | degrading | stable

# ---- Custom Policy ----

class CustomPolicyCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    resource_type: str = Field(..., min_length=2, max_length=100)
    severity: str = Field(..., pattern="^(low|medium|high|critical)$")
    field: str = Field(..., min_length=1, max_length=100)
    operator: str = Field(..., min_length=2, max_length=50)
