"""
Compliance-related SQLAlchemy models:
- CloudAccount: registered cloud provider account
- ComplianceCheck: individual policy check result
- ScanResult: aggregated scan run
- EvidenceRecord: tamper-proof evidence entry
"""

import enum
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import (
    Boolean, DateTime, Enum, Float, ForeignKey,
    Integer, JSON, String, Text, select
)
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.database import Base


class CloudProvider(str, enum.Enum):
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    ON_PREM = "on_prem"


class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class CheckStatus(str, enum.Enum):
    PASS = "pass"
    FAIL = "fail"
    WARNING = "warning"
    ERROR = "error"
    SKIPPED = "skipped"


class CloudAccount(Base):
    __tablename__ = "cloud_accounts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    provider: Mapped[str] = mapped_column(String(50), nullable=False)
    account_id: Mapped[str] = mapped_column(String(255), nullable=False)
    region: Mapped[Optional[str]] = mapped_column(String(100))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    scan_results: Mapped[list["ScanResult"]] = relationship(back_populates="account")


class ScanResult(Base):
    __tablename__ = "scan_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    account_id: Mapped[int] = mapped_column(ForeignKey("cloud_accounts.id"), nullable=False)
    framework: Mapped[str] = mapped_column(String(100), nullable=False)  # pci_dss, hipaa, etc.
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    total_checks: Mapped[int] = mapped_column(Integer, default=0)
    passed_checks: Mapped[int] = mapped_column(Integer, default=0)
    failed_checks: Mapped[int] = mapped_column(Integer, default=0)
    compliance_score: Mapped[float] = mapped_column(Float, default=0.0)
    triggered_by: Mapped[str] = mapped_column(String(100), default="scheduled")

    account: Mapped["CloudAccount"] = relationship(back_populates="scan_results")
    checks: Mapped[list["ComplianceCheck"]] = relationship(back_populates="scan")


class ComplianceCheck(Base):
    __tablename__ = "compliance_checks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scan_results.id"), nullable=False)
    policy_id: Mapped[str] = mapped_column(String(255), nullable=False)
    policy_name: Mapped[str] = mapped_column(String(500), nullable=False)
    framework: Mapped[str] = mapped_column(String(100), nullable=False)
    resource_id: Mapped[Optional[str]] = mapped_column(String(500))
    resource_type: Mapped[Optional[str]] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(50), nullable=False)
    severity: Mapped[str] = mapped_column(String(50), nullable=False)
    details: Mapped[Optional[dict]] = mapped_column(JSON)
    remediation_hint: Mapped[Optional[str]] = mapped_column(Text)
    checked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    scan: Mapped["ScanResult"] = relationship(back_populates="checks")
    evidence: Mapped[list["EvidenceRecord"]] = relationship(back_populates="check")


class EvidenceRecord(Base):
    __tablename__ = "evidence_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    check_id: Mapped[int] = mapped_column(ForeignKey("compliance_checks.id"), nullable=False)
    hash_value: Mapped[str] = mapped_column(String(64), nullable=False)  # SHA-256
    previous_hash: Mapped[str] = mapped_column(String(64), nullable=False, default="genesis")
    storage_path: Mapped[Optional[str]] = mapped_column(String(1024))
    evidence_metadata: Mapped[Optional[dict]] = mapped_column("metadata", JSON)
    signature: Mapped[Optional[str]] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    check: Mapped["ComplianceCheck"] = relationship(back_populates="evidence")
