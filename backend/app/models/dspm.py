"""
DSPM (Data Security Posture Management) models:
- DSPMFinding     : discovered sensitive data store
- DSPMCorrelation : cross-module link between a DSPMFinding and a Violation
"""

import enum
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import DateTime, Float, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship, declared_attr

from app.models.database import Base
from app.models.violations import Violation  # imported here for relationship resolution


class DataClassification(str, enum.Enum):
    PII          = "PII"
    PCI          = "PCI"
    PHI          = "PHI"
    HIPAA        = "HIPAA"
    CONFIDENTIAL = "CONFIDENTIAL"
    PUBLIC       = "PUBLIC"
    UNKNOWN      = "UNKNOWN"


class RiskLevel(str, enum.Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    NONE     = "none"


def risk_score_to_level(score: float) -> str:
    """Map a 0–100 risk_score to a RiskLevel string."""
    if score >= 80:
        return RiskLevel.CRITICAL
    if score >= 60:
        return RiskLevel.HIGH
    if score >= 35:
        return RiskLevel.MEDIUM
    if score > 0:
        return RiskLevel.LOW
    return RiskLevel.NONE


class DSPMFinding(Base):
    """A discovered cloud data store with its classification and risk posture."""
    __tablename__ = "dspm_findings"

    id:                Mapped[int]           = mapped_column(Integer, primary_key=True)
    # Normalised store identifier — mirrors Violation.resource_urn format
    # e.g. aws://123456789/s3/pii-production-bucket
    data_store_urn:    Mapped[str]           = mapped_column(String(512), nullable=False, unique=True, index=True)
    data_store_id:     Mapped[str]           = mapped_column(String(255), nullable=False)
    data_store_name:   Mapped[str]           = mapped_column(String(255), nullable=False)
    data_store_type:   Mapped[str]           = mapped_column(String(64),  nullable=False)  # s3/rds/blob/gcs/bigquery
    cloud_provider:    Mapped[str]           = mapped_column(String(32),  nullable=False, default="aws")
    region:            Mapped[Optional[str]] = mapped_column(String(64))
    account_id:        Mapped[Optional[str]] = mapped_column(String(255))

    # Classification — comma-separated tags
    classifications:   Mapped[str]           = mapped_column(String(512), nullable=False, default="UNKNOWN")
    sensitivity:       Mapped[str]           = mapped_column(String(32),  nullable=False, default="low")

    # Risk factors
    public_access:     Mapped[bool]          = mapped_column(default=False)
    encryption_status: Mapped[str]           = mapped_column(String(32),  nullable=False, default="encrypted")  # encrypted/unencrypted/partial
    record_count:      Mapped[Optional[int]] = mapped_column(Integer)
    owner:             Mapped[Optional[str]] = mapped_column(String(255))

    # Computed 0–100 risk score:
    #   base = sensitivity weight × public_access_multiplier / encryption_factor
    risk_score:        Mapped[float]         = mapped_column(Float, default=0.0)
    risk_level:        Mapped[str]           = mapped_column(String(32), nullable=False, default="none")

    last_scanned:      Mapped[datetime]      = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    correlations: Mapped[list["DSPMCorrelation"]] = relationship(back_populates="dspm_finding")


class DSPMCorrelation(Base):
    """
    Cross-module record linking a Violation to a DSPMFinding.
    Created when a violation's resource_urn overlaps the DSPM store's data_store_urn
    (exact match or prefix/suffix heuristic on the resource identifier segment).
    """
    __tablename__ = "dspm_correlations"

    id:               Mapped[int] = mapped_column(Integer, primary_key=True)
    dspm_finding_id:  Mapped[int] = mapped_column(
        ForeignKey("dspm_findings.id", ondelete="CASCADE"), nullable=False, index=True
    )
    violation_id:     Mapped[int] = mapped_column(
        ForeignKey("violations.id",     ondelete="CASCADE"), nullable=False, index=True
    )
    risk_label:       Mapped[str] = mapped_column(String(512), nullable=False)
    combined_risk:    Mapped[str] = mapped_column(String(32),  nullable=False, default="high")
    detected_at:      Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    dspm_finding: Mapped["DSPMFinding"]  = relationship(back_populates="correlations")
    violation:    Mapped["Violation"]    = relationship(
        back_populates="correlations", foreign_keys=[violation_id]
    )
