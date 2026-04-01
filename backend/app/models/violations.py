"""
Violation Engine models:
- ViolationRule : built-in rule definitions (seeded once)
- Violation     : per-resource findings produced by the engine
"""

import enum
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.database import Base


class ViolationStatus(str, enum.Enum):
    OPEN     = "open"
    RESOLVED = "resolved"
    IGNORED  = "ignored"


class ViolationCategory(str, enum.Enum):
    IAM              = "iam"
    NETWORK          = "network"
    STORAGE          = "storage"
    ENCRYPTION       = "encryption"
    LOGGING          = "logging"
    COMPUTE          = "compute"
    DATABASE         = "database"
    MONITORING       = "monitoring"


class ViolationRule(Base):
    """Static definition of a mis-configuration rule."""
    __tablename__ = "violation_rules"

    id:            Mapped[int]          = mapped_column(Integer, primary_key=True)
    rule_id:       Mapped[str]          = mapped_column(String(64),  nullable=False, unique=True, index=True)
    name:          Mapped[str]          = mapped_column(String(255), nullable=False)
    description:   Mapped[str]          = mapped_column(Text,        nullable=False)
    category:      Mapped[str]          = mapped_column(String(64),  nullable=False)
    severity:      Mapped[str]          = mapped_column(String(32),  nullable=False)   # critical/high/medium/low
    provider:      Mapped[str]          = mapped_column(String(32),  nullable=False)   # aws/azure/gcp/generic
    framework_tags: Mapped[Optional[dict]] = mapped_column(JSON)                       # e.g. {"pci_dss": True}
    remediation:   Mapped[Optional[str]] = mapped_column(Text)
    enabled:       Mapped[bool]         = mapped_column(Boolean, default=True)

    violations: Mapped[list["Violation"]] = relationship(back_populates="rule")


class Violation(Base):
    """A specific resource that has triggered a ViolationRule."""
    __tablename__ = "violations"

    id:               Mapped[int]           = mapped_column(Integer, primary_key=True)
    rule_id:          Mapped[str]           = mapped_column(
        ForeignKey("violation_rules.rule_id", ondelete="CASCADE"),
        nullable=False, index=True
    )
    # Normalised resource identifier — used for cross-module correlation.
    # Format: <provider>://<account_id>/<resource_type>/<resource_id>
    # e.g.  aws://123456789/s3/my-data-lake
    resource_urn:     Mapped[str]           = mapped_column(String(512), nullable=False, index=True)
    resource_id:      Mapped[str]           = mapped_column(String(255), nullable=False)
    resource_type:    Mapped[str]           = mapped_column(String(128), nullable=False)
    account_id:       Mapped[Optional[str]] = mapped_column(String(255))
    cloud_provider:   Mapped[str]           = mapped_column(String(32),  nullable=False, default="aws")
    severity:         Mapped[str]           = mapped_column(String(32),  nullable=False)
    status:           Mapped[str]           = mapped_column(String(32),  nullable=False, default="open")
    details:          Mapped[Optional[dict]] = mapped_column(JSON)
    remediation_hint: Mapped[Optional[str]] = mapped_column(Text)
    detected_at:      Mapped[datetime]      = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    resolved_at:      Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))

    rule: Mapped["ViolationRule"]     = relationship(back_populates="violations")
    correlations: Mapped[list] = relationship(
        "DSPMCorrelation",
        back_populates="violation",
        foreign_keys="DSPMCorrelation.violation_id",
    )
