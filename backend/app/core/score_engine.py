"""
Score Engine — weighted compliance scoring with grade bands and org aggregates.

Formula
-------
  check_weight  = CRITICAL→10, HIGH→5, MEDIUM→2, LOW→1
  weighted_score = Σ(weight × is_pass) / Σ(weight) × 100

  framework_multiplier (used at org-aggregate level):
    pci_dss:1.3  hipaa:1.3  gdpr:1.2  soc2:1.1
    nist:1.0     cis:1.0    owasp:0.9  custom:0.8

  org_score = Σ(account_score × fw_multiplier × account_weight) / Σ(account_weight)

Grade bands: A≥90  B≥75  C≥60  D≥45  F<45
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from typing import Any

import structlog
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.compliance import ComplianceCheck, ScanResult
from app.models.score import AccountScoreCache, ScoreSnapshot

logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SEVERITY_WEIGHTS: dict[str, int] = {
    "critical": 10,
    "high": 5,
    "medium": 2,
    "low": 1,
    "info": 0,
}

FRAMEWORK_MULTIPLIERS: dict[str, float] = {
    "pci_dss": 1.3,
    "hipaa":   1.3,
    "gdpr":    1.2,
    "soc2":    1.1,
    "nist":    1.0,
    "cis":     1.0,
    "owasp":   0.9,
    "custom":  0.8,
}

GRADE_BANDS: list[tuple[float, str]] = [
    (90.0, "A"),
    (75.0, "B"),
    (60.0, "C"),
    (45.0, "D"),
    (0.0,  "F"),
]


# ---------------------------------------------------------------------------
# Data containers
# ---------------------------------------------------------------------------

@dataclass
class ScoreResult:
    score: float                # 0–100
    grade: str                  # A–F
    total_weight: int
    passed_weight: int
    critical_fails: int
    high_fails: int
    medium_fails: int
    low_fails: int
    check_count: int


@dataclass
class OrgScore:
    overall_score: float
    grade: str
    by_framework: dict[str, float]
    account_count: int
    critical_fails: int
    dspm_risk_avg: float


# ---------------------------------------------------------------------------
# Core functions
# ---------------------------------------------------------------------------

def _grade(score: float) -> str:
    for threshold, letter in GRADE_BANDS:
        if score >= threshold:
            return letter
    return "F"


def compute_scan_score(checks: list[ComplianceCheck]) -> ScoreResult:
    """
    Compute a weighted compliance score from a list of check results.
    Skipped / error checks are excluded from the denominator (neutral).
    """
    total_w = passed_w = 0
    c_fail = h_fail = m_fail = l_fail = 0

    for chk in checks:
        if chk.status in ("skipped", "error"):
            continue
        w = SEVERITY_WEIGHTS.get(chk.severity.lower(), 1)
        total_w += w
        if chk.status == "pass":
            passed_w += w
        else:
            sev = chk.severity.lower()
            if sev == "critical":   c_fail += 1
            elif sev == "high":     h_fail += 1
            elif sev == "medium":   m_fail += 1
            else:                   l_fail += 1

    score = (passed_w / total_w * 100) if total_w > 0 else 100.0
    return ScoreResult(
        score=round(score, 2),
        grade=_grade(score),
        total_weight=total_w,
        passed_weight=passed_w,
        critical_fails=c_fail,
        high_fails=h_fail,
        medium_fails=m_fail,
        low_fails=l_fail,
        check_count=len(checks),
    )


def compute_org_score(
    scan_results: list[ScanResult],
    dspm_risk_avg: float = 0.0,
) -> OrgScore:
    """
    Aggregate per-scan scores into an org-level score.
    Framework multipliers give more weight to high-risk standards.
    """
    by_framework: dict[str, list[float]] = {}
    total_score_sum = 0.0
    total_weight_sum = 0.0
    total_critical = 0

    for sr in scan_results:
        fw = sr.framework.lower()
        multiplier = FRAMEWORK_MULTIPLIERS.get(fw, 1.0)
        s = sr.compliance_score
        by_framework.setdefault(fw, []).append(s)
        total_score_sum += s * multiplier
        total_weight_sum += multiplier
        # Pull critical fails count if stored in extra metadata
        if sr.checks:
            total_critical += sum(1 for c in sr.checks if c.severity == "critical" and c.status == "fail")

    overall = (total_score_sum / total_weight_sum) if total_weight_sum > 0 else 0.0

    # DSPM penalty: each 10 points of avg DSPM risk subtracts 1 from org score
    dspm_penalty = dspm_risk_avg / 10.0
    overall = max(0.0, round(overall - dspm_penalty, 2))

    fw_averages = {fw: round(sum(scores) / len(scores), 2) for fw, scores in by_framework.items()}

    return OrgScore(
        overall_score=overall,
        grade=_grade(overall),
        by_framework=fw_averages,
        account_count=len({sr.account_id for sr in scan_results}),
        critical_fails=total_critical,
        dspm_risk_avg=dspm_risk_avg,
    )


# ---------------------------------------------------------------------------
# Daily snapshot Celery task
# ---------------------------------------------------------------------------

async def take_daily_snapshot(db: AsyncSession, org_id: int) -> ScoreSnapshot | None:
    """
    Compute and persist a daily org score snapshot.
    Called by the Celery beat task `tasks.take_score_snapshot`.
    """
    from app.models.dspm import DSPMFinding  # avoid circular import

    # Pull all scan results for this org (last 24h or aggregate)
    stmt = (
        select(ScanResult)
        .join(ScanResult.account)
        .where(ScanResult.account.has(organization_id=org_id))
        .order_by(ScanResult.started_at.desc())
        .limit(200)
    )
    result = await db.execute(stmt)
    scans = list(result.scalars().all())

    if not scans:
        logger.info("No scans found for org snapshot", org_id=org_id)
        return None

    # Avg DSPM risk for org
    dspm_stmt = select(func.avg(DSPMFinding.risk_score)).where(
        DSPMFinding.organization_id == org_id
    )
    dspm_avg_result = await db.execute(dspm_stmt)
    dspm_avg: float = dspm_avg_result.scalar_one_or_none() or 0.0

    org_score = compute_org_score(scans, dspm_avg)

    snapshot = ScoreSnapshot(
        org_id=org_id,
        snapshot_date=date.today(),
        overall_score=org_score.overall_score,
        grade=org_score.grade,
        by_framework=org_score.by_framework,
        account_count=org_score.account_count,
        critical_fails=org_score.critical_fails,
        dspm_risk_avg=dspm_avg,
    )
    db.add(snapshot)
    await db.flush()
    logger.info(
        "Score snapshot taken",
        org_id=org_id,
        score=org_score.overall_score,
        grade=org_score.grade,
    )
    return snapshot
